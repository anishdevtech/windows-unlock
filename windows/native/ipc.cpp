#include "ipc.hpp"
#include <sddl.h>
#include <winsvc.h>
#include <vector>
#include <cwchar>

namespace pu::native {
namespace {
struct Local {void* value{};~Local(){if(value)LocalFree(value);}};
struct Service {SC_HANDLE value{};~Service(){if(value)CloseServiceHandle(value);}};
template<size_t N> bool terminated(const std::array<wchar_t,N>& text){return wmemchr(text.data(),0,N)!=nullptr;}
bool io(HANDLE pipe,void* buffer,DWORD bytes,bool write,HANDLE stop,std::stop_token token){
  auto ready=event();OVERLAPPED op{};op.hEvent=ready.get();DWORD count{};
  BOOL ok=write?WriteFile(pipe,buffer,bytes,&count,&op):ReadFile(pipe,buffer,bytes,&count,&op);
  if(!ok&&GetLastError()!=ERROR_IO_PENDING)return false;
  if(!ok){
    const auto deadline=GetTickCount64()+250;
    while(!token.stop_requested()&&(!stop||WaitForSingleObject(stop,0)!=WAIT_OBJECT_0)&&GetTickCount64()<deadline){
      if(WaitForSingleObject(ready.get(),25)==WAIT_OBJECT_0)break;
    }
    if(WaitForSingleObject(ready.get(),0)!=WAIT_OBJECT_0){CancelIoEx(pipe,&op);GetOverlappedResult(pipe,&op,&count,TRUE);return false;}
    if(!GetOverlappedResult(pipe,&op,&count,FALSE))return false;
  }
  return count==bytes;
}
bool registeredService(DWORD process){
  Service manager{OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT)};if(!manager.value)return false;
  Service service{OpenServiceW(manager.value,ServiceName,SERVICE_QUERY_STATUS|SERVICE_QUERY_CONFIG)};if(!service.value)return false;
  SERVICE_STATUS_PROCESS status{};DWORD needed{};
  if(!QueryServiceStatusEx(service.value,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&status),sizeof(status),&needed)||status.dwCurrentState!=SERVICE_RUNNING||status.dwProcessId!=process)return false;
  QueryServiceConfigW(service.value,nullptr,0,&needed);if(needed<sizeof(QUERY_SERVICE_CONFIGW)||needed>32768)return false;
  std::vector<BYTE> data(needed);auto config=reinterpret_cast<QUERY_SERVICE_CONFIGW*>(data.data());
  return QueryServiceConfigW(service.value,config,needed,&needed)&&config->lpServiceStartName&&_wcsicmp(config->lpServiceStartName,L"LocalSystem")==0&&systemProcess(process);
}
Response exchange(const std::wstring& name,DWORD testServer,const Request& request,std::stop_token stop){
  require(valid(request),"Invalid IPC request");require(!stop.stop_requested(),"IPC cancelled");
  // Identification SQOS prevents a fake pipe from obtaining a usable caller token.
  Handle pipe(CreateFileW(name.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr));require(bool(pipe),"Service unavailable");
  DWORD process{};require(GetNamedPipeServerProcessId(pipe.get(),&process)!=FALSE,"Pipe identity unavailable");
  require(testServer?process==testServer:registeredService(process),"Untrusted pipe server");
  DWORD mode=PIPE_READMODE_MESSAGE;require(SetNamedPipeHandleState(pipe.get(),&mode,nullptr,nullptr)!=FALSE,"IPC mode failed");
  auto outgoing=request;Response response{};
  require(io(pipe.get(),&outgoing,sizeof(outgoing),true,nullptr,stop)&&io(pipe.get(),&response,sizeof(response),false,nullptr,stop),"IPC timed out or invalid frame");
  require(valid(response,request),"Invalid IPC response");return response;
}
}
bool validSid(const std::wstring& sid){if(sid.empty()||sid.size()>=184)return false;Local result;return ConvertStringSidToSidW(sid.c_str(),&result.value)&&IsValidSid(result.value);}
std::wstring tokenSid(HANDLE token){DWORD needed{};GetTokenInformation(token,TokenUser,nullptr,0,&needed);require(needed&&needed<65536,"Token unavailable");std::vector<BYTE> data(needed);require(GetTokenInformation(token,TokenUser,data.data(),needed,&needed)!=FALSE,"Token identity unavailable");Local text;require(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid,reinterpret_cast<LPWSTR*>(&text.value))!=FALSE,"SID unavailable");return static_cast<wchar_t*>(text.value);}
std::wstring currentSid(){HANDLE raw{};require(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw)!=FALSE,"Token unavailable");Handle token(raw);return tokenSid(token.get());}
bool systemProcess(DWORD process,const wchar_t* image){
  try{Handle handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,process));if(!handle)return false;HANDLE raw{};if(!OpenProcessToken(handle.get(),TOKEN_QUERY,&raw))return false;Handle token(raw);if(tokenSid(token.get())!=L"S-1-5-18")return false;
    if(image){wchar_t directory[MAX_PATH]{},path[32768]{};if(!GetSystemDirectoryW(directory,MAX_PATH))return false;DWORD size=32768;if(!QueryFullProcessImageNameW(handle.get(),0,path,&size))return false;return _wcsicmp(path,(std::wstring(directory)+L"\\"+image).c_str())==0;}return true;
  }catch(...){return false;}
}
bool valid(const Request& r){return r.magic==WireMagic&&r.version==WireVersion&&r.operation>=Operation::Describe&&r.operation<=
#ifdef PU_PASSWORD_UNLOCK
Operation::Claim
#else
Operation::Cancel
#endif
&&(r.scenario==1||r.scenario==2)&&terminated(r.sid)&&validSid(r.sid.data())&&(r.operation==Operation::Describe||!IsEqualGUID(r.operationId,GUID{}));}
bool valid(const Response& r,const Request& q){
#ifdef PU_PASSWORD_UNLOCK
  if(r.windowsSignInEnabled!=1||r.proofSize>=ProofCapacity||((q.operation==Operation::Claim&&r.state==State::ApprovedSignIn)?r.proofSize==0:r.proofSize!=0))return false;
  constexpr State last=State::ApprovedSignIn;
#elif defined(PU_WINDOWS_UNLOCK)
  if(r.windowsSignInEnabled!=1||r.proofSize>=ProofCapacity||(r.state==State::ApprovedSignIn?r.proofSize==0:r.proofSize!=0))return false;
  constexpr State last=State::ApprovedSignIn;
#else
  if(r.windowsSignInEnabled!=0)return false;constexpr State last=State::NotConfigured;
#endif
  return r.magic==WireMagic&&r.version==WireVersion&&r.state>=State::Unavailable&&r.state<=last&&r.reserved==0&&terminated(r.sid)&&terminated(r.phoneName)&&r.sid==q.sid&&IsEqualGUID(r.operationId,q.operationId);
}
bool serviceProcess(DWORD process){return registeredService(process);}
std::wstring statusText(State s){switch(s){
  case State::Ready:
#if defined(PU_WINDOWS_UNLOCK) || defined(PU_PASSWORD_UNLOCK)
    return L"Ready. Select Unlock with Phone, or use Windows PIN.";
#else
    return L"Approval preview ready. Windows PIN is still required.";
#endif
  case State::Waiting:return L"Waiting for phone approval...";
  case State::PushUnavailable:return L"Push unavailable. Open Android to review, or use Windows PIN.";
  case State::ApprovedPreview:return L"Phone signature verified. Windows sign-in is not enabled. Use Sign-in options → PIN.";
  case State::ApprovedSignIn:return L"Phone approved. Signing in...";
  case State::Denied:return L"Request denied. Use Windows PIN.";
  case State::Expired:return L"Request expired. Use Windows PIN.";
  case State::Cancelled:return L"Request cancelled. Use Windows PIN.";
  case State::NotConfigured:return L"Phone sign-in is not configured for this account. Use Windows PIN.";
  default:return L"Phone authentication unavailable. Use Sign-in options → PIN.";
}}
bool authorizeLogonUi(HANDLE pipe,Caller& caller){DWORD process{},session{};if(!GetNamedPipeClientProcessId(pipe,&process)||!ProcessIdToSessionId(process,&session)||session!=WTSGetActiveConsoleSessionId()||!systemProcess(process,L"LogonUI.exe"))return false;caller={process,session};return true;}
void serve(const std::wstring& name,const std::wstring& sddl,HANDLE stop,const Authorize& authorize,const Dispatch& dispatch,const std::function<void()>& readyCallback){
  Local descriptor;require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,reinterpret_cast<PSECURITY_DESCRIPTOR*>(&descriptor.value),nullptr)!=FALSE,"Pipe ACL unavailable");SECURITY_ATTRIBUTES security{sizeof(security),descriptor.value,FALSE};
  Handle pipe(CreateNamedPipeW(name.c_str(),PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,sizeof(Response),sizeof(Request),750,&security));require(bool(pipe),"Pipe already owned or unavailable");
  if(readyCallback)readyCallback();
  // Keep the first pipe instance alive across connections so a name cannot be stolen.
  while(WaitForSingleObject(stop,0)!=WAIT_OBJECT_0){auto ready=event();OVERLAPPED op{};op.hEvent=ready.get();BOOL connected=ConnectNamedPipe(pipe.get(),&op);DWORD error=connected?ERROR_SUCCESS:GetLastError();
    if(error==ERROR_IO_PENDING){HANDLE waits[]{stop,ready.get()};auto result=WaitForMultipleObjects(2,waits,FALSE,INFINITE);if(result!=WAIT_OBJECT_0+1){CancelIoEx(pipe.get(),&op);DWORD count{};GetOverlappedResult(pipe.get(),&op,&count,TRUE);break;}DWORD count{};connected=GetOverlappedResult(pipe.get(),&op,&count,FALSE);}
    else if(error==ERROR_PIPE_CONNECTED)connected=TRUE;
    if(connected){Caller caller{};Request request{};try{if(authorize(pipe.get(),caller)&&io(pipe.get(),&request,sizeof(request),false,stop,{})&&valid(request)&&request.sessionId==caller.sessionId){auto reply=dispatch(request,caller);if(valid(reply,request))io(pipe.get(),&reply,sizeof(reply),true,stop,{});
#ifdef PU_PASSWORD_UNLOCK
      SecureZeroMemory(reply.proof.data(),reply.proof.size());
#endif
    }}catch(...){/* Fail closed; never send exception text or secrets. */}}
    DisconnectNamedPipe(pipe.get());
  }
}
Response call(const Request& q,std::stop_token stop){return exchange(PipeName,0,q,stop);}
Response testing::call(const std::wstring& name,DWORD process,const Request& q,std::stop_token stop){require(name.starts_with(L"\\\\.\\pipe\\WINDOWS-UNLOCK-Test-"),"Test pipe namespace required");return exchange(name,process,q,stop);}
}
