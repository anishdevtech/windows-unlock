#include "session.hpp"
#include "storage.hpp"
#include <mutex>
using namespace pu;using namespace pu::auth;using namespace pu::native;
namespace {
constexpr NTSTATUS Ok=0,Denied=NTSTATUS(0xc0000022),Failure=NTSTATUS(0xc000006d),Invalid=NTSTATUS(0xc000000d),NoMemory=NTSTATUS(0xc0000017);
LSA_DISPATCH_TABLE dispatch{};PLSA_SECPKG_FUNCTION_TABLE support{};Authority authority;
SECPKG_CLIENT_INFO client(){SECPKG_CLIENT_INFO c{};require(support&&support->GetClientInfo&&support->GetClientInfo(&c)==0&&!c.Impersonating&&!c.Restricted,"Untrusted LSA caller");return c;}
uint64_t processCreated(DWORD pid){Handle p(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid));FILETIME created{},exit{},kernel{},user{};require(p&&GetProcessTimes(p.get(),&created,&exit,&kernel,&user),"Selected UI process unavailable");return (uint64_t(created.dwHighDateTime)<<32)|created.dwLowDateTime;}
PUNICODE_STRING auditString(const std::wstring& text){require(text.size()<32760&&dispatch.AllocateLsaHeap,"Invalid audit string");const auto bytes=(text.size()+1)*sizeof(wchar_t);auto value=static_cast<PUNICODE_STRING>(dispatch.AllocateLsaHeap(ULONG(sizeof(UNICODE_STRING)+bytes)));require(value!=nullptr,"LSA allocation failed");value->Buffer=reinterpret_cast<PWSTR>(value+1);value->Length=USHORT(bytes-2);value->MaximumLength=USHORT(bytes);CopyMemory(value->Buffer,text.c_str(),bytes);return value;}
NTSTATUS returnJson(PLSA_CLIENT_REQUEST request,const Json& result,PVOID* out,PULONG size){auto bytes=result.dump();require(bytes.size()<MaxSubmission,"LSA response too large");auto status=dispatch.AllocateClientBuffer(request,ULONG(bytes.size()),out);if(status!=0)return status;status=dispatch.CopyToClientBuffer(request,ULONG(bytes.size()),*out,bytes.data());if(status!=0){dispatch.FreeClientBuffer(request,*out);*out=nullptr;return status;}*size=ULONG(bytes.size());return Ok;}
NTSTATUS NTAPI initialize(ULONG_PTR,PSECPKG_PARAMETERS,PLSA_SECPKG_FUNCTION_TABLE table){
  if(!table||!table->GetClientInfo||!table->AllocateLsaHeap||!table->FreeLsaHeap||!table->CreateLogonSession||!table->DeleteLogonSession||!table->AllocateClientBuffer||!table->CopyToClientBuffer||!table->FreeClientBuffer)return Invalid;
  support=table;dispatch.CreateLogonSession=table->CreateLogonSession;dispatch.DeleteLogonSession=table->DeleteLogonSession;dispatch.AllocateLsaHeap=table->AllocateLsaHeap;dispatch.FreeLsaHeap=table->FreeLsaHeap;dispatch.AllocateClientBuffer=table->AllocateClientBuffer;dispatch.CopyToClientBuffer=table->CopyToClientBuffer;dispatch.FreeClientBuffer=table->FreeClientBuffer;return Ok;
}
NTSTATUS NTAPI shutdown(){support=nullptr;return Ok;}
NTSTATUS NTAPI getInfo(PSecPkgInfo out){if(!out)return Invalid;*out={};out->fCapabilities=SECPKG_FLAG_LOGON;out->wVersion=1;out->cbMaxToken=ULONG(MaxSubmission);out->Name=const_cast<PWSTR>(L"WINDOWS-UNLOCK");out->Comment=const_cast<PWSTR>(L"Phone-approved existing console session unlock");return Ok;}
}
extern "C" NTSTATUS NTAPI LsaApInitializePackage(ULONG,PLSA_DISPATCH_TABLE table,PLSA_STRING,PLSA_STRING,PLSA_STRING* name){
  if(!table||!name||!table->AllocateLsaHeap)return Invalid;*name=nullptr;dispatch=*table;auto n=sizeof(PackageName);auto value=static_cast<PLSA_STRING>(dispatch.AllocateLsaHeap(ULONG(sizeof(LSA_STRING)+n)));if(!value)return NoMemory;value->Length=USHORT(n-1);value->MaximumLength=USHORT(n);value->Buffer=reinterpret_cast<PCHAR>(value+1);CopyMemory(value->Buffer,PackageName,n);*name=value;return Ok;
}
extern "C" NTSTATUS NTAPI LsaApCallPackage(PLSA_CLIENT_REQUEST request,PVOID bytes,PVOID,ULONG size,PVOID* out,PULONG outSize,PNTSTATUS status){
  if(!out||!outSize||!status)return Invalid;*out=nullptr;*outSize=0;*status=Denied;
  try{auto c=client();require(c.HasTcbPrivilege&&serviceProcess(c.ProcessID),"Only registered LocalSystem broker allowed");require(bytes&&size>0&&size<MaxSubmission,"Invalid operation length");auto q=parse(std::string(static_cast<char*>(bytes),size));const auto op=q.at("operation").get<std::string>();
    if(op=="cancel"){require(q.size()==3&&q.at("logonUiPid").is_number_unsigned(),"Invalid cancellation");authority.cancel(q.at("requestId"),q.at("logonUiPid"));return *status=returnJson(request,Json{{"cancelled",true}},out,outSize);}
    require(op=="begin"&&q.size()==5&&q.at("sessionId").is_number_unsigned()&&q.at("scenario").is_number_unsigned()&&q.at("logonUiPid").is_number_unsigned(),"Invalid begin operation");
    auto live=session(q.at("sessionId"),q.at("sid"),q.at("scenario"));const DWORD pid=q.at("logonUiPid");DWORD sid{};require(ProcessIdToSessionId(pid,&sid)&&sid==live.context.session&&systemProcess(pid,L"LogonUI.exe"),"Selected tile caller mismatch");live.context.logonUiPid=pid;live.context.logonUiCreated=processCreated(pid);auto trust=pu::preview::publicTrust();auto challenge=authority.begin(live.context,trust);return *status=returnJson(request,challenge,out,outSize);
  }catch(...){return Denied;}
}
extern "C" NTSTATUS NTAPI LsaApCallPackageUntrusted(PLSA_CLIENT_REQUEST r,PVOID p,PVOID b,ULONG n,PVOID* o,PULONG s,PNTSTATUS status){return LsaApCallPackage(r,p,b,n,o,s,status);}
extern "C" NTSTATUS NTAPI LsaApCallPackagePassthrough(PLSA_CLIENT_REQUEST,PVOID,PVOID,ULONG,PVOID* out,PULONG size,PNTSTATUS status){if(out)*out=nullptr;if(size)*size=0;if(status)*status=Denied;return Denied;}
extern "C" VOID NTAPI LsaApLogonTerminated(PLUID id){if(id)try{authority.terminate(luidText(*id));}catch(...){}}
extern "C" NTSTATUS LsaApLogonUserEx2(PLSA_CLIENT_REQUEST,SECURITY_LOGON_TYPE type,PVOID bytes,PVOID,ULONG size,PVOID* profile,PULONG profileSize,PLUID logonId,PNTSTATUS sub,PLSA_TOKEN_INFORMATION_TYPE tokenType,PVOID* tokenInfo,PUNICODE_STRING* account,PUNICODE_STRING* authorityName,PUNICODE_STRING* machine,PSECPKG_PRIMARY_CRED primary,PSECPKG_SUPPLEMENTAL_CRED_ARRAY* supplemental){
  if(!profile||!profileSize||!logonId||!sub||!tokenType||!tokenInfo||!account||!authorityName||!machine||!primary||!supplemental)return Invalid;
  *profile=nullptr;*profileSize=0;*logonId={};*sub=Failure;*tokenInfo=nullptr;*account=nullptr;*authorityName=nullptr;*machine=nullptr;*primary={};*supplemental=nullptr;*tokenType=LsaTokenInformationV2;
  bool created=false;PVOID allocation{};LUID newId{};
  try{
    *account=auditString(L"WINDOWS-UNLOCK");require(type==Interactive||type==Unlock,"No network/batch/service/cold-boot login");auto caller=client();DWORD callerSession{};require(ProcessIdToSessionId(caller.ProcessID,&callerSession)&&(systemProcess(caller.ProcessID,L"Winlogon.exe")||systemProcess(caller.ProcessID,L"LogonUI.exe")),"Only Windows console logon authority may submit");
    auto s=submission(bytes,size);auto trust=pu::preview::publicTrust();auto raw=decode(s.at("requestJws"));auto live=session(raw.at("sessionId"),trust.at("sid"),raw.at("usageScenario"));require(callerSession==live.context.session,"Caller/session mismatch");
    const auto original=authority.context(s.at("requestId"));require(systemProcess(original.logonUiPid,L"LogonUI.exe"),"Original tile process ended");live.context.logonUiPid=original.logonUiPid;live.context.logonUiCreated=processCreated(original.logonUiPid);
    authority.consume(s,live.context,trust); // independent ES256 + authority nonce + local revocation
    // Revalidate the actual signed-in account before constructing LSA-owned information.
    auto current=session(live.context.session,live.context.sid,live.context.scenario);require(current.context.logonId==live.context.logonId,"Session replaced during approval");
    dispatch.FreeLsaHeap(*account);*account=nullptr;*account=auditString(current.account);*authorityName=auditString(current.domain);*machine=auditString(current.domain);
    allocation=tokenInformation(current.token.get(),dispatch.AllocateLsaHeap);require(AllocateLocallyUniqueId(&newId)!=FALSE,"Logon ID unavailable");auto result=dispatch.CreateLogonSession(&newId);require(result==Ok,"LSA session creation failed");created=true;
    *tokenInfo=allocation;*logonId=newId;*sub=Ok;return Ok;
  }catch(...){if(created)dispatch.DeleteLogonSession(&newId);if(allocation&&dispatch.FreeLsaHeap)dispatch.FreeLsaHeap(allocation);return Failure;}
}
extern "C" NTSTATUS SEC_ENTRY SpLsaModeInitialize(ULONG version,PULONG packageVersion,PSECPKG_FUNCTION_TABLE* tables,PULONG count){
  if(version!=SECPKG_INTERFACE_VERSION||!packageVersion||!tables||!count)return Invalid;
  static SECPKG_FUNCTION_TABLE table{};table.InitializePackage=LsaApInitializePackage;table.CallPackage=LsaApCallPackage;table.CallPackageUntrusted=LsaApCallPackageUntrusted;table.CallPackagePassthrough=LsaApCallPackagePassthrough;table.LogonTerminated=LsaApLogonTerminated;table.LogonUserEx2=LsaApLogonUserEx2;table.Initialize=initialize;table.Shutdown=shutdown;table.GetInfo=getInfo;*packageVersion=SECPKG_INTERFACE_VERSION;*tables=&table;*count=1;return Ok;
}
