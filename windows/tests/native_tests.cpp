#include "ipc.hpp"
#include <iostream>
#include <future>
#include <thread>
#include <chrono>
#include <atomic>
using namespace pu::native;
void check(bool condition,const char* label){require(condition,label);}
template<class F> void rejects(F fn){bool rejected=false;try{fn();}catch(...){rejected=true;}check(rejected,"Expected IPC rejection");}
struct Server {
  Handle stop{event()};std::jthread thread;std::wstring name;std::atomic<unsigned> dispatched{};
  Server(std::wstring pipe,Authorize authorize,Dispatch dispatch):name(std::move(pipe)){
    std::promise<void> promise;auto ready=promise.get_future();auto acl=L"D:P(A;;GA;;;"+currentSid()+L")";
    thread=std::jthread([this,acl,authorize=std::move(authorize),dispatch=std::move(dispatch),promise=std::move(promise)]()mutable{
      try{serve(name,acl,stop.get(),authorize,[&](const Request& q,const Caller& c){++dispatched;return dispatch(q,c);},[&]{promise.set_value();});}catch(...){try{promise.set_exception(std::current_exception());}catch(...){}}
    });
    if(ready.wait_for(std::chrono::seconds(2))!=std::future_status::ready){SetEvent(stop.get());throw std::runtime_error("Server startup timeout");}ready.get();
  }
  ~Server(){SetEvent(stop.get());if(thread.joinable())thread.join();}
};
int main(){try{
  Request q;q.scenario=1;DWORD session{};ProcessIdToSessionId(GetCurrentProcessId(),&session);q.sessionId=session;wcscpy_s(q.sid.data(),q.sid.size(),currentSid().c_str());
  constexpr DWORD enabled=WireVersion==3?1:0;
  check(valid(q),"Valid request");auto invalid=q;invalid.sid.fill(L'x');check(!valid(invalid),"Unterminated SID");invalid=q;invalid.scenario=3;check(!valid(invalid),"CredUI rejected");invalid=q;invalid.version=WireVersion+1;check(!valid(invalid),"Unknown version");invalid=q;invalid.operation=Operation::Begin;check(!valid(invalid),"Empty operation ID");
  Response reply;reply.windowsSignInEnabled=enabled;reply.sid=q.sid;reply.operationId=q.operationId;check(valid(reply,q),"Valid failure response");reply.reserved=1;check(!valid(reply,q),"Reserved wire bytes rejected");reply.reserved=0;reply.windowsSignInEnabled=!enabled;check(!valid(reply,q),"Mismatched service mode rejected");reply.windowsSignInEnabled=enabled;reply.phoneName.fill(L'x');check(!valid(reply,q),"Unterminated phone name");
  auto name=L"\\\\.\\pipe\\WINDOWS-UNLOCK-Test-"+std::to_wstring(GetCurrentProcessId());
  auto auth=[](HANDLE pipe,Caller& c){DWORD id{};if(!GetNamedPipeClientProcessId(pipe,&id)||id!=GetCurrentProcessId())return false;DWORD session{};ProcessIdToSessionId(id,&session);c={id,session};return true;};
  auto dispatch=[](const Request& request,const Caller&){Response out;out.windowsSignInEnabled=enabled;out.sid=request.sid;out.operationId=request.operationId;out.state=State::Ready;return out;};
  {Server server(name,auth,dispatch);check(testing::call(name,GetCurrentProcessId(),q).state==State::Ready,"Bound IPC round trip");
    rejects([&]{testing::call(name,GetCurrentProcessId()+1,q);});
    rejects([&]{auto stop=event();serve(name,L"D:P(A;;GA;;;"+currentSid()+L")",stop.get(),auth,dispatch);});
    for(unsigned i=0;i<8;i++){bool done=false;for(unsigned retry=0;retry<20&&!done;retry++){try{testing::call(name,GetCurrentProcessId(),q);done=true;}catch(...){std::this_thread::sleep_for(std::chrono::milliseconds(10));}}check(done,"Pipe remains usable after denied spoof/collision");}
  }
  {Server server(name,[](HANDLE,Caller&){return false;},dispatch);rejects([&]{testing::call(name,GetCurrentProcessId(),q);});check(server.dispatched==0,"Unauthorized caller never dispatched");}
  {Server server(name,authorizeLogonUi,dispatch);rejects([&]{testing::call(name,GetCurrentProcessId(),q);});check(server.dispatched==0,"Normal process cannot impersonate LogonUI");}
  {Server server(PipeName,auth,dispatch);rejects([&]{call(q);});check(server.dispatched==0,"Production client rejects unregistered pipe service");}
  {Server server(name,auth,[](const Request& request,const Caller&){Response out;out.sid=request.sid;out.operationId=request.operationId;out.windowsSignInEnabled=!enabled;return out;});rejects([&]{testing::call(name,GetCurrentProcessId(),q);});}
  {Server server(name,auth,[](const Request& request,const Caller&){std::this_thread::sleep_for(std::chrono::milliseconds(600));Response out;out.windowsSignInEnabled=enabled;out.sid=request.sid;out.operationId=request.operationId;return out;});auto before=GetTickCount64();rejects([&]{testing::call(name,GetCurrentProcessId(),q);});check(GetTickCount64()-before<1000,"Hung dispatch has bounded client fallback");}
#ifdef PU_PASSWORD_UNLOCK
  q.operationId={1,2,3,{4}};q.operation=Operation::Claim;
  {Server server(name,auth,[](const Request& request,const Caller&){Response out;out.windowsSignInEnabled=1;out.sid=request.sid;out.operationId=request.operationId;out.state=State::ApprovedSignIn;out.proofSize=4;memcpy(out.proof.data(),"test",4);return out;});auto claim=testing::call(name,GetCurrentProcessId(),q);check(claim.proofSize==4&&memcmp(claim.proof.data(),"test",4)==0,"V3 Claim frame delivered intact");q.operation=Operation::Poll;rejects([&]{testing::call(name,GetCurrentProcessId(),q);});}
#endif
  std::cout<<"Native IPC: frame validation, caller/server authentication, pipe ownership, deadlines and hard sign-in gate passed.\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
