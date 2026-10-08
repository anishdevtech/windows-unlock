#include "broker.hpp"
#include <winsvc.h>
#include <wtsapi32.h>
using namespace pu::native;
namespace {
SERVICE_STATUS_HANDLE statusHandle{};Handle stop;std::atomic<std::shared_ptr<pu::vault::Broker>> broker;
void report(DWORD state,DWORD error=0){SERVICE_STATUS s{};s.dwServiceType=SERVICE_WIN32_OWN_PROCESS;s.dwCurrentState=state;s.dwWin32ExitCode=error;s.dwControlsAccepted=state==SERVICE_RUNNING?SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN|SERVICE_ACCEPT_SESSIONCHANGE:0;s.dwWaitHint=30000;SetServiceStatus(statusHandle,&s);}
DWORD WINAPI control(DWORD action,DWORD type,void* data,void*){if(action==SERVICE_CONTROL_STOP||action==SERVICE_CONTROL_SHUTDOWN){report(SERVICE_STOP_PENDING);if(stop)SetEvent(stop.get());}
  if(action==SERVICE_CONTROL_SESSIONCHANGE&&data&&type==WTS_SESSION_LOCK)if(auto b=broker.load())b->requestAutomatically(static_cast<WTSSESSION_NOTIFICATION*>(data)->dwSessionId);
  if(action==SERVICE_CONTROL_SESSIONCHANGE&&data&&(type==WTS_SESSION_UNLOCK||type==WTS_SESSION_LOGOFF||type==WTS_CONSOLE_DISCONNECT||type==WTS_REMOTE_DISCONNECT))if(auto b=broker.load())b->cancel(static_cast<WTSSESSION_NOTIFICATION*>(data)->dwSessionId);return 0;}
void WINAPI main(DWORD,LPWSTR*){statusHandle=RegisterServiceCtrlHandlerExW(ServiceName,control,nullptr);if(!statusHandle)return;report(SERVICE_START_PENDING);try{require(currentSid()==L"S-1-5-18","LocalSystem required");HANDLE raw{};require(OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&raw),"Service privilege unavailable");Handle token(raw);TOKEN_PRIVILEGES p{};p.PrivilegeCount=1;require(LookupPrivilegeValueW(nullptr,SE_TCB_NAME,&p.Privileges[0].Luid),"Session privilege unavailable");p.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;SetLastError(0);require(AdjustTokenPrivileges(token.get(),FALSE,&p,0,nullptr,nullptr)&&GetLastError()==0,"Session privilege unavailable");stop=event();broker.store(std::make_shared<pu::vault::Broker>());serve(PipeName,L"D:P(A;;GA;;;SY)",stop.get(),authorizeLogonUi,[](const Request& q,const Caller& c){return broker.load()->dispatch(q,c);},[]{report(SERVICE_RUNNING);});report(SERVICE_STOP_PENDING);broker.store(nullptr);report(SERVICE_STOPPED);}catch(...){broker.store(nullptr);report(SERVICE_STOPPED,ERROR_SERVICE_SPECIFIC_ERROR);}}
}
int wmain(int argc,wchar_t**){if(argc!=1)return ERROR_INVALID_PARAMETER;SERVICE_TABLE_ENTRYW table[]{{const_cast<LPWSTR>(ServiceName),main},{nullptr,nullptr}};return StartServiceCtrlDispatcherW(table)?0:int(GetLastError());}
