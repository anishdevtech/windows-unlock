#include "broker.hpp"
#include <wtsapi32.h>
#include <winsvc.h>
using namespace pu::native;
namespace {
SERVICE_STATUS_HANDLE statusHandle{};Handle stopped;std::atomic<std::shared_ptr<pu::preview::Broker>> broker;
void report(DWORD state,DWORD error=NO_ERROR){SERVICE_STATUS status{};status.dwServiceType=SERVICE_WIN32_OWN_PROCESS;status.dwCurrentState=state;status.dwWin32ExitCode=error;status.dwControlsAccepted=state==SERVICE_RUNNING?SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN|SERVICE_ACCEPT_SESSIONCHANGE:0;status.dwWaitHint=state==SERVICE_STOP_PENDING?30000:0;status.dwCheckPoint=state==SERVICE_STOP_PENDING?1:0;SetServiceStatus(statusHandle,&status);}
DWORD WINAPI control(DWORD command,DWORD type,LPVOID data,LPVOID){
  if(command==SERVICE_CONTROL_STOP||command==SERVICE_CONTROL_SHUTDOWN){report(SERVICE_STOP_PENDING);if(stopped)SetEvent(stopped.get());return NO_ERROR;}
  if(command==SERVICE_CONTROL_SESSIONCHANGE&&data&&(type==WTS_SESSION_UNLOCK||type==WTS_SESSION_LOGOFF||type==WTS_CONSOLE_DISCONNECT||type==WTS_REMOTE_DISCONNECT))if(auto active=broker.load())active->cancel(static_cast<WTSSESSION_NOTIFICATION*>(data)->dwSessionId);
  return NO_ERROR;
}
void WINAPI serviceMain(DWORD,LPWSTR*){
  statusHandle=RegisterServiceCtrlHandlerExW(ServiceName,control,nullptr);if(!statusHandle)return;
  report(SERVICE_START_PENDING);
  try{require(currentSid()==L"S-1-5-18","LocalSystem service required");stopped=event();broker.store(std::make_shared<pu::preview::Broker>());
    serve(PipeName,L"D:P(A;;GA;;;SY)",stopped.get(),authorizeLogonUi,[](const Request& q,const Caller& c){if(auto active=broker.load())return active->dispatch(q,c);Response reply;reply.sid=q.sid;reply.operationId=q.operationId;return reply;},[]{report(SERVICE_RUNNING);});
    report(SERVICE_STOP_PENDING);broker.store(nullptr);report(SERVICE_STOPPED);
  }catch(...){broker.store(nullptr);report(SERVICE_STOPPED,ERROR_SERVICE_SPECIFIC_ERROR);}
}
}
int wmain(int argc,wchar_t**){if(argc!=1)return ERROR_INVALID_PARAMETER;SERVICE_TABLE_ENTRYW services[]{{const_cast<LPWSTR>(ServiceName),serviceMain},{nullptr,nullptr}};return StartServiceCtrlDispatcherW(services)?0:int(GetLastError());}
