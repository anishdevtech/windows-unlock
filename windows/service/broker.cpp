#include "broker.hpp"
#include <wtsapi32.h>
#include <wincrypt.h>

namespace pu::preview {
using namespace native;
namespace {
Handle sessionUser(DWORD session,const std::wstring& sid){HANDLE raw{};require(WTSQueryUserToken(session,&raw)!=FALSE,"Active signed-in session required");Handle token(raw);require(tokenSid(token.get())==sid,"Session/account mismatch");return token;}
bool locked(DWORD session){LPWSTR raw{};DWORD size{};if(!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,session,WTSSessionInfoEx,&raw,&size))return false;bool result=false;if(size>=sizeof(WTSINFOEXW)){auto info=reinterpret_cast<WTSINFOEXW*>(raw);result=info->Level==1&&info->Data.WTSInfoExLevel1.SessionId==session&&info->Data.WTSInfoExLevel1.SessionFlags==WTS_SESSIONSTATE_LOCK;}WTSFreeMemory(raw);return result;}
struct Impersonation{explicit Impersonation(HANDLE token){require(ImpersonateLoggedOnUser(token)!=FALSE,"User key context unavailable");}~Impersonation(){if(!RevertToSelf())TerminateProcess(GetCurrentProcess(),ERROR_ACCESS_DENIED);}};
std::string sign(const Json& config,HANDLE user,const Json& payload){Impersonation scope(user);SigningKey key(config.at("id"));require(key.jwk()==config.at("windowsJwk"),"Enrolled laptop key changed");return key.sign(payload);}
void audit(const Json& config,const std::string& id,const char* result)noexcept{try{
  Json row{{"timestamp",epoch()},{"device",config.at("id")},{"authenticationResult",result},{"snapshotPath",nullptr},{"requestId",id.empty()?Json(nullptr):Json(id)}};
  const auto text=wide(row.dump());HANDLE source=RegisterEventSourceW(nullptr,L"WINDOWS-UNLOCK-ApprovalPreview");if(source){const wchar_t* values[]{text.c_str()};ReportEventW(source,EVENTLOG_INFORMATION_TYPE,0,1001,nullptr,1,0,values,nullptr);DeregisterEventSource(source);}
}catch(...){/* Logging never authorizes or blocks sign-in; contains no credentials. */}}
}
Broker::Broker(){try{config_=configuration();configured_=true;state_=State::Ready;}catch(...){state_=State::NotConfigured;}}
Broker::~Broker(){cancelled_=true;if(worker_.joinable())worker_.join();if(configured_){auto& token=config_.at("transportToken").get_ref<std::string&>();SecureZeroMemory(token.data(),token.size());}}
bool Broker::same(const Request& q,const Caller& c)const{return q.sid==current_.sid&&q.scenario==current_.scenario&&q.sessionId==current_.sessionId&&c.processId==owner_.processId&&c.sessionId==owner_.sessionId&&IsEqualGUID(q.operationId,current_.operationId);}
void Broker::set(State value){std::lock_guard lock(mutex_);if(cancelled_&&(value==State::Waiting||value==State::PushUnavailable))return;state_=value;}
Response Broker::dispatch(const Request& q,const Caller& caller){
  Response reply;reply.sid=q.sid;reply.operationId=q.operationId;
  if(!valid(q)||caller.sessionId!=q.sessionId||caller.sessionId!=WTSGetActiveConsoleSessionId())return reply;
  if(!configured_||wide(config_.at("sid"))!=q.sid.data()){reply.state=State::NotConfigured;return reply;}
  const auto phone=wide(config_.at("pairing").at("phoneName"));wcsncpy_s(reply.phoneName.data(),reply.phoneName.size(),phone.c_str(),_TRUNCATE);
  if(q.operation==Operation::Describe){std::lock_guard lock(mutex_);reply.state=State::Ready;return reply;}
  if(q.operation==Operation::Begin){
    {std::lock_guard lock(mutex_);if(workerActive_){if(same(q,caller))reply.state=state_;return reply;}if(std::chrono::steady_clock::now()<nextAllowed_)return reply;}
    // Never start networking or wait for user response in the pipe dispatch thread.
    if(!locked(caller.sessionId))return reply;
    try{auto user=sessionUser(caller.sessionId,q.sid.data());}catch(...){return reply;}
    if(worker_.joinable())worker_.join();cancelled_=false;
    {std::lock_guard lock(mutex_);current_=q;owner_=caller;state_=State::Waiting;deadline_=std::chrono::steady_clock::now()+std::chrono::seconds(60);nextAllowed_=deadline_;}
    workerActive_=true;try{worker_=std::jthread([this,q,caller]{struct Done{std::atomic<bool>& flag;~Done(){flag=false;}} done{workerActive_};run(q,caller);});}catch(...){workerActive_=false;set(State::Unavailable);throw;}reply.state=State::Waiting;return reply;
  }
  {std::lock_guard lock(mutex_);if(!same(q,caller))return reply;
    if(q.operation==Operation::Cancel){cancelled_=true;state_=State::Cancelled;}
    else if(std::chrono::steady_clock::now()>=deadline_&&(state_==State::Waiting||state_==State::PushUnavailable)){cancelled_=true;state_=State::Expired;}
    reply.state=state_;}
  return reply;
}
void Broker::cancel(DWORD session){std::lock_guard lock(mutex_);if(owner_.sessionId==session){cancelled_=true;state_=State::Cancelled;}}
void Broker::run(Request local,Caller caller){
  std::string requestId;
  try{
    auto user=sessionUser(caller.sessionId,local.sid.data());if(cancelled_||!locked(caller.sessionId))throw std::runtime_error("Session changed");
    auto challenge=message("auth-request");const auto created=epoch();const auto id=uuid();requestId=id;const auto pair=config_.at("pairing");
    challenge.update({{"requestId",id},{"windowsDeviceId",config_.at("id")},{"androidDeviceId",pair.at("androidDeviceId")},{"pairingId",pair.at("id")},{"accountBindingId",config_.at("accountBindingId")},{"nonce",b64url(random(32))},{"issuedAt",created},{"expiresAt",created+60}});
    const auto signedRequest=sign(config_,user.get(),challenge);PendingApproval pending(challenge,signedRequest,pair,deadline_);
    Http relay(config_.at("relayUrl"),config_.at("tlsPin"),config_.at("transportToken"));Json body{{"requestJws",signedRequest}};
    auto sent=relay.call("POST","/v1/authentication-requests",&body);
    if(!cancelled_)set(sent.value("pushDelivery",std::string())=="sent"?State::Waiting:State::PushUnavailable);
    while(!cancelled_&&std::chrono::steady_clock::now()<deadline_&&epoch()<created+60&&locked(caller.sessionId)&&WTSGetActiveConsoleSessionId()==caller.sessionId){
      auto response=relay.call("GET","/v1/authentication-requests/"+id);
      if(response.at("state")=="response_received"){
        // Recheck account, session and deadline after network IO, before consuming proof.
        auto current=sessionUser(caller.sessionId,local.sid.data());
        std::lock_guard lock(mutex_);
        if(cancelled_||!same(local,caller)||!locked(caller.sessionId))break;
        auto decision=pending.consume(response.at("responseJws"));state_=decision=="approve"?State::ApprovedPreview:State::Denied;
        audit(config_,id,decision=="approve"?"approval_preview_verified":"denied");return;
      }
      if(response.at("state")=="cancelled")break;
      for(unsigned i=0;i<10&&!cancelled_;i++)std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    pending.cancel();set(cancelled_?State::Cancelled:State::Expired);audit(config_,id,cancelled_?"cancelled":"expired");auto cancellation=message("auth-cancel");cancellation["requestId"]=id;Json cancelBody{{"cancelJws",sign(config_,user.get(),cancellation)}};try{relay.call("POST","/v1/authentication-requests/"+id+"/cancel",&cancelBody);}catch(...){}
  }catch(...){set(cancelled_?State::Cancelled:State::Unavailable);audit(config_,requestId,cancelled_?"cancelled":"failed");}
}
}
