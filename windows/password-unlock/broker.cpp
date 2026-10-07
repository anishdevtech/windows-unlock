#include "broker.hpp"
#include <wtsapi32.h>
namespace pu::vault {
using namespace native;
bool contextAllowed(DWORD session,const std::wstring& sid,DWORD scenario){
  if(session!=WTSGetActiveConsoleSessionId()||!validSid(sid)||(scenario!=1&&scenario!=2))return false;
  HANDLE raw{};if(WTSQueryUserToken(session,&raw)){Handle token(raw);if(tokenSid(token.get())!=sid)return false;LPWSTR info{};DWORD count{};if(!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,session,WTSSessionInfoEx,&info,&count))return false;bool locked=false;if(count>=sizeof(WTSINFOEXW)){auto p=reinterpret_cast<WTSINFOEXW*>(info);locked=p->Level==1&&p->Data.WTSInfoExLevel1.SessionFlags==WTS_SESSIONSTATE_LOCK;}WTSFreeMemory(info);return locked;}
  if(scenario!=1||GetLastError()!=ERROR_NO_TOKEN)return false;LPWSTR name{};DWORD count{};if(!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,session,WTSUserName,&name,&count))return false;bool empty=name&&name[0]==0;WTSFreeMemory(name);return empty;
}
Broker::Broker(){try{config_=configuration();delegate_=verify(config_.at("delegationJws"),config_.at("windowsJwk"),"vault-delegation","password-unlock");SigningKey key("vault-"+delegate_.at("vaultId").get<std::string>(),false,true);require(key.jwk()==delegate_.at("machineJwk"),"Machine signing key mismatch");configured_=true;state_=State::Ready;}catch(...){state_=State::NotConfigured;}
  if(configured_){try{auto diagnostics=config_;diagnostics["id"]=delegate_.at("windowsDeviceId");telemetry_=std::make_unique<Telemetry>(diagnostics,directory(),"vault-"+delegate_.at("vaultId").get<std::string>(),config_.at("delegationJws"));telemetry_->emit("native_ready");}catch(...){/* Diagnostics cannot block sign-in. */}}
  watchdog_=std::jthread([this](std::stop_token stop){while(!stop.stop_requested()){
    {std::lock_guard lock(mutex_);if(state_==State::ApprovedSignIn&&(std::chrono::steady_clock::now()>=deadline_||epoch()>=expires_||!systemProcess(owner_.processId,L"LogonUI.exe")||!contextAllowed(owner_.sessionId,current_.sid.data(),current_.scenario))){cancelled_=true;clear();state_=State::Expired;}}
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }});
}
void Broker::clear(){if(!credential_.empty())SecureZeroMemory(credential_.data(),credential_.size());credential_.clear();}
Broker::~Broker(){watchdog_.request_stop();if(watchdog_.joinable())watchdog_.join();cancelled_=true;if(worker_.joinable())worker_.join();clear();if(configured_){auto& token=config_.at("transportToken").get_ref<std::string&>();SecureZeroMemory(token.data(),token.size());}}
bool Broker::same(const Request& q,const Caller& c)const{return q.sid==current_.sid&&q.scenario==current_.scenario&&q.sessionId==current_.sessionId&&c.processId==owner_.processId&&c.sessionId==owner_.sessionId&&IsEqualGUID(q.operationId,current_.operationId);}
void Broker::cancel(DWORD session){std::lock_guard lock(mutex_);if(session==owner_.sessionId){cancelled_=true;state_=State::Cancelled;clear();}}
Response Broker::dispatch(const Request& q,const Caller& caller){Response out;out.windowsSignInEnabled=1;out.sid=q.sid;out.operationId=q.operationId;
  if(!valid(q)||caller.sessionId!=q.sessionId||caller.sessionId!=WTSGetActiveConsoleSessionId())return out;
  if(!configured_||wide(delegate_.at("windowsAccountSid"))!=q.sid.data()){out.state=State::NotConfigured;return out;}
  wcscpy_s(out.phoneName.data(),out.phoneName.size(),L"your paired phone");
  if(q.operation==Operation::Describe){out.state=State::Ready;return out;}
  if(q.operation==Operation::Begin){
    {std::lock_guard lock(mutex_);if(active_){if(same(q,caller))out.state=state_;return out;}if(std::chrono::steady_clock::now()<nextAllowed_)return out;}
    if(!contextAllowed(caller.sessionId,q.sid.data(),q.scenario))return out;if(worker_.joinable())worker_.join();
    {std::lock_guard lock(mutex_);clear();current_=q;owner_=caller;cancelled_=false;state_=State::Waiting;deadline_=std::chrono::steady_clock::now()+std::chrono::seconds(60);nextAllowed_=std::chrono::steady_clock::now()+std::chrono::seconds(5);expires_=epoch()+60;}
    active_=true;try{worker_=std::jthread([this,q,caller]{struct End{std::atomic<bool>& flag;~End(){flag=false;}} end{active_};run(q,caller);});}catch(...){active_=false;std::lock_guard lock(mutex_);state_=State::Unavailable;}out.state=State::Waiting;return out;
  }
  std::lock_guard lock(mutex_);if(!same(q,caller))return out;
  if(q.operation==Operation::Cancel){cancelled_=true;state_=State::Cancelled;clear();}
  if(std::chrono::steady_clock::now()>=deadline_||epoch()>=expires_){cancelled_=true;state_=State::Expired;clear();}
  if(q.operation==Operation::Claim&&state_==State::ApprovedSignIn){
    if(cancelled_||!contextAllowed(caller.sessionId,q.sid.data(),q.scenario)||credential_.empty()||credential_.size()>=ProofCapacity){clear();state_=State::Unavailable;}
    else{out.state=State::ApprovedSignIn;out.proofSize=uint32_t(credential_.size());CopyMemory(out.proof.data(),credential_.data(),credential_.size());clear();state_=State::Cancelled;if(telemetry_)telemetry_->emit("credential_submitted");return out;}
  }out.state=state_;return out;
}
void Broker::run(Request q,Caller caller){std::string requestJws,id;try{
  SigningKey signer("vault-"+delegate_.at("vaultId").get<std::string>(),false,true);Ephemeral ephemeral;Http relay(config_.at("relayUrl"),config_.at("tlsPin"),config_.at("transportToken"));
  auto payload=message("vault-unlock","password-unlock");id=uuid();payload.update(Json{{"requestId",id},{"nonce",b64url(random(32))},{"issuedAt",epoch()},{"expiresAt",expires_},{"delegationJws",config_.at("delegationJws")},{"sessionId",q.sessionId},{"usageScenario",q.scenario},{"ephemeralJwk",ephemeral.jwk()},{"wrappedKey",config_.at("wrappedKey")}});requestJws=signer.sign(payload);Json body{{"requestJws",requestJws}};auto delivery=relay.call("POST","/v1/vault-requests",&body);
  if(telemetry_)telemetry_->emit("request_sent","info",id);
  {std::lock_guard lock(mutex_);if(!cancelled_)state_=delivery.value("pushDelivery","")=="sent"?State::Waiting:State::PushUnavailable;}
  while(!cancelled_&&std::chrono::steady_clock::now()<deadline_&&epoch()<expires_){
    require(systemProcess(caller.processId,L"LogonUI.exe")&&contextAllowed(caller.sessionId,q.sid.data(),q.scenario),"Sign-in context changed");auto result=relay.call("GET","/v1/vault-requests/"+id);
    if(result.contains("responseJws")&&result.at("responseJws").is_string()){
      auto p=response(result.at("responseJws"),config_.at("phoneIdentityJwk"),payload,requestJws,false);
      if(p.at("decision")=="deny"){if(telemetry_)telemetry_->emit("approval_denied","info",id);std::lock_guard lock(mutex_);clear();state_=State::Denied;return;}
      auto key=ephemeral.unwrap(p.at("wrappedKey"));auto password=open(key.bytes,config_.at("envelope"),pu::hash(config_.at("delegationJws").get<std::string>()));Secret packed(pack(wide(delegate_.at("loginName")),password.bytes,q.scenario));
      std::lock_guard lock(mutex_);require(!cancelled_&&std::chrono::steady_clock::now()<deadline_&&epoch()<expires_&&contextAllowed(caller.sessionId,q.sid.data(),q.scenario),"Approval expired or cancelled");credential_=std::move(packed.bytes);state_=State::ApprovedSignIn;if(telemetry_)telemetry_->emit("approval_verified","info",id);return;
    }
    if(result.at("state")=="expired"||result.at("state")=="cancelled")break;
    for(int i=0;i<10&&!cancelled_;i++)std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  if(telemetry_)telemetry_->emit("approval_expired","warning",id);
  {std::lock_guard lock(mutex_);clear();state_=cancelled_?State::Cancelled:State::Expired;}
  if(!requestJws.empty()){auto cancellation=message("vault-cancel","password-unlock");cancellation.update(Json{{"requestId",id},{"challengeHash",hash(requestJws)}});Json bodyCancel{{"cancelJws",signer.sign(cancellation)}};try{relay.call("POST","/v1/vault-requests/"+id+"/cancel",&bodyCancel);}catch(...){}}
}catch(...){if(telemetry_)telemetry_->emit("approval_failed","warning",id);std::lock_guard lock(mutex_);clear();state_=cancelled_?State::Cancelled:State::Unavailable;}}
}
