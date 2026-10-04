#include "authority.hpp"
#include "ipc.hpp"
namespace pu::auth {
using native::require;
Json proof(const std::string& request,const std::string& response){auto p=decode(request);return {{"v",1},{"requestId",p.at("requestId")},{"requestJws",request},{"responseJws",response}};}
Json submission(const void* bytes,size_t size){require(bytes&&size>0&&size<MaxSubmission,"Invalid credential length");auto j=parse(std::string(static_cast<const char*>(bytes),size));require(j.size()==4&&j.at("v")==1&&j.at("requestId").is_string()&&j.at("requestJws").is_string()&&j.at("responseJws").is_string(),"Invalid credential fields");return j;}
Json Authority::begin(const Context& c,const Json& trust){
  require(native::validSid(wide(c.sid))&&c.session>0&&(c.scenario==1||c.scenario==2)&&c.logonUiPid&&c.logonId.size()==16&&trust.at("sid")==c.sid,"Invalid unlock context");
  std::lock_guard lock(mutex_);auto now=clock_();
  for(auto i=leases_.begin();i!=leases_.end();)if(i->second.deadline<=now)i=leases_.erase(i);else ++i;
  require(leases_.size()<8,"Too many pending unlocks");for(const auto& [id,lease]:leases_)require(lease.context.session!=c.session,"Unlock already pending");
  const auto id=uuid();const auto issued=epoch();const auto& pair=trust.at("pairing");
  auto q=message("auth-request",Purpose);q.update({{"requestId",id},{"windowsDeviceId",trust.at("id")},{"androidDeviceId",pair.at("androidDeviceId")},{"pairingId",pair.at("id")},{"accountBindingId",trust.at("accountBindingId")},{"nonce",b64url(random(32))},{"issuedAt",issued},{"expiresAt",issued+60},{"windowsAccountSid",c.sid},{"sessionId",c.session},{"usageScenario",c.scenario},{"existingLogonId",c.logonId}});
  leases_.emplace(id,Lease{c,trust,q,now+std::chrono::seconds(60)});return q;
}
void Authority::cancel(const std::string& id,uint32_t pid){std::lock_guard lock(mutex_);auto i=leases_.find(id);if(i!=leases_.end()&&i->second.context.logonUiPid==pid)leases_.erase(i);}
void Authority::terminate(const std::string& luid){std::lock_guard lock(mutex_);for(auto i=leases_.begin();i!=leases_.end();)if(i->second.context.logonId==luid)i=leases_.erase(i);else ++i;}
Context Authority::context(const std::string& id){std::lock_guard lock(mutex_);auto i=leases_.find(id);require(i!=leases_.end(),"Unknown unlock");return i->second.context;}
Json Authority::consume(const Json& s,const Context& live,const Json& trust){
  std::lock_guard lock(mutex_);auto i=leases_.find(s.at("requestId").get<std::string>());require(i!=leases_.end(),"Unknown or consumed nonce");auto& l=i->second;
  require(clock_()<l.deadline&&epoch()<l.challenge.at("expiresAt").get<int64_t>(),"Unlock expired");
  require(l.context.sid==live.sid&&l.context.session==live.session&&l.context.logonId==live.logonId&&l.context.scenario==live.scenario&&l.context.logonUiPid==live.logonUiPid&&l.context.logonUiCreated==live.logonUiCreated&&l.trust==trust,"Unlock context/enrollment changed");
  const auto request=s.at("requestJws").get<std::string>();auto q=verify(request,trust.at("windowsJwk"),"auth-request",Purpose);require(q==l.challenge,"Authority challenge mismatch");
  PendingApproval pending(q,request,trust.at("pairing"),l.deadline);require(pending.consume(s.at("responseJws"))=="approve","Unlock denied");
  auto accepted=l.challenge;leases_.erase(i);return accepted; // consumed before any token allocation
}
}
