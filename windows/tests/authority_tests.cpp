#include "session.hpp"
#include <iostream>
#include <thread>
#include <atomic>
#include <sddl.h>
using namespace pu;using namespace pu::auth;using namespace pu::native;
template<class F> void rejects(F f){bool bad=false;try{f();}catch(...){bad=true;}require(bad,"Expected rejection");}
struct Cleanup{std::string id;~Cleanup(){NCRYPT_PROV_HANDLE p{};NCRYPT_KEY_HANDLE k{};if(NCryptOpenStorageProvider(&p,MS_KEY_STORAGE_PROVIDER,0)==0){auto n=wide("WINDOWS-UNLOCK-"+id);if(NCryptOpenKey(p,&k,n.c_str(),0,0)==0&&NCryptDeleteKey(k,0)!=0)NCryptFreeObject(k);NCryptFreeObject(p);}}};
PVOID NTAPI allocate(ULONG n){return HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,n);}
int main(){try{
  const auto id=uuid(),pid=uuid(),did=uuid();Cleanup a{id},b{pid},c{did};SigningKey laptop(id,true),phone(pid,true),identity(did,true);
  Context ctx{"S-1-5-21-1-2-3-1001","0000000000001234",1,1,123};
  Json trust{{"v",1},{"mode","windows-unlock"},{"id",id},{"sid",ctx.sid},{"accountBindingId",uuid()},{"windowsJwk",laptop.jwk()},{"pairing",Json{{"id",uuid()},{"androidDeviceId",pid},{"phoneName","Fixture"},{"approvalJwk",phone.jwk()},{"identityJwk",identity.jwk()}}}};
  auto signResponse=[&](const Json& q,const std::string& token,SigningKey& key,const std::string& purpose=Purpose){auto response=message("auth-response",purpose);response.update({{"requestId",q.at("requestId")},{"pairingId",q.at("pairingId")},{"windowsDeviceId",q.at("windowsDeviceId")},{"androidDeviceId",q.at("androidDeviceId")},{"challengeHash",hash(token)},{"decision","approve"}});return key.sign(response);};
  Authority auth;auto q=auth.begin(ctx,trust);require(unb64url(q.at("nonce")).size()==32&&q.size()==15,"Authority nonce/context fields");rejects([&]{auth.begin(ctx,trust);});auto request=laptop.sign(q);auto response=signResponse(q,request,phone);auto s=proof(request,response);auto bytes=s.dump();require(submission(bytes.data(),bytes.size())==s,"Pointer-free serialization");rejects([&]{submission(nullptr,1);});rejects([&]{submission(bytes.data(),MaxSubmission);});
  auto wrong=ctx;wrong.session++;rejects([&]{auth.consume(s,wrong,trust);});wrong=ctx;wrong.logonId="0000000000009999";rejects([&]{auth.consume(s,wrong,trust);});wrong=ctx;wrong.sid="S-1-5-21-1-2-3-1002";rejects([&]{auth.consume(s,wrong,trust);});wrong=ctx;wrong.scenario=2;rejects([&]{auth.consume(s,wrong,trust);});
  auto revoked=trust;revoked["pairing"]["approvalJwk"]=identity.jwk();rejects([&]{auth.consume(s,ctx,revoked);});
  wrong=ctx;wrong.logonUiPid++;rejects([&]{auth.consume(s,wrong,trust);});wrong=ctx;wrong.logonUiCreated++;rejects([&]{auth.consume(s,wrong,trust);});
  auto fake=s;fake["responseJws"]=signResponse(q,request,identity);rejects([&]{auth.consume(fake,ctx,trust);});fake=s;fake["responseJws"]=signResponse(q,request,phone,"desktop-approval");rejects([&]{auth.consume(fake,ctx,trust);});
  auto invented=q;invented["nonce"]=b64url(random(32));auto other=laptop.sign(invented);fake=proof(other,signResponse(invented,other,phone));rejects([&]{auth.consume(fake,ctx,trust);});
  std::atomic<unsigned> accepted{};auto consume=[&]{try{auth.consume(s,ctx,trust);accepted++;}catch(...){}};std::thread first(consume),second(consume);first.join();second.join();require(accepted==1,"Exactly one authority consumption");rejects([&]{auth.consume(s,ctx,trust);});
  q=auth.begin(ctx,trust);request=laptop.sign(q);s=proof(request,signResponse(q,request,phone));auth.cancel(q.at("requestId"),ctx.logonUiPid);rejects([&]{auth.consume(s,ctx,trust);});
  q=auth.begin(ctx,trust);request=laptop.sign(q);s=proof(request,signResponse(q,request,phone));auth.terminate(ctx.logonId);rejects([&]{auth.consume(s,ctx,trust);});
  auto time=std::chrono::steady_clock::now();Authority expired([&]{return time;});q=expired.begin(ctx,trust);request=laptop.sign(q);s=proof(request,signResponse(q,request,phone));time+=std::chrono::seconds(61);rejects([&]{expired.consume(s,ctx,trust);});
  HANDLE handle{};require(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&handle)!=FALSE,"Source token unavailable");Handle token(handle);auto info=tokenInformation(token.get(),allocate);require(info->DefaultDacl.DefaultDacl&&IsValidAcl(info->DefaultDacl.DefaultDacl)&&info->Privileges==nullptr,"No broad default DACL/invented privileges");require(tokenSid(handle)==[] (PSID sid){LPWSTR p{};ConvertSidToStringSidW(sid,&p);std::wstring s(p);LocalFree(p);return s;}(info->User.User.Sid),"Source account preserved");for(DWORD i=0;i<info->Groups->GroupCount;i++)require(!(info->Groups->Groups[i].Attributes&SE_GROUP_LOGON_ID),"Old logon SID removed");HeapFree(GetProcessHeap(),0,info);
  std::cout<<"LSA authority: purpose, nonce/session/account binding, revocation, cancellation, expiry, concurrent replay and OS-derived token information passed. No Windows token created or logon attempted.\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
