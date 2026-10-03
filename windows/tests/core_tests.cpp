#include "core.hpp"
#include "remote.hpp"
#include "lock_prompt.hpp"
#include <iostream>
#include <functional>
#include <thread>
#include <atomic>
using namespace pu;
void expect(bool ok,const char* label){if(!ok)throw std::runtime_error(label);}
void rejects(const std::function<void()>& fn){bool rejected=false;try{fn();}catch(...){rejected=true;}expect(rejected,"Expected rejection");}
int main(int argc,char**argv){try{
  const auto now=std::chrono::steady_clock::now();LockPromptGate gate;
  expect(!gate.onLock(false,true,false,true,now),"Lock prompt requires opt-in");gate.unlock();
  expect(!gate.onLock(true,false,false,true,now),"Lock prompt requires pairing");gate.unlock();
  expect(!gate.onLock(true,true,true,true,now),"Lock prompt never queues while busy");
  expect(!gate.onLock(true,true,false,true,now),"Busy lock cycle is not retried");gate.unlock();
  expect(!gate.onLock(true,true,false,false,now),"No remote-session lock prompts");gate.unlock();
  expect(gate.onLock(true,true,false,true,now),"Local lock triggers once");
  expect(!gate.onLock(true,true,false,true,now+std::chrono::seconds(61)),"Duplicate lock event suppressed");gate.unlock();
  expect(!gate.onLock(true,true,false,true,now+std::chrono::seconds(1)),"Rapid relock cooldown");gate.unlock();
  expect(gate.onLock(true,true,false,true,now+std::chrono::seconds(60)),"New lock after cooldown");gate.unlock();
  gate.observeLocked();expect(!gate.onLock(true,true,false,true,now+std::chrono::seconds(120)),"Startup locked state never triggers");
  expect(hash("abc")=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","SHA256 vector");
  for(size_t n=1;n<128;n++){auto b=random(n);expect(unb64url(b64url(b))==b,"Base64 roundtrip");}
  rejects([]{parse("{\"a\":1,\"a\":2}");});rejects([]{unb64url("AA==");});
  const auto id=uuid();{SigningKey key(id,true);auto p=message("auth-response");p["decision"]="approve";auto t=key.sign(p);expect(verify(t,key.jwk(),"auth-response")==p,"CNG roundtrip");
    rejects([&]{verify(t,key.jwk(),"auth-request");});auto bad=t;bad[bad.size()-10]=bad[bad.size()-10]=='A'?'B':'A';rejects([&]{verify(bad,key.jwk(),"auth-response");});
    auto privateJwk=key.jwk();privateJwk["d"]="secret";rejects([&]{publicJwk(privateJwk);});
    auto challenge=message("auth-request");challenge.update({{"requestId",uuid()},{"pairingId",uuid()},{"windowsDeviceId",uuid()},{"androidDeviceId",uuid()},{"expiresAt",epoch()+60}});auto challengeToken=key.sign(challenge);
    Json pairing{{"approvalJwk",key.jwk()},{"identityJwk",key.jwk()}};auto response=message("auth-response");response.update({{"requestId",challenge.at("requestId")},{"pairingId",challenge.at("pairingId")},{"windowsDeviceId",challenge.at("windowsDeviceId")},{"androidDeviceId",challenge.at("androidDeviceId")},{"challengeHash",hash(challengeToken)},{"decision","approve"}});auto responseToken=key.sign(response);auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(60);
    PendingApproval pending(challenge,challengeToken,pairing,deadline);auto wrong=response;wrong["challengeHash"]=std::string(64,'0');rejects([&]{pending.consume(key.sign(wrong));});expect(pending.consume(responseToken)=="approve","Valid approval");rejects([&]{pending.consume(responseToken);});
    PendingApproval cancelled(challenge,challengeToken,pairing,deadline);cancelled.cancel();rejects([&]{cancelled.consume(responseToken);});
    PendingApproval expired(challenge,challengeToken,pairing,std::chrono::steady_clock::now());rejects([&]{expired.consume(responseToken);});
    PendingApproval concurrent(challenge,challengeToken,pairing,deadline);std::atomic<int> accepted{};auto consume=[&]{try{concurrent.consume(responseToken);accepted++;}catch(...){}};std::thread first(consume),second(consume);first.join();second.join();expect(accepted==1,"Atomic duplicate approval");
    auto offer=message("remote-offer");offer.update({{"offerId",uuid()},{"windowsDeviceId",challenge.at("windowsDeviceId")},{"androidDeviceId",challenge.at("androidDeviceId")},{"pairingId",challenge.at("pairingId")},{"expiresAt",epoch()+60},{"actions",Json::array({"lock"})}});auto offerToken=key.sign(offer);
    auto command=message("remote-command");command.update({{"commandId",uuid()},{"offerId",offer.at("offerId")},{"windowsDeviceId",offer.at("windowsDeviceId")},{"androidDeviceId",offer.at("androidDeviceId")},{"pairingId",offer.at("pairingId")},{"offerHash",hash(offerToken)},{"action","lock"},{"viewerJwk",nullptr}});auto commandToken=key.sign(command);
    RemoteLease lease(offer,offerToken,pairing,deadline);auto disabled=command;disabled["action"]="restart";rejects([&]{lease.consume(key.sign(disabled));});auto mismatch=command;mismatch["offerHash"]=std::string(64,'0');rejects([&]{lease.consume(key.sign(mismatch));});expect(lease.consume(commandToken)==command,"Remote command verified");rejects([&]{lease.consume(commandToken);});
    RemoteLease oldLease(offer,offerToken,pairing,std::chrono::steady_clock::now());rejects([&]{oldLease.consume(commandToken);});RemoteLease parallelLease(offer,offerToken,pairing,deadline);accepted=0;auto remoteConsume=[&]{try{parallelLease.consume(commandToken);accepted++;}catch(...){}};std::thread third(remoteConsume),fourth(remoteConsume);third.join();fourth.join();expect(accepted==1,"Atomic remote replay protection");
    if(argc==3&&std::string(argv[1])=="--interop"){auto fixture=parse(read(wide(argv[2])));verify(fixture.at("token"),fixture.at("jwk"),"auth-response");auto out=message("auth-response");out["test"]="windows-to-node";Json result{{"jwk",key.jwk()},{"token",key.sign(out)}};
      if(fixture.contains("cameraJwk")){auto secret=random(32);auto wrapped=wrapCameraKey(fixture.at("cameraJwk"),secret);Bytes testImage{'c','a','m','e','r','a'};result["cameraFrame"]=encryptCameraFrame(secret,testImage,"test-session",1,wrapped);SecureZeroMemory(secret.data(),secret.size());}
      write(wide(std::string(argv[2])+".windows.json"),result.dump());}
  }
  NCRYPT_PROV_HANDLE prov{};NCRYPT_KEY_HANDLE testKey{};NCryptOpenStorageProvider(&prov,MS_KEY_STORAGE_PROVIDER,0);auto name=wide("WINDOWS-UNLOCK-"+id);if(NCryptOpenKey(prov,&testKey,name.c_str(),0,0)==0)NCryptDeleteKey(testKey,0);NCryptFreeObject(prov);
  auto file=std::filesystem::temp_directory_path()/wide("phoneunlock-"+uuid()+".dpapi");save(file,Json{{"token","test-secret"}});expect(load(file).at("token")=="test-secret","DPAPI roundtrip");write(file,"corrupt");rejects([&]{load(file);});std::filesystem::remove(file);
  std::cout<<"CNG, strict JWS/JSON, DPAPI security checks passed\n";return 0;
}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}
