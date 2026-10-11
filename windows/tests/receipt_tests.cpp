#include "unlock_receipt.hpp"
#include <iostream>
using namespace pu;
void check(bool value){if(!value)throw std::runtime_error("Receipt validation failed");}
template<class F> void rejects(F f){bool rejected=false;try{f();}catch(...){rejected=true;}check(rejected);}
int main(){try{
  auto rootId=uuid(),machineId=uuid(),foreignId=uuid();SigningKey root(rootId,true),machine(machineId,true),foreign(foreignId,true);
  struct Cleanup{SigningKey& key;~Cleanup(){try{key.erase();}catch(...){}}} a{root},b{machine},c{foreign};
  auto pairId=uuid(),phoneId=uuid();const std::string sid="S-1-5-21-1-2-3-1001";Json config{{"id",rootId},{"pairing",{{"id",pairId},{"androidDeviceId",phoneId}}}};
  auto delegation=message("vault-delegation","password-unlock");delegation.update({{"vaultId",uuid()},{"windowsDeviceId",rootId},{"androidDeviceId",phoneId},{"pairingId",pairId},{"accountBindingId",uuid()},{"windowsAccountSid",sid},{"loginName","TEST\\user"},{"machineJwk",machine.jwk()}});
  auto receipt=message("signin-success","password-unlock");receipt.update({{"windowsDeviceId",rootId},{"pairingId",pairId},{"windowsAccountSid",sid},{"sessionId",1},{"requestId",uuid()},{"operationId","{11111111-1111-4111-8111-111111111111}"},{"timestamp",epoch()}});
  Json bundle{{"delegationJws",root.sign(delegation)},{"receiptJws",machine.sign(receipt)}};
  check(verifiedUnlockReceipt(bundle,config,sid,1,epoch())==receipt);
  rejects([&]{verifiedUnlockReceipt(bundle,config,sid,2,epoch());});rejects([&]{verifiedUnlockReceipt(bundle,config,"S-1-5-21-1-2-3-1002",1,epoch());});
  rejects([&]{verifiedUnlockReceipt(bundle,config,sid,1,epoch()+31);});rejects([&]{verifiedUnlockReceipt(bundle,config,sid,1,epoch()-3);});
  auto bad=bundle;bad["receiptJws"]=foreign.sign(receipt);rejects([&]{verifiedUnlockReceipt(bad,config,sid,1,epoch());});
  bad=bundle;bad["delegationJws"]=foreign.sign(delegation);rejects([&]{verifiedUnlockReceipt(bad,config,sid,1,epoch());});
  auto other=config;other["pairing"]["id"]=uuid();rejects([&]{verifiedUnlockReceipt(bundle,other,sid,1,epoch());});
  auto fake=receipt;fake["type"]="auth-response";bad=bundle;bad["receiptJws"]=machine.sign(fake);rejects([&]{verifiedUnlockReceipt(bad,config,sid,1,epoch());});
  fake=receipt;fake["password"]="forbidden";bad["receiptJws"]=machine.sign(fake);rejects([&]{verifiedUnlockReceipt(bad,config,sid,1,epoch());});
  std::cout<<"Signed unlock receipt: identity/session/pairing binding, expiry, forgery and field restrictions passed. Cosmetic only; no Windows authentication performed.\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
