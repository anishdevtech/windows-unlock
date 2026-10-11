#include "unlock_receipt.hpp"
namespace pu {
Json verifiedUnlockReceipt(const Json& bundle,const Json& config,const std::string& sid,DWORD session,int64_t now){
  if(bundle.size()!=2||!config.contains("pairing"))throw std::runtime_error("No paired receipt");
  SigningKey root(config.at("id"));
  auto delegate=verify(bundle.at("delegationJws"),root.jwk(),"vault-delegation","password-unlock");
  const auto& pair=config.at("pairing");
  if(delegate.size()!=11||delegate.at("windowsDeviceId")!=config.at("id")||delegate.at("pairingId")!=pair.at("id")||delegate.at("androidDeviceId")!=pair.at("androidDeviceId")||delegate.at("windowsAccountSid")!=sid)throw std::runtime_error("Receipt delegation mismatch");
  auto receipt=verify(bundle.at("receiptJws"),delegate.at("machineJwk"),"signin-success","password-unlock");
  if(receipt.size()!=10||receipt.at("windowsDeviceId")!=config.at("id")||receipt.at("pairingId")!=pair.at("id")||receipt.at("windowsAccountSid")!=sid||receipt.at("sessionId")!=session||!receipt.at("timestamp").is_number_integer())throw std::runtime_error("Receipt binding mismatch");
  auto timestamp=receipt.at("timestamp").get<int64_t>();
  if(timestamp>now+2||timestamp<now-30||!receipt.at("requestId").is_string()||!receipt.at("operationId").is_string())throw std::runtime_error("Stale receipt");
  return receipt;
}
}
