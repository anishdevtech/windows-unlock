#include "remote.hpp"
#include "camera.hpp"
#include <bcrypt.h>
#include <objbase.h>
#include <powrprof.h>
#include <fstream>
#include <algorithm>
#include <regex>
#include <stdexcept>
namespace pu {
namespace {
void ok(NTSTATUS s){if(s<0)throw std::runtime_error("Camera encryption unavailable");}
struct Algorithm{BCRYPT_ALG_HANDLE h{};~Algorithm(){if(h)BCryptCloseAlgorithmProvider(h,0);}};
struct Key{BCRYPT_KEY_HANDLE h{};~Key(){if(h)BCryptDestroyKey(h);}};
bool sessionUnlocked(){HDESK d=OpenInputDesktop(0,FALSE,DESKTOP_READOBJECTS);if(!d)return false;wchar_t name[64]{};DWORD needed=0;bool good=GetUserObjectInformationW(d,UOI_NAME,name,sizeof(name),&needed)&&std::wstring(name)==L"Default";CloseDesktop(d);return good;}
void shutdownPrivilege(){HANDLE token{};if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&token))throw std::runtime_error("Privilege unavailable");TOKEN_PRIVILEGES p{};p.PrivilegeCount=1;LookupPrivilegeValueW(nullptr,SE_SHUTDOWN_NAME,&p.Privileges[0].Luid);p.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;SetLastError(ERROR_SUCCESS);bool good=AdjustTokenPrivileges(token,FALSE,&p,0,nullptr,nullptr)&&GetLastError()==ERROR_SUCCESS;CloseHandle(token);if(!good)throw std::runtime_error("Power control permission unavailable");}
void power(const std::string& action){
  if(action=="lock"){if(!LockWorkStation())throw std::runtime_error("Lock failed");return;}
  shutdownPrivilege();
  if(action=="sleep"){if(!SetSuspendState(FALSE,FALSE,FALSE))throw std::runtime_error("Sleep unavailable");return;}
  UINT flags=action=="restart"?EWX_REBOOT:EWX_SHUTDOWN;
  if(!ExitWindowsEx(flags,SHTDN_REASON_MAJOR_OTHER|SHTDN_REASON_MINOR_OTHER|SHTDN_REASON_FLAG_PLANNED))throw std::runtime_error("Power action unavailable");
}
}
Json RemoteLease::consume(const std::string& token){
  auto c=verify(token,pair_.at("approvalJwk"),"remote-command");
  static const std::regex id("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
  if(c.size()!=11||!std::regex_match(c.at("commandId").get<std::string>(),id)||c.at("offerId")!=offer_.at("offerId")||c.at("offerHash")!=hash(token_)||c.at("windowsDeviceId")!=offer_.at("windowsDeviceId")||c.at("androidDeviceId")!=offer_.at("androidDeviceId")||c.at("pairingId")!=offer_.at("pairingId"))throw std::runtime_error("Remote binding mismatch");
  const auto action=c.at("action").get<std::string>();if(std::find(offer_.at("actions").begin(),offer_.at("actions").end(),action)==offer_.at("actions").end())throw std::runtime_error("Action disabled");
  if(action!="camera-start"&&c.at("viewerJwk")!=nullptr)throw std::runtime_error("Unexpected viewer key");
  if(std::chrono::steady_clock::now()>=deadline_||epoch()>=offer_.at("expiresAt").get<int64_t>())throw std::runtime_error("Remote offer expired");
  bool expected=true;if(!pending_.compare_exchange_strong(expected,false))throw std::runtime_error("Remote offer already consumed");
  if(std::chrono::steady_clock::now()>=deadline_||epoch()>=offer_.at("expiresAt").get<int64_t>())throw std::runtime_error("Remote offer expired");return c;
}
Bytes wrapCameraKey(const Json& jwk,const Bytes& secret){
  if(jwk.size()!=3||jwk.at("kty")!="RSA"||jwk.at("e")!="AQAB")throw std::runtime_error("Invalid viewer key");
  auto n=unb64url(jwk.at("n"));auto e=unb64url(jwk.at("e"));if(n.size()!=256||n.front()<128)throw std::runtime_error("Invalid viewer modulus");
  BCRYPT_RSAKEY_BLOB header{BCRYPT_RSAPUBLIC_MAGIC,2048,ULONG(e.size()),ULONG(n.size()),0,0};Bytes blob(sizeof(header)+e.size()+n.size());memcpy(blob.data(),&header,sizeof(header));memcpy(blob.data()+sizeof(header),e.data(),e.size());memcpy(blob.data()+sizeof(header)+e.size(),n.data(),n.size());
  Algorithm alg;Key key;ok(BCryptOpenAlgorithmProvider(&alg.h,BCRYPT_RSA_ALGORITHM,nullptr,0));ok(BCryptImportKeyPair(alg.h,nullptr,BCRYPT_RSAPUBLIC_BLOB,&key.h,blob.data(),ULONG(blob.size()),0));
  BCRYPT_OAEP_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM,nullptr,0};Bytes out(256);ULONG count=0;ok(BCryptEncrypt(key.h,const_cast<PUCHAR>(secret.data()),ULONG(secret.size()),&padding,nullptr,0,out.data(),ULONG(out.size()),&count,BCRYPT_PAD_OAEP));out.resize(count);return out;
}
Json encryptCameraFrame(const Bytes& secret,const Bytes& jpeg,const std::string& session,uint64_t seq,const Bytes& wrapped){
  if(secret.size()!=32||jpeg.size()>45000)throw std::runtime_error("Frame size invalid");
  Algorithm alg;Key key;ok(BCryptOpenAlgorithmProvider(&alg.h,BCRYPT_AES_ALGORITHM,nullptr,0));ok(BCryptSetProperty(alg.h,BCRYPT_CHAINING_MODE,reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),sizeof(BCRYPT_CHAIN_MODE_GCM),0));
  ok(BCryptGenerateSymmetricKey(alg.h,&key.h,nullptr,0,const_cast<PUCHAR>(secret.data()),ULONG(secret.size()),0));auto iv=random(12);Bytes tag(16),encrypted(jpeg.size()+16);const auto aad=session+":"+std::to_string(seq);
  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;BCRYPT_INIT_AUTH_MODE_INFO(info);info.pbNonce=iv.data();info.cbNonce=ULONG(iv.size());info.pbTag=tag.data();info.cbTag=ULONG(tag.size());info.pbAuthData=reinterpret_cast<PUCHAR>(const_cast<char*>(aad.data()));info.cbAuthData=ULONG(aad.size());ULONG count=0;
  ok(BCryptEncrypt(key.h,const_cast<PUCHAR>(jpeg.data()),ULONG(jpeg.size()),&info,nullptr,0,encrypted.data(),ULONG(jpeg.size()),&count,0));encrypted.resize(count);encrypted.insert(encrypted.end(),tag.begin(),tag.end());
  return {{"sequence",seq},{"iv",b64url(iv)},{"ciphertext",b64url(encrypted)},{"wrappedKey",b64url(wrapped)}};
}
RemoteAgent::RemoteAgent(Json config,std::function<void(std::string)> notify,std::function<bool()> cameraPermitted,std::function<bool(bool)> cameraDisclosure,std::function<bool()> cameraIndicatorVisible,std::function<void(const char*)> trace){
  thread_=std::jthread([config=std::move(config),notify=std::move(notify),cameraPermitted=std::move(cameraPermitted),cameraDisclosure=std::move(cameraDisclosure),cameraIndicatorVisible=std::move(cameraIndicatorVisible),trace=std::move(trace)](std::stop_token stop){
    CoInitializeEx(nullptr,COINIT_MULTITHREADED);
    try{
      auto pair=config.at("pairing");SigningKey signer(config.at("id"));Http relay(config.at("relayUrl"),config.at("tlsPin"),config.at("transportToken"));
      Json offer;std::string offerToken;bool pending=false;auto deadline=std::chrono::steady_clock::now();std::unique_ptr<RemoteLease> lease;bool networkFailed=false,readyReported=false;unsigned retrySeconds=1;auto nextCommands=deadline;
      std::unique_ptr<Camera> camera;Bytes secret,wrapped;std::string cameraId,envelopeJws;bool disclosed=false;uint64_t sequence=0;auto cameraDeadline=deadline;
      auto stopCamera=[&]{const bool wasActive=bool(camera),hadKey=!secret.empty(),hadDisclosure=disclosed;disclosed=false;camera.reset();if(!secret.empty())SecureZeroMemory(secret.data(),secret.size());secret.clear();wrapped.clear();if(wasActive||hadKey||hadDisclosure)cameraDisclosure(false);if(wasActive)trace("camera_stopped");if(wasActive)notify("Camera stopped. Remote controls remain available.");};
      while(!stop.stop_requested()){
        try{
          if(camera&&(!cameraPermitted()||!cameraIndicatorVisible()||!sessionUnlocked()||std::chrono::steady_clock::now()>=cameraDeadline))stopCamera();
          Json actions=Json::array();
            if(config.value("remotePowerEnabled",false))for(const auto* a:{"lock","sleep","shutdown","restart"})actions.push_back(a);
            if(config.value("cameraSharingEnabled",false)&&cameraPermitted()&&sessionUnlocked())actions.push_back("camera-start");actions.push_back("camera-stop");
          if(!pending||std::chrono::steady_clock::now()+std::chrono::seconds(15)>=deadline||offer.value("actions",Json::array())!=actions){
            auto issued=epoch();offer=message("remote-offer");
            offer.update({{"offerId",uuid()},{"windowsDeviceId",config.at("id")},{"androidDeviceId",pair.at("androidDeviceId")},{"pairingId",pair.at("id")},{"nonce",b64url(random(32))},{"issuedAt",issued},{"expiresAt",issued+60},{"actions",actions}});
            pending=false;offerToken=signer.sign(offer);deadline=std::chrono::steady_clock::now()+std::chrono::seconds(60);lease=std::make_unique<RemoteLease>(offer,offerToken,pair,deadline);Json body{{"offerJws",offerToken}};relay.call("POST","/v1/remote/offers",&body);pending=true;
          }
          Json rows{{"commands",Json::array()}};if(!camera||std::chrono::steady_clock::now()>=nextCommands){rows=relay.call("GET","/v1/remote/commands/pending");nextCommands=std::chrono::steady_clock::now()+std::chrono::seconds(1);}
          for(const auto& row:rows.at("commands")){
            const auto token=row.at("commandJws").get<std::string>();
            if(!pending||!lease||stop.stop_requested())continue;Json command;try{command=lease->consume(token);}catch(...){continue;}
            const auto action=command.at("action").get<std::string>();trace("remote_received");
            // Consume the local lease before any OS action; never restore it from the relay.
            pending=false;const auto id=command.at("commandId").get<std::string>();const auto result=[&](const char* value){auto p=message("remote-result");p.update({{"commandId",id},{"commandHash",hash(token)},{"result",value},{"timestamp",epoch()}});if(config.contains("historyFile")){std::ofstream log(wide(config.at("historyFile")),std::ios::app);log<<Json{{"timestamp",epoch()},{"device",config.at("id")},{"requestId",id},{"action",action},{"result",value},{"snapshotPath",nullptr}}.dump()<<'\n';}Json b{{"resultJws",signer.sign(p)}};try{relay.call("POST","/v1/remote/commands/"+id+"/result",&b);}catch(...){};};
            try{
              if(stop.stop_requested())throw std::runtime_error("Local permission changed");
              if(action=="camera-stop"){stopCamera();result("accepted");continue;}
              if(action=="camera-start"){
                if(!cameraPermitted()||!sessionUnlocked())throw std::runtime_error("Camera permission removed");stopCamera();
                if(!cameraDisclosure(true))throw std::runtime_error("Visible camera indicator unavailable");disclosed=true;
                secret=random(32);wrapped=wrapCameraKey(command.at("viewerJwk"),secret);auto envelope=message("camera-envelope");envelope.update({{"cameraId",id},{"commandHash",hash(token)},{"windowsDeviceId",config.at("id")},{"androidDeviceId",pair.at("androidDeviceId")},{"pairingId",pair.at("id")},{"keyHash",hash(b64url(wrapped))}});envelopeJws=signer.sign(envelope);cameraDeadline=std::chrono::steady_clock::now()+std::chrono::seconds(60);camera=std::make_unique<Camera>(cameraDeadline,[&]{return cameraPermitted()&&cameraIndicatorVisible()&&sessionUnlocked()&&!stop.stop_requested();});cameraId=id;sequence=0;trace("camera_started");notify("CAMERA STREAMING TO YOUR PHONE — stops after 60 seconds.\nDisable Camera sharing here to stop.");result("accepted");
              }else {if(command.at("viewerJwk")!=nullptr)throw std::runtime_error("Unexpected camera key");stopCamera();result("accepted");notify("Phone approved laptop action: "+action);power(action);}
            }catch(...){trace(action=="camera-start"?"camera_failed":"remote_failed");stopCamera();result("failed");notify("Remote action unavailable. Check local permissions or camera access.");}
          }
          if(camera){auto jpeg=camera->frame();if(!cameraPermitted()||!cameraIndicatorVisible()||!sessionUnlocked()||stop.stop_requested()||std::chrono::steady_clock::now()>=cameraDeadline){stopCamera();continue;}auto body=encryptCameraFrame(secret,jpeg,cameraId,++sequence,wrapped);body["envelopeJws"]=envelopeJws;relay.call("POST","/v1/camera/"+cameraId+"/frame",&body);}
          if(!readyReported||networkFailed){trace("relay_ready");readyReported=true;networkFailed=false;notify(camera?"Camera streaming • local Stop sharing button remains available.":"Phone controls online • camera sharing requires local permission and an unlocked session.");}retrySeconds=1;
        }catch(...){if(!networkFailed){trace("relay_unavailable");networkFailed=true;}if(camera)trace("camera_failed");stopCamera();notify("Connection or camera unavailable. Check Windows camera privacy and the server logs.");/* fail closed, retry bounded networking without logging secrets */}
        for(unsigned n=0;n<(networkFailed?retrySeconds*10:5)&&!stop.stop_requested();n++)std::this_thread::sleep_for(std::chrono::milliseconds(100));if(networkFailed)retrySeconds=std::min<unsigned>(15,retrySeconds*2);
      }
      stopCamera();
    }catch(...){notify("Remote controls unavailable. Windows PIN remains unchanged.");}
    CoUninitialize();
  });
}
RemoteAgent::~RemoteAgent(){thread_.request_stop();if(thread_.joinable())thread_.join();}
}
