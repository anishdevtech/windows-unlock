#pragma once
#include "core.hpp"
#include <functional>
#include <thread>
#include <memory>
namespace pu {
class RemoteLease {
  Json offer_,pair_;std::string token_;std::chrono::steady_clock::time_point deadline_;std::atomic<bool> pending_{true};
public:
  RemoteLease(Json offer,std::string token,Json pair,std::chrono::steady_clock::time_point deadline):offer_(std::move(offer)),pair_(std::move(pair)),token_(std::move(token)),deadline_(deadline){}
  Json consume(const std::string& command);
};
class RemoteAgent {
  std::jthread thread_;
public:
  RemoteAgent(Json config,std::function<void(std::string)> status,
              std::function<bool()> cameraPermitted);
  ~RemoteAgent();
};
// Standard RSA-OAEP(SHA256/MGF1-SHA256) + AES-256-GCM camera transport.
Bytes wrapCameraKey(const Json& rsaPublic,const Bytes& key);
Json encryptCameraFrame(const Bytes& key,const Bytes& jpeg,const std::string& session,
                        uint64_t sequence,const Bytes& wrappedKey);
}
