#pragma once
#include "core.hpp"
#include <functional>
#include <thread>
namespace pu {
// One authenticated, short-lived LAN session. No media is stored on the relay.
class DirectMedia {
  struct Impl;std::unique_ptr<Impl> impl_;
public:
  DirectMedia(std::string id,std::string mode,Bytes key,std::function<bool()> permitted);
  ~DirectMedia();
  Json transport() const;
  Bytes preview();
  bool connected() const;
  bool running() const;
};
Bytes mediaKey(const Bytes& master,const std::string& direction);
Bytes decryptMediaPacket(const Bytes& key,const Json& packet,const std::string& session);
}
