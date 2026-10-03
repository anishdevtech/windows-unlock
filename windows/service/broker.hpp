#pragma once
#include "storage.hpp"
#include <mutex>
#include <thread>
namespace pu::preview {
class Broker {
  Json config_;bool configured_{};std::mutex mutex_;native::Request current_{};native::Caller owner_{};
  native::State state_{native::State::Unavailable};std::jthread worker_;std::atomic<bool> cancelled_{false},workerActive_{false};
  std::chrono::steady_clock::time_point nextAllowed_{},deadline_{};
  bool same(const native::Request&,const native::Caller&) const;
  void set(native::State);
  void run(native::Request,native::Caller);
public:
  Broker();~Broker();
  native::Response dispatch(const native::Request&,const native::Caller&);
  void cancel(DWORD session);
};
}
