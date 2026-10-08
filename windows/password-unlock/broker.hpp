#pragma once
#include "storage.hpp"
#include "ipc.hpp"
#include "telemetry.hpp"
#include <mutex>
#include <thread>
namespace pu::vault {
class Broker {
  Json config_,delegate_;bool configured_{};std::mutex mutex_;std::jthread worker_,watchdog_;std::atomic<bool> cancelled_{false},active_{false};
  native::Request current_{};native::Caller owner_{};native::State state_{native::State::Unavailable};
  Bytes credential_;std::chrono::steady_clock::time_point deadline_{},nextAllowed_{};int64_t expires_{};
  std::string requestId_;bool claimed_{},resultReported_{};
  std::recursive_mutex launchMutex_;bool background_{};DWORD automaticSession_{0xffffffff};unsigned automaticTicks_{};
  std::unique_ptr<Telemetry> telemetry_;
  bool same(const native::Request&,const native::Caller&)const;void clear();void run(native::Request,native::Caller);
  void automaticTick();
public:
  Broker();~Broker();native::Response dispatch(const native::Request&,const native::Caller&);void cancel(DWORD);
  void requestAutomatically(DWORD session);
};
bool contextAllowed(DWORD session,const std::wstring& sid,DWORD scenario);
}
