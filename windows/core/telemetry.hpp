#pragma once
#include "core.hpp"
#include <condition_variable>
#include <mutex>
#include <thread>
#include <deque>
namespace pu {
class Telemetry {
  Json config_;std::filesystem::path file_;std::mutex mutex_;std::condition_variable ready_;
  std::deque<Json> pending_;std::jthread worker_;std::atomic<bool> enabled_{true};
  std::string machineKey_,delegation_;
public:
  Telemetry(Json config,const std::filesystem::path& state,std::string machineKey={},std::string delegation={});
  ~Telemetry();
  void enabled(bool value);
  void emit(const char* code,const char* level="info",const std::string& requestId={},int64_t duration=-1) noexcept;
};
}
