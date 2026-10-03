#pragma once
#include <chrono>

namespace pu {
// Notification scheduling only. This cannot authorize a Windows logon.
// Confined to the window thread; no timer retries an ignored/denied request.
class LockPromptGate {
  using Clock = std::chrono::steady_clock;
  bool locked_{};
  Clock::time_point nextAllowed_{};
public:
  bool locked() const { return locked_; }
  void unlock() { locked_ = false; }
  void observeLocked() { locked_ = true; }
  bool onLock(bool enabled, bool paired, bool busy, bool localConsole,
              Clock::time_point now) {
    if (locked_) return false;
    locked_ = true;
    if (!enabled || !paired || busy || !localConsole || now < nextAllowed_) return false;
    nextAllowed_ = now + std::chrono::seconds(60);
    return true;
  }
};
}
