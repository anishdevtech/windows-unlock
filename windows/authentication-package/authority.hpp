#pragma once
#include "core.hpp"
#include <map>
#include <mutex>
#include <functional>
namespace pu::auth {
inline constexpr char PackageName[]="WINDOWS-UNLOCK";
inline constexpr char Purpose[]="windows-unlock";
inline constexpr size_t MaxSubmission=8192;
struct Context {std::string sid,logonId;uint32_t session{},scenario{},logonUiPid{};uint64_t logonUiCreated{};};
// No tokens/passwords. OS adapter must authorize callers and obtain live context.
class Authority {
  struct Lease {Context context;Json trust,challenge;std::chrono::steady_clock::time_point deadline;};
  std::mutex mutex_;std::map<std::string,Lease> leases_;
  std::function<std::chrono::steady_clock::time_point()> clock_;
public:
  explicit Authority(std::function<std::chrono::steady_clock::time_point()> clock=[] {return std::chrono::steady_clock::now();}):clock_(std::move(clock)){}
  Json begin(const Context&,const Json& trust);
  void cancel(const std::string& id,uint32_t logonUiPid);
  void terminate(const std::string& logonId);
  Context context(const std::string& requestId);
  Json consume(const Json& submission,const Context& live,const Json& currentTrust);
};
Json proof(const std::string& request,const std::string& response);
Json submission(const void* bytes,size_t size);
}
