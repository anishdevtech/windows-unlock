#include "telemetry.hpp"
#include <fstream>
#include <set>
#include <regex>
#include <algorithm>
namespace pu {
namespace {
bool valid(const Json& e){static const std::set<std::string> codes{"app_started","app_stopped","relay_ready","relay_unavailable","request_sent","push_sent","push_failed","push_missing","approval_verified","approval_denied","approval_expired","approval_failed","camera_started","camera_stopped","camera_failed","remote_received","remote_failed","session_locked","session_unlocked","native_unavailable","native_ready","network_retry","credential_submitted","windows_signin_failed","windows_result_success"};
  static const std::regex id("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");try{return e.size()==6&&codes.contains(e.at("code"))&&e.at("timestamp").is_number_integer()&&e.at("timestamp").get<int64_t>()>epoch()-604800&&e.at("timestamp").get<int64_t>()<=epoch()+30&&std::regex_match(e.at("id").get<std::string>(),id)&&(e.at("requestId").is_null()||std::regex_match(e.at("requestId").get<std::string>(),id))&&(e.at("level")=="info"||e.at("level")=="warning"||e.at("level")=="error")&&(e.at("durationMs").is_null()||(e.at("durationMs").is_number_integer()&&e.at("durationMs").get<int64_t>()>=0&&e.at("durationMs").get<int64_t>()<=300000));}catch(...){return false;}}
}
Telemetry::Telemetry(Json config,const std::filesystem::path& state,std::string machineKey,std::string delegation):config_(std::move(config)),file_(state/L"diagnostics-pending.dpapi"),machineKey_(std::move(machineKey)),delegation_(std::move(delegation)){
  enabled_=config_.value("serverDiagnosticsEnabled",true);
  try{auto saved=load(file_);for(const auto& entry:saved.at("entries"))if(valid(entry)&&pending_.size()<256)pending_.push_back(entry);}catch(...){}
  worker_=std::jthread([this](std::stop_token stop){while(!stop.stop_requested()){
    std::unique_lock lock(mutex_);ready_.wait_for(lock,std::chrono::seconds(15),[&]{return stop.stop_requested();});if(stop.stop_requested())break;
    if(!enabled_||pending_.empty()||!config_.contains("transportToken"))continue;
    Json entries=Json::array();while(!pending_.empty()&&!valid(pending_.front()))pending_.pop_front();for(size_t i=0;i<std::min<size_t>(pending_.size(),50);i++)entries.push_back(pending_[i]);if(entries.empty())continue;lock.unlock();
    try{const bool machine=!machineKey_.empty();SigningKey key(machine?machineKey_:config_.at("id").get<std::string>(),false,machine);auto p=message("diagnostic-batch",machine?"password-unlock":"desktop-approval");auto now=epoch();p.update({{"batchId",uuid()},{"windowsDeviceId",config_.at("id")},{"issuedAt",now},{"expiresAt",now+300},{"entries",entries}});Json body{{"batchJws",key.sign(p)}};if(machine)body["delegationJws"]=delegation_;Http(config_.at("relayUrl"),config_.at("tlsPin"),config_.at("transportToken")).call("POST",machine?"/v1/vault-diagnostics":"/v1/diagnostics",&body);
      lock.lock();for(const auto& entry:entries){auto found=std::find_if(pending_.begin(),pending_.end(),[&](const Json& e){return e.at("id")==entry.at("id");});if(found!=pending_.end())pending_.erase(found);}save(file_,Json{{"entries",pending_}});
    }catch(...){/* Bounded encrypted queue retries; raw errors, paths and secrets are never uploaded. */}
  }});
}
void Telemetry::enabled(bool value){std::lock_guard lock(mutex_);enabled_=value;if(!value){pending_.clear();save(file_,Json{{"entries",pending_}});}ready_.notify_one();}
Telemetry::~Telemetry(){worker_.request_stop();ready_.notify_one();if(worker_.joinable())worker_.join();}
void Telemetry::emit(const char* code,const char* level,const std::string& id,int64_t duration)noexcept{try{Json entry{{"id",uuid()},{"timestamp",epoch()},{"code",code},{"level",level},{"requestId",id.empty()?Json(nullptr):Json(id)},{"durationMs",duration<0?Json(nullptr):Json(duration)}};if(!valid(entry)||!enabled_)return;std::lock_guard lock(mutex_);if(!enabled_)return;if(pending_.size()>=256)pending_.pop_front();pending_.push_back(entry);save(file_,Json{{"entries",pending_}});}catch(...){}}
}
