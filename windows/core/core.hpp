#pragma once
#include <windows.h>
#include <winhttp.h>
#include <ncrypt.h>
#include <nlohmann/json.hpp>
#include <chrono>
#include <filesystem>
#include <string>
#include <vector>
#include <atomic>
namespace pu {
using Json = nlohmann::json;
using Bytes = std::vector<unsigned char>;
std::wstring wide(const std::string& s);
std::string utf8(const std::wstring& s);
std::string uuid();
int64_t epoch();
Bytes random(size_t n);
std::string b64url(const Bytes& bytes);
Bytes unb64url(const std::string& text);
Bytes sha256(const std::string& text);
std::string hash(const std::string& text);
std::string tlsPin(const Bytes& spki);
Json parse(const std::string& text);
Json publicJwk(const Json& jwk);
Json decode(const std::string& token);
Json verify(const std::string& token, const Json& jwk, const std::string& type);
std::string read(const std::filesystem::path& file);
void write(const std::filesystem::path& file, const std::string& text);
void save(const std::filesystem::path& file, const Json& config);
Json load(const std::filesystem::path& file);
class SigningKey {
  NCRYPT_PROV_HANDLE provider_{}; NCRYPT_KEY_HANDLE key_{};
public:
  explicit SigningKey(const std::string& name, bool create=false);
  ~SigningKey();
  SigningKey(const SigningKey&)=delete;
  Json jwk() const;
  std::string sign(const Json& payload) const;
};
Json message(const std::string& type);
class PendingApproval {
  Json request_,pairing_;std::string token_;std::chrono::steady_clock::time_point deadline_;std::atomic<bool> pending_{true};
public:
  PendingApproval(Json request,std::string token,Json pairing,std::chrono::steady_clock::time_point deadline);
  std::string consume(const std::string& response);
  void cancel(){pending_.store(false);}
};
class Http {
  std::wstring host_; INTERNET_PORT port_{}; std::wstring prefix_; std::string pin_; std::string token_;
public:
  Http(const std::string& url, const std::string& pin, const std::string& token);
  Json call(const std::string& method, const std::string& path, const Json* body=nullptr) const;
};
}
