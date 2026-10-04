#include "core.hpp"
#include <bcrypt.h>
#include <wincrypt.h>
#include <objbase.h>
#include <fstream>
#include <set>
#include <algorithm>
#include <stdexcept>
namespace pu {
static void check(long result, const char* operation) { if(result != 0) throw std::runtime_error(operation); }
std::wstring wide(const std::string& s) {
  if(s.empty())return {};int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),int(s.size()),nullptr,0);
  if(!n)throw std::runtime_error("Invalid UTF-8");std::wstring w(n,L'\0');MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),int(s.size()),w.data(),n);return w;
}
std::string utf8(const std::wstring& w) {
  if(w.empty())return {};int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,w.data(),int(w.size()),nullptr,0,nullptr,nullptr);
  if(!n)throw std::runtime_error("Invalid Unicode");std::string s(n,'\0');WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,w.data(),int(w.size()),s.data(),n,nullptr,nullptr);return s;
}
std::string uuid(){GUID g{};if(FAILED(CoCreateGuid(&g)))throw std::runtime_error("Random ID failed");wchar_t out[40]{};StringFromGUID2(g,out,40);auto s=utf8(std::wstring(out+1,36));std::transform(s.begin(),s.end(),s.begin(),[](char c){return char(tolower(c));});return s;}
int64_t epoch(){return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();}
Bytes random(size_t n){Bytes b(n);check(BCryptGenRandom(nullptr,b.data(),ULONG(n),BCRYPT_USE_SYSTEM_PREFERRED_RNG),"Secure random failed");return b;}
static std::string base64(const Bytes& b){DWORD n=0;if(!CryptBinaryToStringA(b.data(),DWORD(b.size()),CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,nullptr,&n))throw std::runtime_error("Encoding failed");std::string s(n,'\0');CryptBinaryToStringA(b.data(),DWORD(b.size()),CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,s.data(),&n);s.resize(n);while(!s.empty()&&s.back()=='\0')s.pop_back();return s;}
std::string b64url(const Bytes& b){auto s=base64(b);std::replace(s.begin(),s.end(),'+','-');std::replace(s.begin(),s.end(),'/','_');while(!s.empty()&&s.back()=='=')s.pop_back();return s;}
Bytes unb64url(const std::string& text){if(text.empty()||text.size()>65536||text.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")!=std::string::npos)throw std::runtime_error("Invalid base64url");auto s=text;std::replace(s.begin(),s.end(),'-','+');std::replace(s.begin(),s.end(),'_','/');while(s.size()%4)s+='=';DWORD n=0;if(!CryptStringToBinaryA(s.data(),DWORD(s.size()),CRYPT_STRING_BASE64,nullptr,&n,nullptr,nullptr))throw std::runtime_error("Invalid base64url");Bytes b(n);CryptStringToBinaryA(s.data(),DWORD(s.size()),CRYPT_STRING_BASE64,b.data(),&n,nullptr,nullptr);if(b64url(b)!=text)throw std::runtime_error("Noncanonical base64url");return b;}
Bytes sha256(const std::string& s){BCRYPT_ALG_HANDLE alg{};check(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0),"Hash unavailable");Bytes out(32);auto result=BCryptHash(alg,nullptr,0,reinterpret_cast<PUCHAR>(const_cast<char*>(s.data())),ULONG(s.size()),out.data(),32);BCryptCloseAlgorithmProvider(alg,0);check(result,"Hash failed");return out;}
std::string hash(const std::string& s){auto b=sha256(s);static const char* hex="0123456789abcdef";std::string out;for(auto v:b){out+=hex[v>>4];out+=hex[v&15];}return out;}
std::string tlsPin(const Bytes& spki){return "sha256/"+base64(sha256(std::string(reinterpret_cast<const char*>(spki.data()),spki.size())));}
Json parse(const std::string& s){if(s.size()>65536)throw std::runtime_error("Message too large");std::vector<std::set<std::string>> objects;
  auto callback=[&](int depth,Json::parse_event_t event,Json& value){if(depth>16)throw std::runtime_error("JSON too deep");if(event==Json::parse_event_t::object_start)objects.emplace_back();if(event==Json::parse_event_t::key && !objects.back().insert(value.get<std::string>()).second)throw std::runtime_error("Duplicate JSON key");if(event==Json::parse_event_t::object_end)objects.pop_back();return true;};
  auto j=Json::parse(s,callback);if(!j.is_object())throw std::runtime_error("JSON object required");return j;
}
Json publicJwk(const Json& j){if(!j.is_object()||j.size()!=4||j.value("kty","")!="EC"||j.value("crv","")!="P-256"||!j.contains("x")||!j.contains("y")||unb64url(j.at("x").get<std::string>()).size()!=32||unb64url(j.at("y").get<std::string>()).size()!=32)throw std::runtime_error("Invalid public key");return j;}
static std::vector<std::string> parts(const std::string& token){if(token.size()>65536)throw std::runtime_error("Message too large");auto a=token.find('.'),b=token.find('.',a==std::string::npos?token.size():a+1);if(a==std::string::npos||b==std::string::npos||token.find('.',b+1)!=std::string::npos)throw std::runtime_error("Invalid JWS");return {token.substr(0,a),token.substr(a+1,b-a-1),token.substr(b+1)};}
Json decode(const std::string& token){auto p=parts(token);auto h=unb64url(p[0]),v=unb64url(p[1]);auto head=parse(std::string(h.begin(),h.end()));if(head!=Json{{"alg","ES256"},{"typ","phoneunlock+jws"}}||unb64url(p[2]).size()!=64)throw std::runtime_error("Invalid JWS header/signature");return parse(std::string(v.begin(),v.end()));}
Json verify(const std::string& token,const Json& pub,const std::string& type,const std::string& purpose){auto payload=decode(token);publicJwk(pub);auto p=parts(token);auto x=unb64url(pub.at("x")),y=unb64url(pub.at("y"));Bytes blob(sizeof(BCRYPT_ECCKEY_BLOB)+64);auto header=reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(blob.data());header->dwMagic=BCRYPT_ECDSA_PUBLIC_P256_MAGIC;header->cbKey=32;std::copy(x.begin(),x.end(),blob.begin()+sizeof(*header));std::copy(y.begin(),y.end(),blob.begin()+sizeof(*header)+32);
  BCRYPT_ALG_HANDLE alg{};BCRYPT_KEY_HANDLE key{};check(BCryptOpenAlgorithmProvider(&alg,BCRYPT_ECDSA_P256_ALGORITHM,nullptr,0),"ECDSA unavailable");auto status=BCryptImportKeyPair(alg,nullptr,BCRYPT_ECCPUBLIC_BLOB,&key,blob.data(),ULONG(blob.size()),0);if(status!=0){BCryptCloseAlgorithmProvider(alg,0);check(status,"Key import failed");}
  auto digest=sha256(p[0]+"."+p[1]),signature=unb64url(p[2]);status=BCryptVerifySignature(key,nullptr,digest.data(),32,signature.data(),ULONG(signature.size()),0);BCryptDestroyKey(key);BCryptCloseAlgorithmProvider(alg,0);check(status,"Invalid signature");
  if((purpose!="desktop-approval"&&purpose!="windows-unlock")||payload.value("v",0)!=1||payload.value("purpose","")!=purpose||payload.value("type","")!=type)throw std::runtime_error("Invalid protocol purpose");return payload;
}
SigningKey::SigningKey(const std::string& name,bool create){check(NCryptOpenStorageProvider(&provider_,MS_KEY_STORAGE_PROVIDER,0),"Key provider unavailable");auto w=wide("WINDOWS-UNLOCK-"+name);auto status=NCryptOpenKey(provider_,&key_,w.c_str(),0,0);if(status!=0&&create){status=NCryptCreatePersistedKey(provider_,&key_,NCRYPT_ECDSA_P256_ALGORITHM,w.c_str(),0,0);if(status==0)status=NCryptFinalizeKey(key_,0);}if(status!=0){NCryptFreeObject(provider_);provider_=0;check(status,"Device key unavailable; pair again");}}
SigningKey::~SigningKey(){if(key_)NCryptFreeObject(key_);if(provider_)NCryptFreeObject(provider_);}
Json SigningKey::jwk()const{DWORD n=0;check(NCryptExportKey(key_,0,BCRYPT_ECCPUBLIC_BLOB,nullptr,nullptr,0,&n,0),"Public key export failed");Bytes b(n);check(NCryptExportKey(key_,0,BCRYPT_ECCPUBLIC_BLOB,nullptr,b.data(),n,&n,0),"Public key export failed");if(n!=sizeof(BCRYPT_ECCKEY_BLOB)+64)throw std::runtime_error("Unexpected public key");auto start=b.begin()+sizeof(BCRYPT_ECCKEY_BLOB);return {{"kty","EC"},{"crv","P-256"},{"x",b64url(Bytes(start,start+32))},{"y",b64url(Bytes(start+32,start+64))}};}
std::string SigningKey::sign(const Json& payload)const{auto hs=Json{{"alg","ES256"},{"typ","phoneunlock+jws"}}.dump(),ps=payload.dump();auto input=b64url(Bytes(hs.begin(),hs.end()))+"."+b64url(Bytes(ps.begin(),ps.end()));auto digest=sha256(input);DWORD n=0;check(NCryptSignHash(key_,nullptr,digest.data(),32,nullptr,0,&n,0),"Signing failed");Bytes signature(n);check(NCryptSignHash(key_,nullptr,digest.data(),32,signature.data(),n,&n,0),"Signing failed");if(n!=64)throw std::runtime_error("Unexpected signature format");return input+"."+b64url(signature);}
Json message(const std::string& type,const std::string& purpose){return {{"v",1},{"type",type},{"purpose",purpose}};}
PendingApproval::PendingApproval(Json request,std::string token,Json pairing,std::chrono::steady_clock::time_point deadline):request_(std::move(request)),pairing_(std::move(pairing)),token_(std::move(token)),deadline_(deadline){}
std::string PendingApproval::consume(const std::string& response){
  auto available=[&]{return pending_.load()&&std::chrono::steady_clock::now()<deadline_&&epoch()<request_.at("expiresAt").get<int64_t>();};
  if(!available())throw std::runtime_error("Request expired or processed");const auto raw=decode(response);const auto decision=raw.at("decision").get<std::string>();if(decision!="approve"&&decision!="deny")throw std::runtime_error("Invalid decision");
  auto p=verify(response,pairing_.at(decision=="approve"?"approvalJwk":"identityJwk"),"auth-response",request_.at("purpose"));
  if(p.size()!=9||p.at("requestId")!=request_.at("requestId")||p.at("pairingId")!=request_.at("pairingId")||p.at("windowsDeviceId")!=request_.at("windowsDeviceId")||p.at("androidDeviceId")!=request_.at("androidDeviceId")||p.at("challengeHash")!=hash(token_))throw std::runtime_error("Response binding mismatch");
  bool expected=true;if(!available()||!pending_.compare_exchange_strong(expected,false))throw std::runtime_error("Request expired or processed");
  // Recheck after reservation in case the thread was descheduled before the CAS.
  if(std::chrono::steady_clock::now()>=deadline_||epoch()>=request_.at("expiresAt").get<int64_t>())throw std::runtime_error("Request expired");return decision;
}
std::string read(const std::filesystem::path& file){std::ifstream in(file,std::ios::binary);if(!in)throw std::runtime_error("File unavailable");std::string s((std::istreambuf_iterator<char>(in)),{});if(s.size()>65536)throw std::runtime_error("File too large");return s;}
void write(const std::filesystem::path& file,const std::string& text){std::ofstream out(file,std::ios::binary|std::ios::trunc);if(!out||!out.write(text.data(),std::streamsize(text.size())))throw std::runtime_error("File write failed");}
void save(const std::filesystem::path& file,const Json& config){auto s=config.dump();DATA_BLOB input{DWORD(s.size()),reinterpret_cast<BYTE*>(s.data())},encrypted{};if(!CryptProtectData(&input,L"WINDOWS-UNLOCK configuration",nullptr,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&encrypted))throw std::runtime_error("DPAPI protection failed");auto tmp=file;tmp+=L".tmp";try{write(tmp,std::string(reinterpret_cast<char*>(encrypted.pbData),encrypted.cbData));LocalFree(encrypted.pbData);}catch(...){LocalFree(encrypted.pbData);throw;}if(!MoveFileExW(tmp.c_str(),file.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH))throw std::runtime_error("Configuration commit failed");SecureZeroMemory(s.data(),s.size());}
Json load(const std::filesystem::path& file){auto s=read(file);DATA_BLOB input{DWORD(s.size()),reinterpret_cast<BYTE*>(s.data())},output{};if(!CryptUnprotectData(&input,nullptr,nullptr,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&output))throw std::runtime_error("Configuration cannot be decrypted");try{auto j=parse(std::string(reinterpret_cast<char*>(output.pbData),output.cbData));SecureZeroMemory(output.pbData,output.cbData);LocalFree(output.pbData);return j;}catch(...){SecureZeroMemory(output.pbData,output.cbData);LocalFree(output.pbData);throw;}}
}
