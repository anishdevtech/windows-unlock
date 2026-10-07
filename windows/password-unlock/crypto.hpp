#pragma once
#include "core.hpp"
#include "handles.hpp"
#include <bcrypt.h>
namespace pu::vault {
struct Secret {
  Bytes bytes;
  explicit Secret(Bytes b={}):bytes(std::move(b)){}
  ~Secret(){if(!bytes.empty())SecureZeroMemory(bytes.data(),bytes.size());}
  Secret(const Secret&)=delete;Secret& operator=(const Secret&)=delete;
  Secret(Secret&& other)noexcept:bytes(std::move(other.bytes)){}
};
void rsaPublic(const Json&);
Bytes wrap(const Json&,const Bytes&);
class Ephemeral {
  BCRYPT_ALG_HANDLE algorithm_{};BCRYPT_KEY_HANDLE key_{};
public:
  Ephemeral();~Ephemeral();Ephemeral(const Ephemeral&)=delete;
  Json jwk()const;Secret unwrap(const std::string&)const;
};
Json seal(const Bytes& key,const std::wstring& password,const std::string& aad);
Secret open(const Bytes& key,const Json& envelope,const std::string& aad);
Bytes pack(const std::wstring& login,const Bytes& password,DWORD scenario=1);
ULONG negotiatePackage();
Json response(const std::string& token,const Json& key,const Json& request,const std::string& requestJws,bool enroll);
}
