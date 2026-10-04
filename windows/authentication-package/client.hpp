#pragma once
#include "authority.hpp"
namespace pu::auth {
class Client {
  HANDLE handle_{};ULONG package_{};
public:
  Client();~Client();Client(const Client&)=delete;
  Json call(const Json& request);
};
ULONG packageId(); // lookup only, used by Credential Provider serialization
}
