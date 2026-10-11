#pragma once
#include "core.hpp"
namespace pu {
// Cosmetic signal only. It is never consumed as a Windows credential.
Json verifiedUnlockReceipt(const Json& bundle,const Json& config,const std::string& sid,DWORD session,int64_t now);
}
