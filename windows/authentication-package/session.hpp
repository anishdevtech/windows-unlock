#pragma once
#include "authority.hpp"
#include "ipc.hpp"
#define SECURITY_WIN32
#include <ntsecapi.h>
#include <sspi.h>
#include <ntsecpkg.h>
namespace pu::auth {
struct Session {native::Handle token;Context context;std::wstring account,domain;};
std::string luidText(LUID id);
Session session(uint32_t id,const std::string& sid,uint32_t scenario);
// Produces LSA token information from the existing OS-authenticated session.
// Does not create/duplicate/impersonate a kernel token or authenticate callers.
PLSA_TOKEN_INFORMATION_V2 tokenInformation(HANDLE token,PLSA_ALLOCATE_LSA_HEAP allocate);
}
