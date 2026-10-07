#pragma once
#include "handles.hpp"
#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <stop_token>

namespace pu::native {
#if defined(PU_PASSWORD_UNLOCK)
inline constexpr wchar_t ServiceName[]=L"WindowsUnlockPasswordService";
inline constexpr wchar_t PipeName[]=L"\\\\.\\pipe\\WINDOWS-UNLOCK-Password-v3";
inline constexpr GUID ProviderId={0x59d7e749,0xf07a,0x4549,{0x97,0x56,0xe8,0x7c,0x03,0x55,0xb5,0x32}};
inline constexpr uint32_t WireVersion=3;
inline constexpr size_t ProofCapacity=8192;
#elif defined(PU_WINDOWS_UNLOCK)
inline constexpr wchar_t ServiceName[]=L"WindowsUnlockService";
inline constexpr wchar_t PipeName[]=L"\\\\.\\pipe\\WINDOWS-UNLOCK-SignIn-v2";
inline constexpr GUID ProviderId={0x45bec8e2,0x1359,0x48d6,{0x95,0x87,0x96,0x3f,0xb9,0x3d,0x60,0x71}};
inline constexpr uint32_t WireVersion=2;
inline constexpr size_t ProofCapacity=8192;
#else
inline constexpr wchar_t ServiceName[]=L"WindowsUnlockPreviewService";
inline constexpr wchar_t PipeName[]=L"\\\\.\\pipe\\WINDOWS-UNLOCK-ApprovalPreview-v1";
inline constexpr GUID ProviderId={0x8ee2412c,0x28c7,0x4f11,{0xa7,0xcd,0x2a,0x99,0xf9,0x5c,0x8c,0x11}};
inline constexpr uint32_t WireVersion=1;
#endif
inline constexpr uint32_t WireMagic=0x50555731;
enum class Operation:uint32_t { Describe=1,Begin=2,Poll=3,Cancel=4,Claim=5 };
enum class State:uint32_t { Unavailable=0,Ready=1,Waiting=2,PushUnavailable=3,ApprovedPreview=4,Denied=5,Expired=6,Cancelled=7,NotConfigured=8,ApprovedSignIn=9 };
// Fixed UTF-16 frames. V3 returns packed credentials only for a one-time Claim.
struct Request {
  uint32_t magic{WireMagic},version{WireVersion};Operation operation{Operation::Describe};
  uint32_t scenario{},sessionId{};GUID operationId{};std::array<wchar_t,184> sid{};
};
struct Response {
  uint32_t magic{WireMagic},version{WireVersion};State state{State::Unavailable};
  uint32_t windowsSignInEnabled{};GUID operationId{};std::array<wchar_t,184> sid{};std::array<wchar_t,81> phoneName{};
  uint16_t reserved{}; // Explicitly initialized tail, never transmit compiler padding.
#if defined(PU_WINDOWS_UNLOCK) || defined(PU_PASSWORD_UNLOCK)
  uint32_t proofSize{};std::array<char,ProofCapacity> proof{};
#endif
#ifdef PU_PASSWORD_UNLOCK
  ~Response(){SecureZeroMemory(proof.data(),proof.size());}
#endif
};
static_assert(sizeof(wchar_t)==2&&sizeof(Request)==404);
#if defined(PU_WINDOWS_UNLOCK) || defined(PU_PASSWORD_UNLOCK)
static_assert(sizeof(Response)==8760);
#else
static_assert(sizeof(Response)==564);
#endif
struct Caller {DWORD processId{},sessionId{};};
bool valid(const Request& request);
bool valid(const Response& response,const Request& request);
bool validSid(const std::wstring& sid);
std::wstring tokenSid(HANDLE token);
std::wstring currentSid();
bool systemProcess(DWORD processId,const wchar_t* expectedImage=nullptr);
bool serviceProcess(DWORD processId);
std::wstring statusText(State state);
using Authorize=std::function<bool(HANDLE,Caller&)>;
using Dispatch=std::function<Response(const Request&,const Caller&)>;
// Production authorization is fixed; test authorization is only in the standalone harness.
bool authorizeLogonUi(HANDLE pipe,Caller& caller);
void serve(const std::wstring& pipeName,const std::wstring& sddl,HANDLE stop,
           const Authorize& authorize,const Dispatch& dispatch,const std::function<void()>& ready={});
Response call(const Request& request,std::stop_token stop={});
namespace testing {
Response call(const std::wstring& pipeName,DWORD expectedServer,const Request& request,std::stop_token stop={});
}
}
