#include "storage.hpp"
#include "ipc.hpp"
#include <wincred.h>
#define SECURITY_WIN32
#include <security.h>
#include <shellapi.h>
#include <sddl.h>
#include <lm.h>
#include <thread>
using namespace pu;using namespace pu::native;
namespace {
struct Inputs {std::array<wchar_t,257> user{},password{};~Inputs(){SecureZeroMemory(password.data(),sizeof(password));}};
void enroll(const std::filesystem::path& path){
  BOOL member{};BYTE sid[SECURITY_MAX_SID_SIZE];DWORD sidSize=sizeof(sid);require(CreateWellKnownSid(WinBuiltinAdministratorsSid,nullptr,sid,&sidSize)&&CheckTokenMembership(nullptr,sid,&member)&&member,"Run setup as administrator using your Windows account");
  auto c=load(path);SigningKey root(c.at("id"));auto pair=c.at("pairing");publicJwk(pair.at("approvalJwk"));publicJwk(pair.at("identityJwk"));
  Inputs inputs;ULONG nameSize=ULONG(inputs.user.size());GetUserNameExW(NameSamCompatible,inputs.user.data(),&nameSize);
  std::wstring onlineLogin;{std::wstring sam(inputs.user.data());const auto slash=sam.find(L'\\');const auto local=sam.substr(slash==std::wstring::npos?0:slash+1);LPBYTE rawInfo{};
    if(NetUserGetInfo(nullptr,local.c_str(),24,&rawInfo)==NERR_Success){auto info=reinterpret_cast<USER_INFO_24*>(rawInfo);if(info->usri24_internet_identity&&info->usri24_internet_provider_name&&info->usri24_internet_principal_name&&_wcsicmp(info->usri24_internet_provider_name,L"MicrosoftAccount")==0){onlineLogin=L"MicrosoftAccount\\"+std::wstring(info->usri24_internet_principal_name);if(onlineLogin.size()<inputs.user.size())wcscpy_s(inputs.user.data(),inputs.user.size(),onlineLogin.c_str());}NetApiBufferFree(rawInfo);}}
  CREDUI_INFOW ui{sizeof(ui)};ui.pszCaptionText=L"WINDOWS-UNLOCK — encrypted password setup";ui.pszMessageText=L"Enter your Windows PASSWORD, not your PIN. For a Microsoft account, use MicrosoftAccount\\you@example.com. The password stays on this laptop, encrypted; your phone controls decryption.";BOOL save=FALSE;
  const auto result=CredUIPromptForCredentialsW(&ui,L"WINDOWS-UNLOCK local password vault",nullptr,0,inputs.user.data(),DWORD(inputs.user.size()),inputs.password.data(),DWORD(inputs.password.size()),&save,CREDUI_FLAGS_GENERIC_CREDENTIALS|CREDUI_FLAGS_DO_NOT_PERSIST|CREDUI_FLAGS_ALWAYS_SHOW_UI|CREDUI_FLAGS_EXCLUDE_CERTIFICATES);
  require(result==NO_ERROR,"Setup cancelled");std::wstring username(inputs.user.data()),domain,user;auto split=username.find(L'\\');if(split==std::wstring::npos){require(username.find(L'@')!=std::wstring::npos,"Use a qualified Windows account name");domain=L"MicrosoftAccount";user=username;username=domain+L"\\"+user;}else{domain=username.substr(0,split);user=username.substr(split+1);}
  HANDLE raw{};require(LogonUserW(user.c_str(),domain.c_str(),inputs.password.data(),LOGON32_LOGON_INTERACTIVE,LOGON32_PROVIDER_DEFAULT,&raw),"Windows rejected the password. Verify normal Password sign-in first; PIN cannot enroll this vault.");Handle account(raw);require(tokenSid(account.get())==currentSid(),"Enroll the same Windows account that paired this laptop");
  if(!onlineLogin.empty())username=onlineLogin;else if(_wcsicmp(domain.c_str(),L"MicrosoftAccount")==0)username=L"MicrosoftAccount\\"+user;
  const auto id=uuid();SigningKey machine("vault-"+id,true,true);bool committed=false;struct Cleanup{SigningKey& key;bool& committed;~Cleanup(){if(!committed)try{key.erase();}catch(...){}}} cleanup{machine,committed};auto delegation=message("vault-delegation","password-unlock");delegation.update(Json{{"vaultId",id},{"windowsDeviceId",c.at("id")},{"androidDeviceId",pair.at("androidDeviceId")},{"pairingId",pair.at("id")},{"accountBindingId",c.at("accountBindingId")},{"windowsAccountSid",utf8(currentSid())},{"loginName",utf8(username)},{"machineJwk",machine.jwk()}});const auto delegationJws=root.sign(delegation);
  vault::Secret key(random(32));std::wstring password(inputs.password.data());struct Wipe{std::wstring& value;~Wipe(){SecureZeroMemory(value.data(),value.size()*2);}} wipe{password};auto envelope=vault::seal(key.bytes,password,hash(delegationJws));SecureZeroMemory(password.data(),password.size()*2);SecureZeroMemory(inputs.password.data(),sizeof(inputs.password));
  auto request=message("vault-enroll","password-unlock");const auto requestId=uuid();const auto issuedAt=epoch();request.update(Json{{"requestId",requestId},{"nonce",b64url(random(32))},{"issuedAt",issuedAt},{"expiresAt",issuedAt+300},{"delegationJws",delegationJws}});const auto token=root.sign(request);Http relay(c.at("relayUrl"),c.at("tlsPin"),c.at("transportToken"));Json body{{"requestJws",token}};relay.call("POST","/v1/vault-requests",&body);
  MessageBoxW(nullptr,L"Open WINDOWS-UNLOCK on your paired phone. Review Enable phone sign-in and approve with your biometrics. Click OK here to wait for the response. This request expires in five minutes.",L"Approve on your phone",MB_OK|MB_ICONINFORMATION);
  const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(300);
  while(epoch()<request.at("expiresAt").get<int64_t>()&&std::chrono::steady_clock::now()<deadline){auto state=relay.call("GET","/v1/vault-requests/"+requestId);
    if(state.contains("responseJws")&&state.at("responseJws").is_string()){
      auto decoded=decode(state.at("responseJws"));auto response=vault::response(state.at("responseJws"),pair.at(decoded.at("decision")=="approve"?"approvalJwk":"identityJwk"),request,token,true);require(response.at("decision")=="approve","Phone declined setup");
      Json config{{"v",1},{"delegationJws",delegationJws},{"windowsJwk",root.jwk()},{"phoneJwk",response.at("phoneJwk")},{"phoneIdentityJwk",pair.at("identityJwk")},{"wrappedKey",b64url(vault::wrap(response.at("phoneJwk"),key.bytes))},{"envelope",envelope},{"relayUrl",c.at("relayUrl")},{"tlsPin",c.at("tlsPin")},{"transportToken",c.at("transportToken")},{"serverDiagnosticsEnabled",c.value("serverDiagnosticsEnabled",true)}};vault::store(config);committed=true;return;
    }
    if(state.at("state")=="expired"||state.at("state")=="denied"||state.at("state")=="cancelled")break;std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }throw std::runtime_error("Phone setup expired. Use Windows PIN; rerun setup when ready.");
}
}
int WINAPI wWinMain(HINSTANCE,HINSTANCE,PWSTR,int){int argc{};auto argv=CommandLineToArgvW(GetCommandLineW(),&argc);if(!argv)return ERROR_INVALID_PARAMETER;std::filesystem::path config;if(argc==3&&std::wstring(argv[1])==L"--config")config=argv[2];LocalFree(argv);try{require(!config.empty(),"Launch with --config and the paired desktop config.dpapi path");enroll(config);MessageBoxW(nullptr,L"Phone-controlled password vault enrolled. Install the password Credential Provider and service next. Windows PIN and Password remain available.",L"WINDOWS-UNLOCK setup complete",MB_OK|MB_ICONINFORMATION);return 0;}catch(const std::exception& e){MessageBoxW(nullptr,wide(e.what()).c_str(),L"WINDOWS-UNLOCK setup did not complete",MB_OK|MB_ICONWARNING);return 1;}}
