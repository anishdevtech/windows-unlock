#include "storage.hpp"
#include <shlobj.h>
#include <sddl.h>
#include <aclapi.h>
#include <wincrypt.h>
#include <set>

namespace pu::preview {
using namespace native;
namespace {
struct Local{void* value{};Local()=default;explicit Local(void* p):value(p){};Local(const Local&)=delete;Local(Local&& other)noexcept:value(std::exchange(other.value,nullptr)){};~Local(){if(value)LocalFree(value);}};
bool privilegedSid(PSID sid){Local text;if(!sid||!ConvertSidToStringSidW(sid,reinterpret_cast<LPWSTR*>(&text.value)))return false;auto s=std::wstring(static_cast<wchar_t*>(text.value));return s==L"S-1-5-18"||s==L"S-1-5-32-544";}
void checkAcl(HANDLE handle){
  PSID owner{};PACL dacl{};PSECURITY_DESCRIPTOR descriptor{};
  require(GetSecurityInfo(handle,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,nullptr,&dacl,nullptr,&descriptor)==ERROR_SUCCESS,"Storage ACL unavailable");Local cleanup{descriptor};
  require(privilegedSid(owner)&&dacl,"Untrusted storage ownership or null ACL");
  require(dacl->AceCount>0&&dacl->AceCount<=8,"Invalid storage ACL");
  for(DWORD i=0;i<dacl->AceCount;i++){void* ace{};require(GetAce(dacl,i,&ace)!=FALSE,"Invalid storage ACE");auto header=static_cast<ACE_HEADER*>(ace);require(header->AceType==ACCESS_ALLOWED_ACE_TYPE,"Unexpected storage ACE");auto allowed=static_cast<ACCESS_ALLOWED_ACE*>(ace);require(privilegedSid(&allowed->SidStart),"Storage grants nonprivileged access");}
  FILE_ATTRIBUTE_TAG_INFO info{};require(GetFileInformationByHandleEx(handle,FileAttributeTagInfo,&info,sizeof(info))!=FALSE&&!(info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT),"Reparse storage refused");
}
Handle openProtected(const std::filesystem::path& path,DWORD access){Handle file(CreateFileW(path.c_str(),access|READ_CONTROL,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));require(bool(file),"Protected storage unavailable");checkAcl(file.get());return file;}
Local descriptor(){Local sd;require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",SDDL_REVISION_1,reinterpret_cast<PSECURITY_DESCRIPTOR*>(&sd.value),nullptr)!=FALSE,"Storage protection unavailable");return sd;}
bool isUuid(const Json& value){if(!value.is_string())return false;const auto& s=value.get_ref<const std::string&>();if(s.size()!=36)return false;
  for(size_t i=0;i<s.size();i++){if(i==8||i==13||i==18||i==23){if(s[i]!='-')return false;}else if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return false;}return true;
}
// Preserve ACLs atomically; never follow an operator-created symlink or overwrite enrollment.
void createProtected(const std::filesystem::path& path,const Bytes& bytes){auto sd=descriptor();SECURITY_ATTRIBUTES sa{sizeof(sa),sd.value,FALSE};Handle file(CreateFileW(path.c_str(),GENERIC_WRITE|READ_CONTROL,0,&sa,CREATE_NEW,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));require(bool(file),"Enrollment already exists or write unavailable");checkAcl(file.get());DWORD count{};require(bytes.size()<=65536&&WriteFile(file.get(),bytes.data(),DWORD(bytes.size()),&count,nullptr)&&count==bytes.size()&&FlushFileBuffers(file.get()),"Enrollment commit failed");}
}
std::filesystem::path directory(){PWSTR raw{};require(SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramData,KF_FLAG_DEFAULT,nullptr,&raw)),"ProgramData unavailable");auto result=std::filesystem::path(raw)/L"WINDOWS-UNLOCK-ApprovalPreview";CoTaskMemFree(raw);return result;}
void validateConfiguration(const Json& c){
  std::set<std::string> fields{"mode","windowsSignInEnabled","sid","id","name","accountBindingId","relayUrl","tlsPin","transportToken","pairing","windowsJwk"};
  require(c.is_object()&&c.size()==fields.size(),"Unexpected enrollment fields");for(const auto& item:c.items())require(fields.erase(item.key())==1,"Unexpected enrollment field");
  require(c.size()==11&&c.at("mode")=="approval-preview"&&c.at("windowsSignInEnabled")==false,"Windows sign-in must remain disabled");
  require(validSid(wide(c.at("sid")))&&unb64url(c.at("transportToken")).size()==32,"Invalid account or transport enrollment");
  require(isUuid(c.at("id")),"Invalid key identity");
  require(c.at("name").is_string()&&c.at("name").get<std::string>().size()<=320&&isUuid(c.at("accountBindingId")),"Invalid enrollment binding");
  require(c.at("pairing").is_object(),"Pairing required");publicJwk(c.at("pairing").at("approvalJwk"));publicJwk(c.at("pairing").at("identityJwk"));
  require(c.at("pairing").size()==5&&isUuid(c.at("pairing").at("id"))&&isUuid(c.at("pairing").at("androidDeviceId")),"Invalid pairing binding");
  publicJwk(c.at("windowsJwk"));require(c.at("pairing").at("phoneName").is_string()&&c.at("pairing").at("phoneName").get<std::string>().size()<=320,"Invalid phone name");
  Http(c.at("relayUrl"),c.at("tlsPin"),c.at("transportToken"));
}
Json configuration(){
  auto root=directory();auto parent=openProtected(root,FILE_READ_ATTRIBUTES);auto file=openProtected(root/L"enrollment.dpapi",GENERIC_READ);
  LARGE_INTEGER size{};require(GetFileSizeEx(file.get(),&size)&&size.QuadPart>0&&size.QuadPart<=65536,"Invalid enrollment size");Bytes encrypted(size_t(size.QuadPart));DWORD count{};require(ReadFile(file.get(),encrypted.data(),DWORD(encrypted.size()),&count,nullptr)&&count==encrypted.size(),"Enrollment read failed");
  DATA_BLOB input{DWORD(encrypted.size()),encrypted.data()},plain{};require(CryptUnprotectData(&input,nullptr,nullptr,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&plain)!=FALSE,"Enrollment unavailable");
  try{auto c=parse(std::string(reinterpret_cast<char*>(plain.pbData),plain.cbData));SecureZeroMemory(plain.pbData,plain.cbData);LocalFree(plain.pbData);plain.pbData=nullptr;validateConfiguration(c);return c;}catch(...){if(plain.pbData){SecureZeroMemory(plain.pbData,plain.cbData);LocalFree(plain.pbData);}throw;}
}
void stage(const std::filesystem::path& source){
  BOOL member{};BYTE adminBuffer[SECURITY_MAX_SID_SIZE];DWORD adminSize=sizeof(adminBuffer);require(CreateWellKnownSid(WinBuiltinAdministratorsSid,nullptr,adminBuffer,&adminSize)&&CheckTokenMembership(nullptr,adminBuffer,&member)&&member,"Elevated administrator required to stage preview enrollment");
  const auto c=load(source);SigningKey key(c.at("id")); // Same Windows account as the desktop pairing.
  Json result{{"mode","approval-preview"},{"windowsSignInEnabled",false},{"sid",utf8(currentSid())},{"id",c.at("id")},{"name",c.at("name")},{"accountBindingId",c.at("accountBindingId")},{"relayUrl",c.at("relayUrl")},{"tlsPin",c.at("tlsPin")},{"transportToken",c.at("transportToken")},{"pairing",c.at("pairing")},{"windowsJwk",key.jwk()}};
  validateConfiguration(result);auto root=directory();auto sd=descriptor();SECURITY_ATTRIBUTES sa{sizeof(sa),sd.value,FALSE};
  if(!CreateDirectoryW(root.c_str(),&sa))require(GetLastError()==ERROR_ALREADY_EXISTS,"Preview directory unavailable");auto parent=openProtected(root,FILE_READ_ATTRIBUTES);
  auto text=result.dump();DATA_BLOB input{DWORD(text.size()),reinterpret_cast<BYTE*>(text.data())},encrypted{};require(CryptProtectData(&input,L"WINDOWS-UNLOCK approval preview enrollment",nullptr,nullptr,nullptr,CRYPTPROTECT_LOCAL_MACHINE|CRYPTPROTECT_UI_FORBIDDEN,&encrypted)!=FALSE,"Machine DPAPI unavailable");
  Bytes bytes(encrypted.pbData,encrypted.pbData+encrypted.cbData);LocalFree(encrypted.pbData);SecureZeroMemory(text.data(),text.size());createProtected(root/L"enrollment.dpapi",bytes);
}
}
