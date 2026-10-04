#include "session.hpp"
#include <wtsapi32.h>
#include <lm.h>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <limits>
namespace pu::auth {
using namespace native;
namespace {
Bytes info(HANDLE token,TOKEN_INFORMATION_CLASS kind){DWORD size{};GetTokenInformation(token,kind,nullptr,0,&size);require(size&&size<=65536,"Invalid token metadata");Bytes b(size);require(GetTokenInformation(token,kind,b.data(),size,&size)!=FALSE,"Token metadata unavailable");return b;}
void policy(const std::wstring& account){
  LPBYTE raw{};require(NetUserGetInfo(nullptr,account.c_str(),3,&raw)==NERR_Success,"Local account policy unavailable");struct Free{LPBYTE p;~Free(){NetApiBufferFree(p);}} free{raw};auto u=reinterpret_cast<USER_INFO_3*>(raw);
  require(!(u->usri3_flags&(UF_ACCOUNTDISABLE|UF_LOCKOUT|UF_PASSWORD_EXPIRED))&&(u->usri3_flags&UF_NORMAL_ACCOUNT),"Account disabled, locked or password expired");
  require(u->usri3_acct_expires==TIMEQ_FOREVER||uint64_t(u->usri3_acct_expires)>uint64_t(epoch()),"Account expired");
  if(u->usri3_logon_hours){require(u->usri3_units_per_week==168,"Unsupported account hours");const auto time=std::time(nullptr);std::tm utc{};require(gmtime_s(&utc,&time)==0,"Clock unavailable");const auto hour=utc.tm_wday*24+utc.tm_hour;require(u->usri3_logon_hours[hour/8]&(1<<(hour%8)),"Account logon hours restriction");}
  if(u->usri3_workstations&&*u->usri3_workstations){wchar_t name[MAX_COMPUTERNAME_LENGTH+1]{};DWORD count=MAX_COMPUTERNAME_LENGTH+1;require(GetComputerNameW(name,&count)!=FALSE,"Computer name unavailable");std::wistringstream list(u->usri3_workstations);std::wstring entry;bool allowed=false;while(std::getline(list,entry,L','))if(_wcsicmp(entry.c_str(),name)==0)allowed=true;require(allowed,"Account workstation restriction");}
}
}
std::string luidText(LUID l){std::ostringstream s;s<<std::hex<<std::setfill('0')<<std::setw(8)<<uint32_t(l.HighPart)<<std::setw(8)<<l.LowPart;return s.str();}
Session session(uint32_t id,const std::string& sid,uint32_t scenario){
  require(id==WTSGetActiveConsoleSessionId()&&(scenario==1||scenario==2),"Local console unlock only");LPWSTR raw{};DWORD size{};
  require(WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,id,WTSSessionInfoEx,&raw,&size)!=FALSE,"Session state unavailable");bool locked=false;if(size>=sizeof(WTSINFOEXW)){auto v=reinterpret_cast<WTSINFOEXW*>(raw);locked=v->Level==1&&v->Data.WTSInfoExLevel1.SessionId==id&&v->Data.WTSInfoExLevel1.SessionFlags==WTS_SESSIONSTATE_LOCK;}WTSFreeMemory(raw);require(locked,"Existing locked session required");
  HANDLE handle{};require(WTSQueryUserToken(id,&handle)!=FALSE,"Existing session token unavailable");Session s;s.token=Handle(handle);require(tokenSid(handle)==wide(sid)&&!IsTokenRestricted(handle),"Account/token mismatch");
  auto stats=info(handle,TokenStatistics);auto v=reinterpret_cast<TOKEN_STATISTICS*>(stats.data());require(v->TokenType==TokenPrimary,"Primary session required");s.context={sid,luidText(v->AuthenticationId),id,scenario,0};
  auto user=info(handle,TokenUser);wchar_t name[256]{},domain[256]{};DWORD nc=256,dc=256;SID_NAME_USE use{};require(LookupAccountSidW(nullptr,reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid,name,&nc,domain,&dc,&use)&&use==SidTypeUser,"Account resolution unavailable");
  wchar_t computer[MAX_COMPUTERNAME_LENGTH+1]{};DWORD cc=MAX_COMPUTERNAME_LENGTH+1;require(GetComputerNameW(computer,&cc)&&_wcsicmp(domain,computer)==0,"Only existing local SAM-backed account sessions supported");
  s.account=name;s.domain=domain;policy(s.account);return s;
}
PLSA_TOKEN_INFORMATION_V2 tokenInformation(HANDLE token,PLSA_ALLOCATE_LSA_HEAP allocate){
  require(allocate!=nullptr,"LSA allocator unavailable");auto user=info(token,TokenUser),primary=info(token,TokenPrimaryGroup),groups=info(token,TokenGroups),dacl=info(token,TokenDefaultDacl);
  auto u=reinterpret_cast<TOKEN_USER*>(user.data());auto p=reinterpret_cast<TOKEN_PRIMARY_GROUP*>(primary.data());auto g=reinterpret_cast<TOKEN_GROUPS*>(groups.data());auto d=reinterpret_cast<TOKEN_DEFAULT_DACL*>(dacl.data());
  require(IsValidSid(u->User.Sid)&&IsValidSid(p->PrimaryGroup)&&g->GroupCount<=256&&d->DefaultDacl&&IsValidAcl(d->DefaultDacl),"Invalid source token");
  std::vector<SID_AND_ATTRIBUTES> kept;for(DWORD i=0;i<g->GroupCount;i++){auto v=g->Groups[i];require(IsValidSid(v.Sid),"Invalid group SID");if(v.Attributes&(SE_GROUP_LOGON_ID|SE_GROUP_INTEGRITY))continue;if(IsWellKnownSid(v.Sid,WinWorldSid)||IsWellKnownSid(v.Sid,WinLocalSid)||IsWellKnownSid(v.Sid,WinInteractiveSid)||IsWellKnownSid(v.Sid,WinAuthenticatedUserSid))continue;kept.push_back(v);}
  // One LSA-owned allocation; all pointers are internal. No null/default everyone DACL.
  auto aligned=[](size_t n){return (n+7)&~size_t(7);};size_t bytes=aligned(sizeof(LSA_TOKEN_INFORMATION_V2))+aligned(sizeof(TOKEN_GROUPS)+kept.size()*sizeof(SID_AND_ATTRIBUTES))+aligned(GetLengthSid(u->User.Sid))+aligned(GetLengthSid(p->PrimaryGroup))+aligned(d->DefaultDacl->AclSize);
  for(const auto& v:kept)bytes+=aligned(GetLengthSid(v.Sid));require(bytes<=65536,"Token metadata too large");auto root=static_cast<BYTE*>(allocate(ULONG(bytes)));require(root!=nullptr,"LSA allocation failed");ZeroMemory(root,bytes);size_t offset=aligned(sizeof(LSA_TOKEN_INFORMATION_V2));
  auto take=[&](size_t n){auto out=root+offset;offset+=aligned(n);return out;};auto out=reinterpret_cast<PLSA_TOKEN_INFORMATION_V2>(root);out->ExpirationTime.QuadPart=std::numeric_limits<LONGLONG>::max();out->Groups=reinterpret_cast<PTOKEN_GROUPS>(take(sizeof(TOKEN_GROUPS)+kept.size()*sizeof(SID_AND_ATTRIBUTES)));out->Groups->GroupCount=DWORD(kept.size());
  auto copySid=[&](PSID sid){DWORD n=GetLengthSid(sid);auto result=take(n);CopyMemory(result,sid,n);return PSID(result);};out->User.User.Sid=copySid(u->User.Sid);out->User.User.Attributes=u->User.Attributes;out->PrimaryGroup.PrimaryGroup=copySid(p->PrimaryGroup);out->Owner.Owner=out->User.User.Sid;
  out->DefaultDacl.DefaultDacl=reinterpret_cast<PACL>(take(d->DefaultDacl->AclSize));CopyMemory(out->DefaultDacl.DefaultDacl,d->DefaultDacl,d->DefaultDacl->AclSize);
  for(size_t i=0;i<kept.size();i++)out->Groups->Groups[i]={copySid(kept[i].Sid),kept[i].Attributes};out->Privileges=nullptr;return out; // local policy supplies privileges; never invent groups/privileges
}
}
