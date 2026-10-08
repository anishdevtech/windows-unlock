#include "storage.hpp"
#include "ipc.hpp"
#include <iostream>
int wmain(int argc,wchar_t** argv){try{
  if(argc==2&&std::wstring(argv[1])==L"--probe"){pu::vault::negotiatePackage();std::cout<<"Built-in Windows authentication is available.\n";return 0;}
  const bool policy=argc==3&&std::wstring(argv[1])==L"--automatic-requests";
  const bool status=argc==2&&std::wstring(argv[1])==L"--status";
  pu::native::require(argc==1||policy||status,"Invalid readiness-check arguments");
  auto c=pu::vault::configuration();auto d=pu::verify(c.at("delegationJws"),c.at("windowsJwk"),"vault-delegation","password-unlock");
  pu::SigningKey key("vault-"+d.at("vaultId").get<std::string>(),false,true);pu::native::require(key.jwk()==d.at("machineJwk"),"Machine key mismatch");pu::vault::negotiatePackage();
  if(policy){
    const std::wstring value=argv[2];pu::native::require(value==L"on"||value==L"off","Use on or off");
    BOOL member{};BYTE sid[SECURITY_MAX_SID_SIZE];DWORD size=sizeof(sid);
    pu::native::require(CreateWellKnownSid(WinBuiltinAdministratorsSid,nullptr,sid,&size)&&CheckTokenMembership(nullptr,sid,&member)&&member,"Administrator required");
    pu::native::require(pu::wide(d.at("windowsAccountSid"))==pu::native::currentSid(),"Use the enrolled Windows account");
    c["automaticRequestsEnabled"]=value==L"on";pu::vault::store(c);
    std::cout<<"Automatic phone requests "<<(value==L"on"?"enabled":"disabled")<<". Normal Windows PIN/Password are unchanged. Restart the owned service to apply.\n";
  }else if(status)std::cout<<"Password vault ready; IPC V"<<pu::native::WireVersion<<"; automatic requests "<<(c.value("automaticRequestsEnabled",false)?"enabled":"disabled")<<". Normal Windows PIN/Password are unchanged.\n";
  else std::cout<<"Password vault and built-in Windows authentication are ready.\n";
  return 0;
}catch(...){std::cerr<<"Password vault is unavailable or invalid. Run local enrollment before installing the tile.\n";return 1;}}
