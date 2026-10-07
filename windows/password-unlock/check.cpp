#include "storage.hpp"
#include "ipc.hpp"
#include <iostream>
int wmain(int argc,wchar_t** argv){try{
  if(argc==2&&std::wstring(argv[1])==L"--probe"){pu::vault::negotiatePackage();std::cout<<"Built-in Windows authentication is available.\n";return 0;}
  pu::native::require(argc==1,"Invalid readiness-check arguments");auto c=pu::vault::configuration();auto d=pu::verify(c.at("delegationJws"),c.at("windowsJwk"),"vault-delegation","password-unlock");pu::SigningKey key("vault-"+d.at("vaultId").get<std::string>(),false,true);pu::native::require(key.jwk()==d.at("machineJwk"),"Machine key mismatch");pu::vault::negotiatePackage();std::cout<<"Password vault and built-in Windows authentication are ready.\n";return 0;
}catch(...){std::cerr<<"Password vault is unavailable or invalid. Run local enrollment before installing the tile.\n";return 1;}}
