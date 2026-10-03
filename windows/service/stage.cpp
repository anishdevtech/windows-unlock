#include "storage.hpp"
#include <iostream>
int wmain(int argc,wchar_t** argv){
  if(argc!=3||std::wstring(argv[1])!=L"--stage-preview-from-desktop"){std::wcerr<<L"Usage: PhoneUnlockPreviewStage --stage-preview-from-desktop <windows-config.dpapi>\nNo service or Credential Provider is installed.\n";return 1;}
  try{pu::preview::stage(argv[2]);std::cout<<"Preview enrollment staged with machine DPAPI and SYSTEM/Administrators-only storage.\nWindows sign-in is disabled. No service or Credential Provider installed.\n";return 0;}catch(...){std::cerr<<"Staging refused. Requires matching elevated account, paired desktop state, protected storage and no previous enrollment. No secrets printed.\n";return 1;}
}
