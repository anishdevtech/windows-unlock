#include "storage.hpp"
#include <iostream>
#ifdef PU_WINDOWS_UNLOCK
#include "client.hpp"
#endif
int wmain(int argc,wchar_t** argv){
#ifdef PU_WINDOWS_UNLOCK
  if(argc==2&&std::wstring(argv[1])==L"--check-auth-package"){try{pu::auth::packageId();std::cout<<"WINDOWS-UNLOCK authentication package is loaded. This lookup does not validate unlock compatibility or authenticate.\n";return 0;}catch(...){std::cerr<<"WINDOWS-UNLOCK package unavailable. Keep using Windows PIN; inspect Code Integrity and LSA startup events.\n";return 1;}}
  if(argc!=3||std::wstring(argv[1])!=L"--stage-unlock-from-desktop"){std::wcerr<<L"Usage: PhoneUnlockStage --stage-unlock-from-desktop <windows-config.dpapi>\nRun only during reviewed setup. No components are installed by staging.\n";return 1;}
  try{pu::preview::stage(argv[2]);std::cout<<"Unlock enrollment staged. LSA public trust and encrypted broker config use SYSTEM/Administrators-only storage. No components installed.\n";return 0;}catch(...){std::cerr<<"Unlock enrollment refused. Check paired identity, matching elevated account and protected storage; clean partial staging before retrying.\n";return 1;}
#else
  if(argc!=3||std::wstring(argv[1])!=L"--stage-preview-from-desktop"){std::wcerr<<L"Usage: PhoneUnlockPreviewStage --stage-preview-from-desktop <windows-config.dpapi>\nNo service or Credential Provider is installed.\n";return 1;}
  try{pu::preview::stage(argv[2]);std::cout<<"Preview enrollment staged with machine DPAPI and SYSTEM/Administrators-only storage.\nWindows sign-in is disabled. No service or Credential Provider installed.\n";return 0;}catch(...){std::cerr<<"Staging refused. Requires matching elevated account, paired desktop state, protected storage and no previous enrollment. No secrets printed.\n";return 1;}
#endif
}
