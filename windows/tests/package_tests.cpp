#include "session.hpp"
#include <filesystem>
#include <iostream>
using pu::native::require;
namespace {
PVOID NTAPI heap(ULONG n){return HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,n);}
VOID NTAPI release(PVOID p){HeapFree(GetProcessHeap(),0,p);}
unsigned sessionCreations{};
NTSTATUS NTAPI createSession(PLUID){sessionCreations++;return NTSTATUS(0xc0000022);}
NTSTATUS NTAPI deleteSession(PLUID){return 0;}
NTSTATUS NTAPI allocateClient(PLSA_CLIENT_REQUEST,ULONG n,PVOID* p){*p=heap(n);return *p?0:NTSTATUS(0xc0000017);}
NTSTATUS NTAPI freeClient(PLSA_CLIENT_REQUEST,PVOID p){release(p);return 0;}
NTSTATUS NTAPI copyClient(PLSA_CLIENT_REQUEST,ULONG n,PVOID p,PVOID source){CopyMemory(p,source,n);return 0;}
NTSTATUS NTAPI client(PSECPKG_CLIENT_INFO c){*c={};c->ProcessID=GetCurrentProcessId();c->Restricted=TRUE;return 0;}
}
int wmain(int argc,wchar_t** argv){try{
  SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX);
  require(argc==2,"DLL path required");auto path=std::filesystem::absolute(argv[1]);auto dll=LoadLibraryExW(path.c_str(),nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);require(dll!=nullptr,"Package DLL load blocked or failed; inspect Application Control");
  auto initialize=reinterpret_cast<SpLsaModeInitializeFn>(GetProcAddress(dll,"SpLsaModeInitialize"));require(initialize!=nullptr,"SSP/AP entrypoint missing");ULONG version{},count{};PSECPKG_FUNCTION_TABLE tables{};require(initialize(SECPKG_INTERFACE_VERSION,&version,&tables,&count)==0&&count==1&&tables&&tables->LogonUserEx2&&tables->CallPackageUntrusted,"Authentication callbacks missing");
  LSA_SECPKG_FUNCTION_TABLE support{};support.GetClientInfo=client;support.AllocateLsaHeap=heap;support.FreeLsaHeap=release;support.CreateLogonSession=createSession;support.DeleteLogonSession=deleteSession;support.AllocateClientBuffer=allocateClient;support.CopyToClientBuffer=copyClient;support.FreeClientBuffer=freeClient;
  require(tables->Initialize(0,nullptr,&support)==0,"LSA support initialization");LSA_DISPATCH_TABLE dispatch{};dispatch.AllocateLsaHeap=heap;dispatch.FreeLsaHeap=release;dispatch.CreateLogonSession=createSession;dispatch.DeleteLogonSession=deleteSession;dispatch.AllocateClientBuffer=allocateClient;dispatch.CopyToClientBuffer=copyClient;dispatch.FreeClientBuffer=freeClient;PLSA_STRING name{};require(tables->InitializePackage(0,&dispatch,nullptr,nullptr,&name)==0&&std::string(name->Buffer,name->Length)=="WINDOWS-UNLOCK","Package identity");release(name);
  std::string malformed="{}";PVOID output{};ULONG size{};NTSTATUS status{};require(tables->CallPackageUntrusted(nullptr,malformed.data(),nullptr,ULONG(malformed.size()),&output,&size,&status)!=0&&!output&&size==0&&status!=0,"Untrusted begin denied with empty output");
  for(auto type:{Interactive,Unlock,Network,Batch,Service}){PVOID profile{},token{};ULONG profileSize{};LUID id{};NTSTATUS sub{};LSA_TOKEN_INFORMATION_TYPE info{};PUNICODE_STRING account{},domain{},machine{};SECPKG_PRIMARY_CRED primary{};PSECPKG_SUPPLEMENTAL_CRED_ARRAY supplemental{};
    require(tables->LogonUserEx2(nullptr,type,malformed.data(),nullptr,ULONG(malformed.size()),&profile,&profileSize,&id,&sub,&info,&token,&account,&domain,&machine,&primary,&supplemental)!=0&&!token&&!profile&&profileSize==0&&!id.HighPart&&!id.LowPart&&sub!=0&&!primary.Password.Buffer&&!supplemental,"Untrusted submission never yields credential/token");if(account)release(account);if(domain)release(domain);if(machine)release(machine);
  }
  require(sessionCreations==0,"Untrusted caller must not reach session creation");require(tables->Shutdown()==0,"Shutdown");FreeLibrary(dll);std::cout<<"Actual SSP/AP exports, restricted caller rejection and empty failure outputs passed in a normal process. No LSA registration, Windows logon or token creation.\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
