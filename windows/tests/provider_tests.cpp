#include "provider_test_support.hpp"
int wmain(int argc,wchar_t** argv){try{
  // Loader failures must fail the test without opening an unattended modal dialog.
  // This only changes error presentation; Windows still enforces its integrity policy.
  SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX);
  check(argc==2,"Provider DLL path required");check(SUCCEEDED(CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED)),"COM initialization failed");
  auto path=std::filesystem::absolute(argv[1]);HMODULE dll=LoadLibraryExW(path.c_str(),nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);check(dll!=nullptr,"Provider DLL loading failed (check Application Control)");
  auto factoryEntry=reinterpret_cast<HRESULT(WINAPI*)(REFCLSID,REFIID,void**)>(GetProcAddress(dll,"DllGetClassObject"));auto unload=reinterpret_cast<HRESULT(WINAPI*)()>(GetProcAddress(dll,"DllCanUnloadNow"));check(factoryEntry&&unload,"COM exports missing");
  {ComPtr<IClassFactory> factory;check(SUCCEEDED(factoryEntry(ProviderId,IID_PPV_ARGS(&factory))),"COM factory");check(unload()==S_FALSE,"Active factory holds DLL");
    ComPtr<ICredentialProvider> provider;check(SUCCEEDED(factory->CreateInstance(nullptr,IID_PPV_ARGS(&provider))),"Provider construction");
    ComPtr<ICredentialProviderFilter> filter;check(provider.As(&filter)==E_NOINTERFACE,"No builtin provider filter");
    for(auto scenario:{CPUS_CREDUI,CPUS_CHANGE_PASSWORD,CPUS_PLAP}){check(provider->SetUsageScenario(scenario,0)==E_NOTIMPL,"Unsupported scenario rejected");DWORD count{},def{};BOOL automatic=TRUE;check(SUCCEEDED(provider->GetCredentialCount(&count,&def,&automatic))&&count==0&&def==CREDENTIAL_PROVIDER_NO_DEFAULT&&!automatic,"No default/auto-logon on rejected scenario");}
    check(SUCCEEDED(provider->SetUsageScenario(CPUS_LOGON,0)),"Local console scenario");
    ComPtr<ICredentialProviderSetUserArray> userSetter;check(SUCCEEDED(provider.As(&userSetter)),"V2 user array");
    ComPtr<Users> users;users.Attach(new Users);users->add(currentSid());users->add(L"not-a-sid");users->add(L"S-1-5-21-1-2-3-1001");check(SUCCEEDED(userSetter->SetUserArray(users.Get())),"User enumeration");
    DWORD count{},def{};BOOL automatic=TRUE;check(SUCCEEDED(provider->GetCredentialCount(&count,&def,&automatic))&&count==2&&def==CREDENTIAL_PROVIDER_NO_DEFAULT&&!automatic,"Only valid SIDs; no default/automatic login");check(users->filterCalls==0,"Never filters system providers");
    DWORD fields{};check(SUCCEEDED(provider->GetFieldDescriptorCount(&fields))&&fields==7,"Field layout");
    for(DWORD i=0;i<fields;i++){CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* descriptor{};check(SUCCEEDED(provider->GetFieldDescriptorAt(i,&descriptor))&&descriptor&&descriptor->dwFieldID==i,"Descriptor allocation");if(i==0)check(descriptor->guidFieldType==CPFG_CREDENTIAL_PROVIDER_LOGO,"V2 logo");if(i==4)check(descriptor->guidFieldType==CPFG_CREDENTIAL_PROVIDER_LABEL,"V2 label");CoTaskMemFree(descriptor->pszLabel);CoTaskMemFree(descriptor);}
    for(DWORD i=0;i<count;i++){ComPtr<ICredentialProviderCredential> credential;check(SUCCEEDED(provider->GetCredentialAt(i,&credential)),"Credential enumeration");ComPtr<ICredentialProviderCredential2> v2;check(SUCCEEDED(credential.As(&v2)),"V2 credential");LPWSTR sid{};check(SUCCEEDED(v2->GetUserSid(&sid))&&validSid(sid),"Bound user SID");CoTaskMemFree(sid);
      ComPtr<Events> events;events.Attach(new Events);check(SUCCEEDED(credential->Advise(events.Get())),"Event subscription");automatic=TRUE;check(SUCCEEDED(credential->SetSelected(&automatic))&&!automatic,"Tile never requests auto-logon");
      CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE response{};CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION serialized{};LPWSTR message{};CREDENTIAL_PROVIDER_STATUS_ICON icon{};
      const auto before=GetTickCount64();check(SUCCEEDED(credential->GetSerialization(&response,&serialized,&message,&icon)),"Serialization call");check(GetTickCount64()-before<1000,"LogonUI submission does not wait for network");
      check(response==CPGSR_NO_CREDENTIAL_NOT_FINISHED&&serialized.cbSerialization==0&&serialized.rgbSerialization==nullptr&&serialized.ulAuthenticationPackage==0,"Hard gate emits no Windows credential");check(message&&std::wstring(message).find(L"PIN")!=std::wstring::npos,"PIN fallback visible");CoTaskMemFree(message);
      auto deadline=GetTickCount64()+1000;while(GetTickCount64()<deadline&&events->updates<2){MSG msg;while(PeekMessageW(&msg,nullptr,0,0,PM_REMOVE)){TranslateMessage(&msg);DispatchMessageW(&msg);}Sleep(5);}
      check(events->updates>=2,"Selecting tile initiates request and reports unavailable service");check(!events->wrongThread,"Events delivered on original UI thread");check(SUCCEEDED(credential->SetDeselected()),"Deselect cancellation");check(SUCCEEDED(credential->UnAdvise()),"Event teardown");
      HBITMAP bitmap{};check(SUCCEEDED(credential->GetBitmapValue(0,&bitmap))&&bitmap,"Provider icon");DeleteObject(bitmap);
    }
  }
  check(unload()==S_OK,"All COM objects released");FreeLibrary(dll);CoUninitialize();std::cout<<"Provider COM: V2 enumeration, no filter/default/autologon, UI events, bounded submission and zero credential serialization passed. No registry changes.\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
