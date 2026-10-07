#include "ipc.hpp"
#include <credentialprovider.h>
#include <shlguid.h>
#include <wrl/client.h>
#include <iostream>
#include <vector>
#include <atomic>
#include <filesystem>
using namespace pu::native;using Microsoft::WRL::ComPtr;
void check(bool value,const char* label){require(value,label);}
HRESULT text(const std::wstring& value,LPWSTR* out){if(!out)return E_POINTER;*out=static_cast<LPWSTR>(CoTaskMemAlloc((value.size()+1)*sizeof(wchar_t)));if(!*out)return E_OUTOFMEMORY;wcscpy_s(*out,value.size()+1,value.c_str());return S_OK;}
struct User final:ICredentialProviderUser {
  std::atomic<ULONG> refs{1};std::wstring sid;explicit User(std::wstring s):sid(std::move(s)){}
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id,void** out)override{if(!out)return E_POINTER;*out=nullptr;if(id!=IID_IUnknown&&id!=__uuidof(ICredentialProviderUser))return E_NOINTERFACE;*out=this;AddRef();return S_OK;}
  ULONG STDMETHODCALLTYPE AddRef()override{return ++refs;}ULONG STDMETHODCALLTYPE Release()override{auto n=--refs;if(!n)delete this;return n;}
  HRESULT STDMETHODCALLTYPE GetSid(LPWSTR* out)override{return text(sid,out);}
  HRESULT STDMETHODCALLTYPE GetProviderID(GUID* id)override{if(!id)return E_POINTER;*id={};return S_OK;}
  HRESULT STDMETHODCALLTYPE GetStringValue(REFPROPERTYKEY,LPWSTR* out)override{if(out)*out=nullptr;return E_NOTIMPL;}
  HRESULT STDMETHODCALLTYPE GetValue(REFPROPERTYKEY,PROPVARIANT* out)override{if(out)*out={};return E_NOTIMPL;}
};
struct Users final:ICredentialProviderUserArray {
  std::atomic<ULONG> refs{1};std::vector<ComPtr<ICredentialProviderUser>> list;unsigned filterCalls{};
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id,void** out)override{if(!out)return E_POINTER;*out=nullptr;if(id!=IID_IUnknown&&id!=__uuidof(ICredentialProviderUserArray))return E_NOINTERFACE;*out=this;AddRef();return S_OK;}
  ULONG STDMETHODCALLTYPE AddRef()override{return ++refs;}ULONG STDMETHODCALLTYPE Release()override{auto n=--refs;if(!n)delete this;return n;}
  HRESULT STDMETHODCALLTYPE SetProviderFilter(REFGUID)override{++filterCalls;return E_FAIL;}
  HRESULT STDMETHODCALLTYPE GetAccountOptions(CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS* out)override{if(!out)return E_POINTER;*out=CPAO_NONE;return S_OK;}
  HRESULT STDMETHODCALLTYPE GetCount(DWORD* out)override{if(!out)return E_POINTER;*out=DWORD(list.size());return S_OK;}
  HRESULT STDMETHODCALLTYPE GetAt(DWORD i,ICredentialProviderUser** out)override{if(!out)return E_POINTER;*out=nullptr;if(i>=list.size())return E_INVALIDARG;return list[i].CopyTo(out);}
  void add(const std::wstring& sid){ComPtr<ICredentialProviderUser> user;user.Attach(new User(sid));list.push_back(std::move(user));}
};
struct Events final:ICredentialProviderCredentialEvents {
  std::atomic<ULONG> refs{1};DWORD thread{GetCurrentThreadId()};unsigned updates{};bool wrongThread{};
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id,void** out)override{if(!out)return E_POINTER;*out=nullptr;if(id!=IID_IUnknown&&id!=__uuidof(ICredentialProviderCredentialEvents))return E_NOINTERFACE;*out=this;AddRef();return S_OK;}
  ULONG STDMETHODCALLTYPE AddRef()override{return ++refs;}ULONG STDMETHODCALLTYPE Release()override{auto n=--refs;if(!n)delete this;return n;}
  HRESULT STDMETHODCALLTYPE SetFieldState(ICredentialProviderCredential*,DWORD,CREDENTIAL_PROVIDER_FIELD_STATE)override{return S_OK;}
  HRESULT STDMETHODCALLTYPE SetFieldInteractiveState(ICredentialProviderCredential*,DWORD,CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE)override{return S_OK;}
  HRESULT STDMETHODCALLTYPE SetFieldString(ICredentialProviderCredential*,DWORD,LPCWSTR)override{++updates;if(GetCurrentThreadId()!=thread)wrongThread=true;return S_OK;}
  HRESULT STDMETHODCALLTYPE SetFieldCheckbox(ICredentialProviderCredential*,DWORD,BOOL,LPCWSTR)override{return S_OK;}
  HRESULT STDMETHODCALLTYPE SetFieldBitmap(ICredentialProviderCredential*,DWORD,HBITMAP)override{return S_OK;}
  HRESULT STDMETHODCALLTYPE SetFieldComboBoxSelectedItem(ICredentialProviderCredential*,DWORD,DWORD)override{return S_OK;}
  HRESULT STDMETHODCALLTYPE DeleteFieldComboBoxItem(ICredentialProviderCredential*,DWORD,DWORD)override{return S_OK;}
  HRESULT STDMETHODCALLTYPE AppendFieldComboBoxItem(ICredentialProviderCredential*,DWORD,LPCWSTR)override{return S_OK;}
  HRESULT STDMETHODCALLTYPE SetFieldSubmitButton(ICredentialProviderCredential*,DWORD,DWORD)override{return S_OK;}
  HRESULT STDMETHODCALLTYPE OnCreatingWindow(HWND* out)override{if(!out)return E_POINTER;*out=nullptr;return S_OK;}
};
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
