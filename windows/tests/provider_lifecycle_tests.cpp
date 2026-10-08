#include "provider_test_support.hpp"
#include <future>
#include <chrono>
#include <thread>
struct MockService {
  Handle stop{event()};std::jthread worker;std::atomic<State> phase{State::Waiting};std::atomic<unsigned> begins{},claims{},results{};GUID operation{};
  explicit MockService(bool automatic){
    std::promise<void> ready;auto future=ready.get_future();
    worker=std::jthread([this,automatic,promise=std::move(ready)]()mutable{try{
      auto authorize=[](HANDLE pipe,Caller& caller){DWORD pid{};if(!GetNamedPipeClientProcessId(pipe,&pid)||pid!=GetCurrentProcessId())return false;caller.processId=pid;return ProcessIdToSessionId(pid,&caller.sessionId)!=FALSE;};
      serve(L"\\\\.\\pipe\\WINDOWS-UNLOCK-Test-Provider-"+std::to_wstring(GetCurrentProcessId()),L"D:P(A;;GA;;;"+currentSid()+L")",stop.get(),authorize,[this,automatic](const Request& q,const Caller&){
        Response r;r.sid=q.sid;r.operationId=q.operationId;r.windowsSignInEnabled=1;
        if(q.operation==Operation::Describe){r.state=State::Ready;r.reserved=automatic?AutomaticRequests:0;return r;}
        if(q.operation==Operation::Begin){++begins;operation=q.operationId;r.state=State::Waiting;return r;}
        check(IsEqualGUID(q.operationId,operation),"Request remains bound through UI refresh");
        r.state=phase.load();
        if(q.operation==Operation::Claim){++claims;check(r.state==State::ApprovedSignIn,"No credential claimed before approval");r.proofSize=4;memcpy(r.proof.data(),"test",4);}
        if(q.operation==Operation::Result){++results;r.state=State::Cancelled;}
        if(q.operation==Operation::Cancel)r.state=State::Cancelled;
        return r;
      },[&]{promise.set_value();});
    }catch(...){try{promise.set_exception(std::current_exception());}catch(...){}}});
    check(future.wait_for(std::chrono::seconds(2))==std::future_status::ready,"Mock service starts");future.get();
  }
  ~MockService(){SetEvent(stop.get());if(worker.joinable())worker.join();}
};
template<class Predicate>void pump(Predicate done,const char* stage="UI lifecycle"){auto end=GetTickCount64()+5000;while(!done()&&GetTickCount64()<end){MSG m;while(PeekMessageW(&m,nullptr,0,0,PM_REMOVE)){TranslateMessage(&m);DispatchMessageW(&m);}Sleep(5);}check(done(),stage);}
struct ProviderEvents final:ICredentialProviderEvents {
  std::atomic<ULONG> refs{1};unsigned changes{};DWORD thread{GetCurrentThreadId()};ICredentialProviderSetUserArray* setter{};ICredentialProviderUserArray* users{};
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** out)override{if(!out)return E_POINTER;*out=nullptr;if(iid!=IID_IUnknown&&iid!=__uuidof(ICredentialProviderEvents))return E_NOINTERFACE;*out=this;AddRef();return S_OK;}
  ULONG STDMETHODCALLTYPE AddRef()override{return ++refs;}ULONG STDMETHODCALLTYPE Release()override{auto n=--refs;if(!n)delete this;return n;}
  HRESULT STDMETHODCALLTYPE CredentialsChanged(UINT_PTR context)override{check(GetCurrentThreadId()==thread&&context==42,"Provider callback on advised UI thread");++changes;return setter->SetUserArray(users);}
};
void scenario(IClassFactory* factory,bool automatic,bool lateAdvise,State terminal){
  std::cout<<"Scenario automatic="<<automatic<<" lateAdvise="<<lateAdvise<<" state="<<unsigned(terminal)<<'\n';
  MockService service(automatic);ComPtr<ICredentialProvider> provider;check(SUCCEEDED(factory->CreateInstance(nullptr,IID_PPV_ARGS(&provider))),"Provider creation");
  check(SUCCEEDED(provider->SetUsageScenario(CPUS_LOGON,0)),"Console scenario");ComPtr<ICredentialProviderSetUserArray> setter;check(SUCCEEDED(provider.As(&setter)),"V2 user array");
  ComPtr<Users> users;users.Attach(new Users);users->add(currentSid());check(SUCCEEDED(setter->SetUserArray(users.Get())),"User enumeration");
  ComPtr<ProviderEvents> events;events.Attach(new ProviderEvents);events->setter=setter.Get();events->users=users.Get();if(!lateAdvise)check(SUCCEEDED(provider->Advise(events.Get(),42)),"Provider advise");
  DWORD count{},def{};BOOL autologon{};check(SUCCEEDED(provider->GetCredentialCount(&count,&def,&autologon))&&count==1&&def==CREDENTIAL_PROVIDER_NO_DEFAULT&&!autologon,"No default or automatic login before approval");
  ComPtr<ICredentialProviderCredential> credential;check(SUCCEEDED(provider->GetCredentialAt(0,&credential)),"Credential identity");
  if(automatic){pump([&]{return service.begins==1;});check(SUCCEEDED(credential->SetDeselected()),"Unselected background request survives UI initialization");}
  else{
    pump([&]{LPWSTR text{};auto hr=credential->GetStringValue(2,&text);bool ready=SUCCEEDED(hr)&&text&&std::wstring(text).starts_with(L"Ready");CoTaskMemFree(text);return ready;});check(service.begins==0,"Manual policy sends no background request");
    ComPtr<Events> fields;fields.Attach(new Events);check(SUCCEEDED(credential->Advise(fields.Get())),"Manual field advise");BOOL immediate=TRUE;check(SUCCEEDED(credential->SetSelected(&immediate))&&!immediate,"Manual selection cannot bypass approval");pump([&]{return service.begins==1;});check(SUCCEEDED(credential->UnAdvise()),"Refresh detaches field events");
  }
  service.phase=terminal;
  if(lateAdvise){pump([&]{LPWSTR text{};credential->GetStringValue(2,&text);bool done=text&&std::wstring(text).starts_with(L"Phone approved");CoTaskMemFree(text);return done;});check(SUCCEEDED(provider->Advise(events.Get(),42)),"Late provider advise delivers completed approval");}
  if(terminal!=State::ApprovedSignIn){pump([&]{LPWSTR text{};credential->GetStringValue(2,&text);bool done=text&&(std::wstring(text).starts_with(L"Request denied")||std::wstring(text).starts_with(L"Request expired"));CoTaskMemFree(text);return done;});check(SUCCEEDED(provider->GetCredentialCount(&count,&def,&autologon))&&!autologon&&def==CREDENTIAL_PROVIDER_NO_DEFAULT&&service.claims==0,"Denial/expiry never auto-submits");check(events->changes==0,"No sign-in notification on rejection");provider->UnAdvise();return;}
  try{pump([&]{return events->changes>=1;},"Approved credential must notify provider");}catch(...){LPWSTR text{};credential->GetStringValue(2,&text);std::wcerr<<L"Last UI status: "<<(text?text:L"missing")<<L"; changes="<<events->changes<<L"; begins="<<service.begins.load()<<L"\n";CoTaskMemFree(text);throw;}check(events->changes==1,"Provider notifies exactly once");ComPtr<ICredentialProviderCredential> refreshed;check(SUCCEEDED(provider->GetCredentialAt(0,&refreshed))&&refreshed.Get()==credential.Get(),"Re-enumeration retains the approved credential object");
  check(SUCCEEDED(provider->SetUsageScenario(CPUS_LOGON,0)),"Same scenario refresh preserves approval");check(SUCCEEDED(provider->GetCredentialCount(&count,&def,&autologon))&&autologon&&def==0,"Approved account is automatically submitted from provider callback");
  ComPtr<Events> fields;fields.Attach(new Events);check(SUCCEEDED(credential->Advise(fields.Get())),"Field events attach after background approval");check(SUCCEEDED(credential->UnAdvise()),"Field detach preserves authenticated model");check(SUCCEEDED(credential->SetDeselected()),"Re-enumeration selection transition preserves handoff");
  BOOL immediate=FALSE;check(SUCCEEDED(credential->SetSelected(&immediate))&&immediate,"Ready credential requests automatic serialization");
  CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE response{};CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION serialized{};LPWSTR message{};CREDENTIAL_PROVIDER_STATUS_ICON icon{};
  check(SUCCEEDED(credential->GetSerialization(&response,&serialized,&message,&icon))&&response==CPGSR_RETURN_CREDENTIAL_FINISHED&&serialized.cbSerialization==4&&memcmp(serialized.rgbSerialization,"test",4)==0,"One-time claim reaches Windows serialization");SecureZeroMemory(serialized.rgbSerialization,serialized.cbSerialization);CoTaskMemFree(serialized.rgbSerialization);CoTaskMemFree(message);
  check(SUCCEEDED(provider->GetCredentialCount(&count,&def,&autologon))&&!autologon&&service.claims==1&&service.begins==1,"No duplicate claim or challenge on UI refresh");
  check(SUCCEEDED(credential->ReportResult(NTSTATUS(0xc000006d),NTSTATUS(0xc000006a),&message,&icon))&&icon==CPSI_ERROR&&message&&std::wstring(message).find(L"0xC000006D")!=std::wstring::npos,"Windows rejection is visible and reported");CoTaskMemFree(message);check(service.results==1,"Result audit reaches service");provider->UnAdvise();
}
int wmain(int argc,wchar_t** argv){try{
  SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX);check(argc==2&&SUCCEEDED(CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED)),"COM initialization");auto path=std::filesystem::absolute(argv[1]);auto dll=LoadLibraryExW(path.c_str(),nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);check(dll!=nullptr,"Test-only provider loads");
  auto entry=reinterpret_cast<HRESULT(WINAPI*)(REFCLSID,REFIID,void**)>(GetProcAddress(dll,"DllGetClassObject"));auto unload=reinterpret_cast<HRESULT(WINAPI*)()>(GetProcAddress(dll,"DllCanUnloadNow"));check(entry&&unload,"COM exports");
  {ComPtr<IClassFactory> factory;check(SUCCEEDED(entry(ProviderId,IID_PPV_ARGS(&factory))),"Test-only GUID factory");scenario(factory.Get(),true,false,State::ApprovedSignIn);scenario(factory.Get(),true,true,State::ApprovedSignIn);scenario(factory.Get(),false,false,State::ApprovedSignIn);scenario(factory.Get(),true,false,State::Denied);scenario(factory.Get(),true,false,State::Expired);}
  check(unload()==S_OK,"All provider workers/windows and COM references released");FreeLibrary(dll);CoUninitialize();std::cout<<"Provider lifecycle: background approval, UI refresh, late events, manual policy, one-time serialization, rejection and expiry passed. Test-only GUID/mock pipe; no registration or Windows login.\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
