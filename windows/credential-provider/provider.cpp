#include "ipc.hpp"
#include <credentialprovider.h>
#include <shlguid.h>
#include <wrl/client.h>
#include <atomic>
#include <thread>
#include <mutex>
#include <vector>
#include <new>
#include <memory>
#ifdef PU_WINDOWS_UNLOCK
#include "client.hpp"
#endif

using namespace pu::native;
using Microsoft::WRL::ComPtr;
namespace {
HINSTANCE module{};std::atomic<long> objects{},locks{};
constexpr wchar_t WindowClass[]=L"WINDOWS-UNLOCK-Preview-Events";
constexpr UINT UpdateMessage=WM_APP+193;
enum Field:DWORD {Image,Title,Status,Recovery,Label,Submit,Cancel,FieldCount};
constexpr const wchar_t* Labels[]{L"Phone",L"Unlock with Phone",L"Approval preview only. Use Windows PIN to sign in.",L"Sign-in options → PIN",L"Unlock with Phone (approval preview)",L"Request phone approval",L"Cancel request"};
#ifdef PU_WINDOWS_UNLOCK
constexpr const wchar_t* UnlockLabels[]{L"Phone",L"Unlock with Phone",L"Select to request phone approval.",L"Sign-in options → PIN",L"Unlock with Phone",L"Request phone approval",L"Cancel request"};
struct EventHub {ComPtr<ICredentialProviderEvents> events;UINT_PTR context{};DWORD selected{CREDENTIAL_PROVIDER_NO_DEFAULT},ready{CREDENTIAL_PROVIDER_NO_DEFAULT};};
#endif
constexpr CREDENTIAL_PROVIDER_FIELD_TYPE Types[]{CPFT_TILE_IMAGE,CPFT_LARGE_TEXT,CPFT_SMALL_TEXT,CPFT_SMALL_TEXT,CPFT_SMALL_TEXT,CPFT_SUBMIT_BUTTON,CPFT_COMMAND_LINK};
HRESULT copy(const std::wstring& text,LPWSTR* output){if(!output)return E_POINTER;*output=nullptr;auto value=static_cast<wchar_t*>(CoTaskMemAlloc((text.size()+1)*sizeof(wchar_t)));if(!value)return E_OUTOFMEMORY;wcscpy_s(value,text.size()+1,text.c_str());*output=value;return S_OK;}
template<class F> HRESULT boundary(F&& f) noexcept {try{return f();}catch(const std::bad_alloc&){return E_OUTOFMEMORY;}catch(...){return E_FAIL;}}

class Credential final:public ICredentialProviderCredential2 {
  std::atomic<ULONG> refs_{1};std::wstring sid_;DWORD scenario_{},session_{};
  ComPtr<ICredentialProviderCredentialEvents> events_;HWND notification_{};DWORD uiThread_{};
  std::jthread worker_;std::atomic<State> pending_{State::Unavailable};State state_{State::Unavailable};
  std::mutex phoneMutex_;std::wstring phone_;bool selected_{},requested_{},windowReference_{};
#ifdef PU_WINDOWS_UNLOCK
  std::shared_ptr<EventHub> hub_;DWORD index_{};std::string proof_;GUID operation_{};bool submitted_{};
  void revoke(){stop();{std::lock_guard lock(phoneMutex_);proof_.clear();}hub_->ready=CREDENTIAL_PROVIDER_NO_DEFAULT;hub_->selected=CREDENTIAL_PROVIDER_NO_DEFAULT;
    // After serialization Windows owns the proof. Teardown must not race its LSA call.
    if(!submitted_&&!IsEqualGUID(operation_,GUID{})){try{call(request(Operation::Cancel,operation_));}catch(...){}}operation_={};submitted_=false;}
#endif
  static LRESULT CALLBACK windowProc(HWND window,UINT message,WPARAM wp,LPARAM lp){
    auto self=reinterpret_cast<Credential*>(GetWindowLongPtrW(window,GWLP_USERDATA));
    if(message==WM_NCCREATE){self=static_cast<Credential*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);SetWindowLongPtrW(window,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(self));}
    if(message==UpdateMessage&&self){self->update();return 0;}
    if(message==WM_NCDESTROY&&self){self->stop();self->events_.Reset();self->notification_=nullptr;SetWindowLongPtrW(window,GWLP_USERDATA,0);if(self->windowReference_){self->windowReference_=false;self->Release();}}
    return DefWindowProcW(window,message,wp,lp);
  }
  void update() noexcept {try{state_=pending_.load();if(events_){auto text=statusText(state_);{std::lock_guard lock(phoneMutex_);if((state_==State::Waiting||state_==State::PushUnavailable)&&!phone_.empty())text=L"Request sent to "+phone_+L"\n"+text;}events_->SetFieldString(this,Status,text.c_str());}
#ifdef PU_WINDOWS_UNLOCK
    if(state_==State::ApprovedSignIn&&selected_&&!submitted_&&hub_->events&&hub_->selected==index_&&hub_->ready!=index_){hub_->ready=index_;hub_->events->CredentialsChanged(hub_->context);}
#endif
  }catch(...){/* Never let UI callback exceptions escape into LogonUI. */}}
  Request request(Operation op,const GUID& id)const {Request q;q.operation=op;q.scenario=scenario_;q.sessionId=session_;q.operationId=id;wcscpy_s(q.sid.data(),q.sid.size(),sid_.c_str());return q;}
  void stop() {if(worker_.joinable()){worker_.request_stop();worker_.join();}}
  void begin(){
    if(!notification_||!selected_||requested_)return;
    requested_=true;stop();pending_=State::Waiting;update();GUID id{};if(FAILED(CoCreateGuid(&id))){pending_=State::Unavailable;update();return;}
#ifdef PU_WINDOWS_UNLOCK
    operation_=id;submitted_=false;hub_->selected=index_;hub_->ready=CREDENTIAL_PROVIDER_NO_DEFAULT;{std::lock_guard lock(phoneMutex_);proof_.clear();}
#endif
    // Only local IPC on this worker; no HTTP, private keys or biometric logic in DLL.
    worker_=std::jthread([this,id](std::stop_token token){bool started=false,terminal=false;try{
      auto reply=call(request(Operation::Begin,id),token);started=reply.state==State::Waiting||reply.state==State::PushUnavailable;
      const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(60);
      while(!token.stop_requested()){
        {std::lock_guard lock(phoneMutex_);phone_=reply.phoneName.data();for(auto& c:phone_)if(c<32)c=L' ';
#ifdef PU_WINDOWS_UNLOCK
          if(reply.state==State::ApprovedSignIn)proof_.assign(reply.proof.data(),reply.proofSize);
#endif
        }
        pending_=reply.state;PostMessageW(notification_,UpdateMessage,0,0);
        if(reply.state!=State::Waiting&&reply.state!=State::PushUnavailable){terminal=true;break;}
        if(std::chrono::steady_clock::now()>=deadline){pending_=State::Expired;PostMessageW(notification_,UpdateMessage,0,0);break;}
        for(unsigned i=0;i<10&&!token.stop_requested();i++)std::this_thread::sleep_for(std::chrono::milliseconds(50));
        if(!token.stop_requested())reply=call(request(Operation::Poll,id),token);
      }
    }catch(...){pending_=State::Unavailable;if(!token.stop_requested())PostMessageW(notification_,UpdateMessage,0,0);}
      if(started&&!terminal){try{call(request(Operation::Cancel,id));}catch(...){/* Session change and expiry also revoke pending work. */}}
    });
  }
public:
#ifdef PU_WINDOWS_UNLOCK
  Credential(std::wstring sid,DWORD scenario,std::shared_ptr<EventHub> hub,DWORD index):sid_(std::move(sid)),scenario_(scenario),hub_(std::move(hub)),index_(index){++objects;ProcessIdToSessionId(GetCurrentProcessId(),&session_);}
#else
  Credential(std::wstring sid,DWORD scenario):sid_(std::move(sid)),scenario_(scenario){++objects;ProcessIdToSessionId(GetCurrentProcessId(),&session_);}
#endif
  ~Credential(){stop();if(notification_)DestroyWindow(notification_);--objects;}
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** output)override {if(!output)return E_POINTER;*output=nullptr;if(iid==IID_IUnknown||iid==__uuidof(ICredentialProviderCredential)||iid==__uuidof(ICredentialProviderCredential2))*output=static_cast<ICredentialProviderCredential2*>(this);else return E_NOINTERFACE;AddRef();return S_OK;}
  ULONG STDMETHODCALLTYPE AddRef()override{return ++refs_;}
  ULONG STDMETHODCALLTYPE Release()override{auto n=--refs_;if(!n)delete this;return n;}
  HRESULT STDMETHODCALLTYPE Advise(ICredentialProviderCredentialEvents* events)override{return boundary([&]()->HRESULT{
    if(!events)return E_INVALIDARG;if(events_)return E_UNEXPECTED;
    uiThread_=GetCurrentThreadId();WNDCLASSW cls{};cls.hInstance=module;cls.lpszClassName=WindowClass;cls.lpfnWndProc=windowProc;
    if(!RegisterClassW(&cls)&&GetLastError()!=ERROR_CLASS_ALREADY_EXISTS)return HRESULT_FROM_WIN32(GetLastError());
    AddRef();windowReference_=true;notification_=CreateWindowExW(0,WindowClass,L"",0,0,0,0,0,HWND_MESSAGE,nullptr,module,this);if(!notification_){auto error=GetLastError();if(windowReference_){windowReference_=false;Release();}return HRESULT_FROM_WIN32(error);}events_=events;return S_OK;
  });}
  HRESULT STDMETHODCALLTYPE UnAdvise()override{return boundary([&]()->HRESULT{if(uiThread_&&uiThread_!=GetCurrentThreadId())return E_UNEXPECTED;selected_=false;stop();
#ifdef PU_WINDOWS_UNLOCK
    revoke();
#endif
    events_.Reset();if(notification_){DestroyWindow(notification_);notification_=nullptr;UnregisterClassW(WindowClass,module);}return S_OK;});}
  HRESULT STDMETHODCALLTYPE SetSelected(BOOL* autoLogon)override{return boundary([&]()->HRESULT{if(!autoLogon)return E_POINTER;*autoLogon=FALSE;if(uiThread_&&uiThread_!=GetCurrentThreadId())return E_UNEXPECTED;selected_=true;begin();return S_OK;});}
  HRESULT STDMETHODCALLTYPE SetDeselected()override{return boundary([&]()->HRESULT{selected_=false;stop();
#ifdef PU_WINDOWS_UNLOCK
    revoke();
#endif
    requested_=false;pending_=State::Cancelled;update();return S_OK;});}
  HRESULT STDMETHODCALLTYPE GetUserSid(LPWSTR* sid)override{return boundary([&]{return copy(sid_,sid);});}
  HRESULT STDMETHODCALLTYPE GetFieldState(DWORD id,CREDENTIAL_PROVIDER_FIELD_STATE* state,CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interactive)override{if(id>=FieldCount||!state||!interactive)return E_INVALIDARG;*interactive=CPFIS_NONE;*state=id==Label?CPFS_HIDDEN:id==Image?CPFS_DISPLAY_IN_BOTH:CPFS_DISPLAY_IN_SELECTED_TILE;return S_OK;}
  HRESULT STDMETHODCALLTYPE GetStringValue(DWORD id,LPWSTR* text)override{return boundary([&]()->HRESULT{if(id>=FieldCount||id==Image)return E_INVALIDARG;
#ifdef PU_WINDOWS_UNLOCK
    return copy(id==Status?statusText(state_):UnlockLabels[id],text);
#else
    return copy(id==Status?statusText(state_):Labels[id],text);
#endif
  });}
  HRESULT STDMETHODCALLTYPE GetBitmapValue(DWORD id,HBITMAP* bitmap)override {
    if(!bitmap)return E_POINTER;*bitmap=nullptr;if(id!=Image)return E_INVALIDARG;
    BITMAPINFO info{};info.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);info.bmiHeader.biWidth=72;info.bmiHeader.biHeight=-72;info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=32;info.bmiHeader.biCompression=BI_RGB;void* pixels{};
    *bitmap=CreateDIBSection(nullptr,&info,DIB_RGB_COLORS,&pixels,nullptr,0);if(!*bitmap)return E_OUTOFMEMORY;
    auto values=static_cast<uint32_t*>(pixels);for(int y=0;y<72;y++)for(int x=0;x<72;x++){bool edge=(x>=23&&x<=48&&(y>=12&&y<=15||y>=56&&y<=59))||(y>=12&&y<=59&&(x>=23&&x<=26||x>=45&&x<=48));values[y*72+x]=edge?0xffffffff:0xff164a87;}return S_OK;
  }
  HRESULT STDMETHODCALLTYPE GetCheckboxValue(DWORD,BOOL*,LPWSTR*)override{return E_NOTIMPL;}
  HRESULT STDMETHODCALLTYPE GetSubmitButtonValue(DWORD id,DWORD* adjacent)override{if(id!=Submit||!adjacent)return E_INVALIDARG;*adjacent=Status;return S_OK;}
  HRESULT STDMETHODCALLTYPE GetComboBoxValueCount(DWORD,DWORD*,DWORD*)override{return E_NOTIMPL;}
  HRESULT STDMETHODCALLTYPE GetComboBoxValueAt(DWORD,DWORD,LPWSTR*)override{return E_NOTIMPL;}
  HRESULT STDMETHODCALLTYPE SetStringValue(DWORD,LPCWSTR)override{return E_NOTIMPL;}
  HRESULT STDMETHODCALLTYPE SetCheckboxValue(DWORD,BOOL)override{return E_NOTIMPL;}
  HRESULT STDMETHODCALLTYPE SetComboBoxSelectedValue(DWORD,DWORD)override{return E_NOTIMPL;}
  HRESULT STDMETHODCALLTYPE CommandLinkClicked(DWORD id)override{return boundary([&]()->HRESULT{if(id!=Cancel)return E_INVALIDARG;stop();
#ifdef PU_WINDOWS_UNLOCK
    revoke();
#endif
    requested_=false;pending_=State::Cancelled;update();return S_OK;});}
  HRESULT STDMETHODCALLTYPE GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* credentials,LPWSTR* text,CREDENTIAL_PROVIDER_STATUS_ICON* icon)override {
    // Desktop-preview proofs never become credentials. The unlock build submits to LSA.
    if(!response||!credentials||!text||!icon)return E_POINTER;
    *response=CPGSR_NO_CREDENTIAL_NOT_FINISHED;*credentials={};*text=nullptr;*icon=CPSI_WARNING;
#ifdef PU_WINDOWS_UNLOCK
    return boundary([&]()->HRESULT{if(uiThread_&&uiThread_!=GetCurrentThreadId())return E_UNEXPECTED;begin();if(state_!=State::ApprovedSignIn||!selected_||submitted_)return copy(L"Waiting for phone approval. Use Windows PIN if unavailable.",text);
      std::string proof;{std::lock_guard lock(phoneMutex_);proof=proof_;}if(proof.empty()||proof.size()>=pu::auth::MaxSubmission)return E_FAIL;
      const auto package=pu::auth::packageId();auto data=static_cast<BYTE*>(CoTaskMemAlloc(proof.size()));if(!data)return E_OUTOFMEMORY;CopyMemory(data,proof.data(),proof.size());credentials->ulAuthenticationPackage=package;credentials->clsidCredentialProvider=ProviderId;credentials->cbSerialization=ULONG(proof.size());credentials->rgbSerialization=data;*response=CPGSR_RETURN_CREDENTIAL_FINISHED;*icon=CPSI_NONE;submitted_=true;hub_->ready=CREDENTIAL_PROVIDER_NO_DEFAULT;return S_OK;
    });
#else
    return boundary([&]()->HRESULT{begin();return copy(L"Approval transport preview. Windows sign-in is disabled; use Sign-in options → PIN.",text);});
#endif
  }
  HRESULT STDMETHODCALLTYPE ReportResult(NTSTATUS,NTSTATUS,LPWSTR* text,CREDENTIAL_PROVIDER_STATUS_ICON* icon)override{return boundary([&]()->HRESULT{if(!text||!icon)return E_POINTER;*text=nullptr;*icon=CPSI_ERROR;return copy(L"Phone sign-in unavailable. Use Windows PIN.",text);});}
};

class Provider final:public ICredentialProvider,public ICredentialProviderSetUserArray {
  std::atomic<ULONG> refs_{1};DWORD scenario_{};ComPtr<ICredentialProviderUserArray> users_;std::vector<ComPtr<ICredentialProviderCredential>> credentials_;
#ifdef PU_WINDOWS_UNLOCK
  std::shared_ptr<EventHub> hub_{std::make_shared<EventHub>()};
#endif
  void enumerate(){if(!credentials_.empty()||!users_||!scenario_)return;DWORD count{};if(FAILED(users_->GetCount(&count))||count>64)return;
    for(DWORD i=0;i<count;i++){ComPtr<ICredentialProviderUser> user;if(FAILED(users_->GetAt(i,&user)))continue;LPWSTR raw{};if(FAILED(user->GetSid(&raw)))continue;std::wstring sid=raw?raw:L"";CoTaskMemFree(raw);if(!validSid(sid))continue;ComPtr<ICredentialProviderCredential> credential;
#ifdef PU_WINDOWS_UNLOCK
      credential.Attach(new Credential(std::move(sid),scenario_,hub_,DWORD(credentials_.size())));
#else
      credential.Attach(new Credential(std::move(sid),scenario_));
#endif
      credentials_.push_back(std::move(credential));}
  }
public:
  Provider(){++objects;}~Provider(){--objects;}
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** output)override{if(!output)return E_POINTER;*output=nullptr;if(iid==IID_IUnknown||iid==__uuidof(ICredentialProvider))*output=static_cast<ICredentialProvider*>(this);else if(iid==__uuidof(ICredentialProviderSetUserArray))*output=static_cast<ICredentialProviderSetUserArray*>(this);else return E_NOINTERFACE;AddRef();return S_OK;}
  ULONG STDMETHODCALLTYPE AddRef()override{return ++refs_;}ULONG STDMETHODCALLTYPE Release()override{auto n=--refs_;if(!n)delete this;return n;}
  HRESULT STDMETHODCALLTYPE SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario,DWORD flags)override{return boundary([&]()->HRESULT{scenario_=0;credentials_.clear();users_.Reset();
#ifdef PU_WINDOWS_UNLOCK
    hub_->ready=hub_->selected=CREDENTIAL_PROVIDER_NO_DEFAULT;
#endif
    DWORD session{};if(flags||!ProcessIdToSessionId(GetCurrentProcessId(),&session)||session!=WTSGetActiveConsoleSessionId()||(scenario!=CPUS_LOGON&&scenario!=CPUS_UNLOCK_WORKSTATION))return E_NOTIMPL;scenario_=DWORD(scenario);return S_OK;});}
  HRESULT STDMETHODCALLTYPE SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*)override{return E_NOTIMPL;}
  HRESULT STDMETHODCALLTYPE Advise(ICredentialProviderEvents* events,UINT_PTR context)override{
#ifdef PU_WINDOWS_UNLOCK
    if(!events)return E_INVALIDARG;hub_->events=events;hub_->context=context;
#else
    (void)events;(void)context;
#endif
    return S_OK;}
  HRESULT STDMETHODCALLTYPE UnAdvise()override{
#ifdef PU_WINDOWS_UNLOCK
    hub_->events.Reset();hub_->ready=hub_->selected=CREDENTIAL_PROVIDER_NO_DEFAULT;
#endif
    return S_OK;}
  HRESULT STDMETHODCALLTYPE SetUserArray(ICredentialProviderUserArray* users)override{return boundary([&]()->HRESULT{credentials_.clear();users_=users;
#ifdef PU_WINDOWS_UNLOCK
    hub_->ready=hub_->selected=CREDENTIAL_PROVIDER_NO_DEFAULT;
#endif
    return S_OK;});}
  HRESULT STDMETHODCALLTYPE GetFieldDescriptorCount(DWORD* count)override{if(!count)return E_POINTER;*count=FieldCount;return S_OK;}
  HRESULT STDMETHODCALLTYPE GetFieldDescriptorAt(DWORD id,CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** output)override{return boundary([&]()->HRESULT{if(!output)return E_POINTER;*output=nullptr;if(id>=FieldCount)return E_INVALIDARG;auto field=static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));if(!field)return E_OUTOFMEMORY;*field={};field->dwFieldID=id;field->cpft=Types[id];
#ifdef PU_WINDOWS_UNLOCK
    auto result=copy(UnlockLabels[id],&field->pszLabel);
#else
    auto result=copy(Labels[id],&field->pszLabel);
#endif
    if(FAILED(result)){CoTaskMemFree(field);return result;}if(id==Image)field->guidFieldType=CPFG_CREDENTIAL_PROVIDER_LOGO;if(id==Label)field->guidFieldType=CPFG_CREDENTIAL_PROVIDER_LABEL;*output=field;return S_OK;});}
  HRESULT STDMETHODCALLTYPE GetCredentialCount(DWORD* count,DWORD* defaultIndex,BOOL* autoLogon)override{return boundary([&]()->HRESULT{if(!count||!defaultIndex||!autoLogon)return E_POINTER;*count=0;*defaultIndex=CREDENTIAL_PROVIDER_NO_DEFAULT;*autoLogon=FALSE;enumerate();*count=DWORD(credentials_.size());
#ifdef PU_WINDOWS_UNLOCK
    if(hub_->ready==hub_->selected&&hub_->ready<*count){*defaultIndex=hub_->ready;*autoLogon=TRUE;}
#endif
    return S_OK;});}
  HRESULT STDMETHODCALLTYPE GetCredentialAt(DWORD i,ICredentialProviderCredential** output)override {if(!output)return E_POINTER;*output=nullptr;if(i>=credentials_.size())return E_INVALIDARG;return credentials_[i].CopyTo(output);}
};
class Factory final:public IClassFactory {
  std::atomic<ULONG> refs_{1};
public:
  Factory(){++objects;}~Factory(){--objects;}
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** output)override{if(!output)return E_POINTER;*output=nullptr;if(iid!=IID_IUnknown&&iid!=IID_IClassFactory)return E_NOINTERFACE;*output=static_cast<IClassFactory*>(this);AddRef();return S_OK;}
  ULONG STDMETHODCALLTYPE AddRef()override{return ++refs_;}ULONG STDMETHODCALLTYPE Release()override{auto n=--refs_;if(!n)delete this;return n;}
  HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer,REFIID iid,void** output)override{return boundary([&]()->HRESULT{if(!output)return E_POINTER;*output=nullptr;if(outer)return CLASS_E_NOAGGREGATION;auto p=new Provider;auto hr=p->QueryInterface(iid,output);p->Release();return hr;});}
  HRESULT STDMETHODCALLTYPE LockServer(BOOL lock)override{if(lock)++locks;else{auto count=locks.load();while(count>0&&!locks.compare_exchange_weak(count,count-1)){} }return S_OK;}
};
}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,LPVOID){if(reason==DLL_PROCESS_ATTACH)module=instance;return TRUE;}
extern "C" HRESULT WINAPI DllGetClassObject(REFCLSID id,REFIID iid,void** output){if(!output)return E_POINTER;*output=nullptr;if(id!=ProviderId)return CLASS_E_CLASSNOTAVAILABLE;return boundary([&]{auto factory=new Factory;auto hr=factory->QueryInterface(iid,output);factory->Release();return hr;});}
extern "C" HRESULT WINAPI DllCanUnloadNow(){return objects==0&&locks==0?S_OK:S_FALSE;}
