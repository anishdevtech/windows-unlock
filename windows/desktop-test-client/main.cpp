#include "core.hpp"
#include "remote.hpp"
#include <shellapi.h>
#include <commctrl.h>
#include <objbase.h>
#include <atomic>
#include <thread>
#include <fstream>
using namespace pu;
namespace {
HWND window{},statusLabel{},remoteLabel{},powerCheck{},cameraCheck{},pairButton{},requestButton{},cancelButton{},unpairButton{};
std::unique_ptr<RemoteAgent> remoteAgent;std::atomic<bool> cameraAllowed{false};NOTIFYICONDATAW tray{};
std::filesystem::path stateDir;Json config;std::jthread worker;std::atomic<bool> cancel{false},busy{false},closing{false};HFONT font{};
std::atomic<std::shared_ptr<PendingApproval>> active;
constexpr UINT StatusMessage=WM_APP+1,FinishedMessage=WM_APP+2,RemoteMessage=WM_APP+3,TrayMessage=WM_APP+4;
void remoteStatus(const std::string& s){if(!closing)PostMessageW(window,RemoteMessage,0,reinterpret_cast<LPARAM>(new std::wstring(wide(s))));}
void startRemote(){remoteAgent.reset();if(config.contains("pairing")&&!closing){auto context=config;context["historyFile"]=utf8((stateDir/L"remote-history.jsonl").wstring());remoteAgent=std::make_unique<RemoteAgent>(context,remoteStatus,[]{return cameraAllowed.load()&&IsWindowVisible(window)&&!IsIconic(window)&&!closing;});}}
void status(const std::string& s){if(!closing)PostMessageW(window,StatusMessage,0,reinterpret_cast<LPARAM>(new std::wstring(wide(s))));}
void persist(){save(stateDir/L"windows-config.dpapi",config);}
Http relay(){return Http(config.at("relayUrl"),config.at("tlsPin"),config.at("transportToken"));}
void record(const std::string& id,const std::string& result){
  Json row{{"timestamp",epoch()},{"device",config.at("id")},{"authenticationResult",result},{"snapshotPath",nullptr},{"requestId",id}};
  std::ofstream out(stateDir/L"history.jsonl",std::ios::app);out<<row.dump()<<'\n';
  try{SigningKey key(config.at("id"));auto e=message("auth-event");e.update({{"requestId",id},{"pairingId",config.at("pairing").at("id")},{"result",result},{"timestamp",epoch()},{"snapshotPath",nullptr}});Json b{{"eventJws",key.sign(e)}};relay().call("POST","/v1/authentication-events",&b);}catch(...){/* local result remains authoritative */}
}
void pair(){
  if(config.contains("pairing"))throw std::runtime_error("Already paired");
  if(config.contains("revocationPending")){relay().call("DELETE","/v1/device-pairings/"+config.at("revocationPending").get<std::string>());config.erase("revocationPending");persist();}
  SigningKey key(config.at("id"));auto invitation=message("pair-invitation");auto session=uuid(),token=b64url(random(32));
  const auto created=epoch();invitation.update({{"sessionId",session},{"windowsDeviceId",config.at("id")},{"windowsName",config.at("name")},{"nonce",b64url(random(32))},{"issuedAt",created},{"expiresAt",created+300}});
  auto invitationJws=key.sign(invitation);Json body{{"invitationJws",invitationJws},{"tokenHash",hash(token)}};relay().call("POST","/v1/pairing-sessions",&body);
  auto path=stateDir/L"phone-invitation.json";Json bundle{{"relayUrl",config.at("relayUrl")},{"tlsPin",config.at("tlsPin")},{"caPem",config.at("caPem")},{"windowsJwk",key.jwk()},{"invitationJws",invitationJws},{"pairingToken",token}};write(path,bundle.dump(2));
  status("Import this invitation in Android:\n"+utf8(path.wstring())+"\nWaiting for phone pairing (5 minutes)…");
  try{
    auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(300);
    while(!cancel&&!closing&&std::chrono::steady_clock::now()<deadline){auto r=relay().call("GET","/v1/pairing-sessions/"+session);
      if(r.contains("proposalJws")){auto tokenJws=r.at("proposalJws").get<std::string>();auto untrusted=decode(tokenJws);auto p=verify(tokenJws,untrusted.at("approvalJwk"),"pair-proposal");publicJwk(p.at("identityJwk"));
        if(p.at("sessionId")!=session||p.at("windowsDeviceId")!=config.at("id")||p.at("invitationHash")!=hash(invitationJws)||p.size()!=11)throw std::runtime_error("Pairing mismatch");
        auto fingerprint=hash(invitationJws+"."+tokenJws).substr(0,16);for(auto& c:fingerprint)c=char(toupper(c));
        auto text=wide("Phone: "+p.at("phoneName").get<std::string>()+"\n\nCompare this code with the Android screen:\n"+fingerprint+"\n\nDo both codes match? Confirm only if you are pairing your own phone.");
        status("Pairing comparison: "+fingerprint);
        if(MessageBoxW(window,text.c_str(),L"Confirm pairing on both devices",MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2)!=IDYES||cancel||closing)break;
        auto receipt=message("pair-receipt");auto pairId=uuid();receipt.update({{"sessionId",session},{"pairingId",pairId},{"windowsDeviceId",config.at("id")},{"androidDeviceId",p.at("androidDeviceId")},{"proposalHash",hash(tokenJws)}});
        Json confirm{{"receiptJws",key.sign(receipt)}};relay().call("POST","/v1/pairing-sessions/"+session+"/confirmation",&confirm);
        config["pairing"]={{"id",pairId},{"androidDeviceId",p.at("androidDeviceId")},{"phoneName",p.at("phoneName")},{"approvalJwk",p.at("approvalJwk")},{"identityJwk",p.at("identityJwk")}};persist();status("Paired with "+p.at("phoneName").get<std::string>()+". Open Android to receive test requests.");std::filesystem::remove(path);return;
      }
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    status("Pairing cancelled or expired. Create a new invitation to try again.");
  }catch(...){std::filesystem::remove(path);throw;}std::filesystem::remove(path);
}
void requestApproval(){
  const auto pair=config.at("pairing");SigningKey key(config.at("id"));const auto id=uuid();auto challenge=message("auth-request");const auto issued=epoch();
  challenge.update({{"requestId",id},{"windowsDeviceId",config.at("id")},{"androidDeviceId",pair.at("androidDeviceId")},{"pairingId",pair.at("id")},{"accountBindingId",config.at("accountBindingId")},{"nonce",b64url(random(32))},{"issuedAt",issued},{"expiresAt",issued+60}});
  const auto token=key.sign(challenge);const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(60);auto pending=std::make_shared<PendingApproval>(challenge,token,pair,deadline);active.store(pending);Json body{{"requestJws",token}};
  try{
    relay().call("POST","/v1/authentication-requests",&body);status("Request sent to "+pair.at("phoneName").get<std::string>()+"\nWaiting for phone approval…");
    while(!cancel&&!closing&&std::chrono::steady_clock::now()<deadline&&epoch()<issued+60){auto r=relay().call("GET","/v1/authentication-requests/"+id);
      if(r.at("state")=="response_received"){
        const auto responseToken=r.at("responseJws").get<std::string>();
        if(cancel||closing||std::chrono::steady_clock::now()>=deadline||epoch()>=issued+60)break;
        const auto decision=pending->consume(responseToken);
        // This local pending request is consumed by returning; never persist/resume it.
        record(id,decision=="approve"?"approved":"denied");status(decision=="approve"?"Phone approval verified\nDesktop test complete. Windows sign-in is unchanged.":"Request denied");return;
      }
      if(r.at("state")=="cancelled")break;
      auto remaining=std::max<int64_t>(0,issued+60-epoch());status("Waiting for "+pair.at("phoneName").get<std::string>()+"… "+std::to_string(remaining)+" seconds\nCancel anytime. Windows PIN remains available.");
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    const std::string result=cancel||closing?"cancelled":"expired";record(id,result);status(result=="cancelled"?"Request cancelled":"Request expired. Use Windows PIN instead.");
    auto c=message("auth-cancel");c["requestId"]=id;Json b{{"cancelJws",key.sign(c)}};try{relay().call("POST","/v1/authentication-requests/"+id+"/cancel",&b);}catch(...){}
  }catch(...){record(id,"failed");throw;}
}
void unpair(){const auto id=config.at("pairing").at("id").get<std::string>();config.erase("pairing");config["revocationPending"]=id;persist();try{relay().call("DELETE","/v1/device-pairings/"+id);config.erase("revocationPending");persist();status("Phone unpaired. Create a new invitation to pair again.");}catch(...){status("Local trust removed. Relay revocation will retry before pairing again.");}}
void refresh(){EnableWindow(pairButton,!busy&&!config.contains("pairing"));EnableWindow(requestButton,!busy&&config.contains("pairing"));EnableWindow(unpairButton,!busy&&config.contains("pairing"));EnableWindow(cancelButton,busy);EnableWindow(powerCheck,!busy);EnableWindow(cameraCheck,!busy);}
void start(void(*operation)()){
  if(busy.exchange(true))return;remoteAgent.reset();if(worker.joinable())worker.join();cancel=false;refresh();
  worker=std::jthread([operation]{try{operation();}catch(...){status("Phone authentication failed. Check setup, TLS, relay and pairing.\nUse Windows PIN instead. No sign-in settings were changed.");}active.store(nullptr);PostMessageW(window,FinishedMessage,0,0);});
}
HWND control(const wchar_t* cls,const wchar_t* text,int x,int y,int w,int h,int id=0){auto child=CreateWindowW(cls,text,WS_CHILD|WS_VISIBLE|(std::wstring(cls)==L"BUTTON"?WS_TABSTOP:0),x,y,w,h,window,reinterpret_cast<HMENU>(INT_PTR(id)),GetModuleHandleW(nullptr),nullptr);SendMessageW(child,WM_SETFONT,reinterpret_cast<WPARAM>(font),TRUE);return child;}
LRESULT CALLBACK proc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp){switch(msg){
  case WM_CREATE:window=hwnd;font=CreateFontW(-18,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
    control(L"STATIC",L"WINDOWS-UNLOCK",28,24,600,32);control(L"STATIC",L"Secure phone approval and remote controls",28,65,600,28);
    control(L"STATIC",wide("Laptop: "+config.at("name").get<std::string>()).c_str(),28,112,600,28);
    statusLabel=control(L"STATIC",config.contains("pairing")?L"Ready. Open the Android app, then request approval.":L"Create an invitation, then import it on your Android phone.",28,160,660,118);
    pairButton=control(L"BUTTON",L"Pair phone",28,298,150,44,1);requestButton=control(L"BUTTON",L"Unlock with Phone (test)",190,298,250,44,2);cancelButton=control(L"BUTTON",L"Cancel",452,298,112,44,3);unpairButton=control(L"BUTTON",L"Unpair",576,298,100,44,4);
    powerCheck=control(L"BUTTON",L"Allow phone lock / sleep / shutdown / restart",28,364,640,28,5);SetWindowLongPtrW(powerCheck,GWL_STYLE,GetWindowLongPtrW(powerCheck,GWL_STYLE)|BS_AUTOCHECKBOX);
    cameraCheck=control(L"BUTTON",L"Allow live camera while this window is visible (60 seconds)",28,400,640,28,6);SetWindowLongPtrW(cameraCheck,GWL_STYLE,GetWindowLongPtrW(cameraCheck,GWL_STYLE)|BS_AUTOCHECKBOX);
    SendMessageW(powerCheck,BM_SETCHECK,config.value("remotePowerEnabled",false)?BST_CHECKED:BST_UNCHECKED,0);cameraAllowed=config.value("cameraSharingEnabled",false);SendMessageW(cameraCheck,BM_SETCHECK,cameraAllowed?BST_CHECKED:BST_UNCHECKED,0);
    remoteLabel=control(L"STATIC",L"Remote controls are opt-in. Camera sharing is off by default.",28,440,660,70);
    control(L"STATIC",L"Windows PIN/password remain available. Desktop approval does not sign in.\nClose minimizes to tray when paired. Right-click tray icon → Exit.",28,520,660,58);
    tray.cbSize=sizeof(tray);tray.hWnd=hwnd;tray.uID=1;tray.uFlags=NIF_MESSAGE|NIF_ICON|NIF_TIP;tray.uCallbackMessage=TrayMessage;tray.hIcon=LoadIconW(nullptr,IDI_SHIELD);wcscpy_s(tray.szTip,L"WINDOWS-UNLOCK • phone controls");Shell_NotifyIconW(NIM_ADD,&tray);refresh();startRemote();return 0;
  case WM_COMMAND:if(LOWORD(wp)==1)start(pair);if(LOWORD(wp)==2)start(requestApproval);if(LOWORD(wp)==3){cancel=true;if(auto p=active.load())p->cancel();}if(LOWORD(wp)==4&&MessageBoxW(hwnd,L"Remove trust in the paired phone?",L"Unpair phone",MB_YESNO|MB_DEFBUTTON2)==IDYES)start(unpair);
    if((LOWORD(wp)==5||LOWORD(wp)==6)&&!busy){const bool camera=LOWORD(wp)==6;HWND check=camera?cameraCheck:powerCheck;bool enabled=SendMessageW(check,BM_GETCHECK,0,0)==BST_CHECKED;
      if(enabled&&MessageBoxW(hwnd,camera?L"Your paired phone can request a live camera view after biometric authentication. Camera is used only while this window is visible and Windows is unlocked. Each session stops after 60 seconds. Minimize, close, or untick this setting to stop. No recording is stored.":L"Your paired phone can lock, sleep, shut down or restart this laptop after biometric authentication. Shutdown/restart can interrupt unsaved work. Enable?",L"Enable phone control",MB_YESNO|MB_DEFBUTTON2|MB_ICONQUESTION)!=IDYES){enabled=false;SendMessageW(check,BM_SETCHECK,BST_UNCHECKED,0);}
      if(camera)cameraAllowed=enabled;remoteAgent.reset();config[camera?"cameraSharingEnabled":"remotePowerEnabled"]=enabled;persist();startRemote();}
    if(LOWORD(wp)==7){closing=true;SendMessageW(hwnd,WM_CLOSE,0,0);}return 0;
  case StatusMessage:{auto text=reinterpret_cast<std::wstring*>(lp);SetWindowTextW(statusLabel,text->c_str());delete text;return 0;}
  case RemoteMessage:{auto text=reinterpret_cast<std::wstring*>(lp);SetWindowTextW(remoteLabel,text->c_str());delete text;return 0;}
  case TrayMessage:if(lp==WM_LBUTTONDBLCLK){ShowWindow(hwnd,SW_RESTORE);SetForegroundWindow(hwnd);}if(lp==WM_RBUTTONUP){POINT point;GetCursorPos(&point);HMENU menu=CreatePopupMenu();AppendMenuW(menu,MF_STRING,7,L"Exit WINDOWS-UNLOCK");SetForegroundWindow(hwnd);TrackPopupMenu(menu,TPM_RIGHTBUTTON,point.x,point.y,0,hwnd,nullptr);DestroyMenu(menu);}return 0;
  case FinishedMessage:if(worker.joinable())worker.join();busy=false;refresh();startRemote();return 0;
  case WM_CLOSE:if(!closing&&config.contains("pairing")&&!busy){ShowWindow(hwnd,SW_HIDE);return 0;}closing=true;cameraAllowed=false;remoteAgent.reset();cancel=true;if(auto p=active.load())p->cancel();if(worker.joinable())worker.join();DestroyWindow(hwnd);return 0;
  case WM_DESTROY:Shell_NotifyIconW(NIM_DELETE,&tray);if(font)DeleteObject(font);PostQuitMessage(0);return 0;
  default:return DefWindowProcW(hwnd,msg,wp,lp);}}
}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,PWSTR,int show){
  bool cli=false;
  CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
  try{int argc=0;auto argv=CommandLineToArgvW(GetCommandLineW(),&argc);std::vector<std::string> args;for(int i=1;i<argc;i++)args.push_back(utf8(argv[i]));LocalFree(argv);
    stateDir=std::filesystem::current_path()/L".runtime";
    for(size_t i=0;i<args.size();i++)if(args[i]=="--state"&&i+1<args.size()){stateDir=std::filesystem::absolute(wide(args[i+1]));args.erase(args.begin()+i,args.begin()+i+2);break;}
    cli=!args.empty();std::filesystem::create_directories(stateDir);auto file=stateDir/L"windows-config.dpapi";
    if(args.size()==4&&args[0]=="--init"){
      if(std::filesystem::exists(file))throw std::runtime_error("Configuration already exists");wchar_t host[256];DWORD n=256;GetComputerNameW(host,&n);auto id=uuid();SigningKey key(id,true);
      Json c{{"id",id},{"name",utf8(host)},{"accountBindingId",uuid()},{"relayUrl",args[1]},{"tlsPin",args[2]},{"caPem",read(wide(args[3]))}};Http(c.at("relayUrl"),c.at("tlsPin"),"");save(file,c);return 0;
    }
    config=load(file);SigningKey key(config.at("id"));
    if(args.size()==4&&args[0]=="--relay"){if(config.contains("pairing")||config.contains("revocationPending"))throw std::runtime_error("Unpair before changing relay");Http(args[1],args[2],"");config["relayUrl"]=args[1];config["tlsPin"]=args[2];config["caPem"]=read(wide(args[3]));config.erase("transportToken");persist();return 0;}
    if(args.size()==2&&args[0]=="--public"){write(wide(args[1]),Json{{"id",config.at("id")},{"name",config.at("name")},{"jwk",key.jwk()}}.dump(2));return 0;}
    if(args.size()==2&&args[0]=="--configure"){auto b=parse(read(wide(args[1])));auto token=b.at("transportToken").get<std::string>();if(unb64url(token).size()!=32)throw std::runtime_error("Invalid transport token");config["transportToken"]=token;persist();return 0;}
    if(args.size()==1&&args[0]=="--health"){relay().call("GET","/health");return 0;}
    if(!args.empty())throw std::runtime_error("Unknown arguments");
    WNDCLASSW wc{};wc.lpfnWndProc=proc;wc.hInstance=instance;wc.lpszClassName=L"PhoneUnlockDesktop";wc.hCursor=LoadCursor(nullptr,IDC_ARROW);wc.hbrBackground=reinterpret_cast<HBRUSH>(COLOR_WINDOW+1);RegisterClassW(&wc);
    auto h=CreateWindowW(wc.lpszClassName,L"WINDOWS-UNLOCK for Windows 11",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,CW_USEDEFAULT,CW_USEDEFAULT,740,660,nullptr,nullptr,instance,nullptr);if(!h)throw std::runtime_error("Window unavailable");ShowWindow(h,show);MSG msg;while(GetMessageW(&msg,nullptr,0,0)>0){if(!IsDialogMessageW(h,&msg)){TranslateMessage(&msg);DispatchMessageW(&msg);}}return 0;
  }catch(...){if(!cli)MessageBoxW(nullptr,L"Setup or operation failed. Follow docs/setup.md.\nWindows PIN and password remain unchanged.",L"WINDOWS-UNLOCK",MB_OK|MB_ICONERROR);return 1;}
}
