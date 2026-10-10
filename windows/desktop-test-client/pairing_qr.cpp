#include "pairing_qr.hpp"
#include "qrcodegen.hpp"
#include <algorithm>
#include <ctime>
#include <memory>

namespace {
constexpr wchar_t QrClass[]=L"WindowsUnlockPairingQr";
HWND qrWindow{};
struct QrView { qrcodegen::QrCode code; int64_t expiresAt; bool owned{false}; };
LRESULT CALLBACK qrProc(HWND window,UINT message,WPARAM wp,LPARAM lp){
  auto view=reinterpret_cast<QrView*>(GetWindowLongPtrW(window,GWLP_USERDATA));
  if(message==WM_NCCREATE){view=reinterpret_cast<QrView*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);SetWindowLongPtrW(window,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(view));}
  if(message==WM_CREATE){SetTimer(window,1,1000,nullptr);return 0;}
  if(message==WM_TIMER&&view){if(std::time(nullptr)>=view->expiresAt)DestroyWindow(window);else InvalidateRect(window,nullptr,FALSE);return 0;}
  if(message==WM_PAINT&&view){
    PAINTSTRUCT paint{};auto dc=BeginPaint(window,&paint);RECT client{};GetClientRect(window,&client);FillRect(dc,&client,GetSysColorBrush(COLOR_WINDOW));
    SetBkMode(dc,TRANSPARENT);SetTextColor(dc,RGB(20,35,27));SelectObject(dc,GetStockObject(DEFAULT_GUI_FONT));
    RECT heading{16,16,client.right-16,54};DrawTextW(dc,L"Open WINDOWS-UNLOCK on your phone\nTap Scan laptop QR code",-1,&heading,DT_CENTER|DT_WORDBREAK);
    const int modules=view->code.getSize(),border=4;
    const int scale=std::max<int>(1,int(std::min(client.right-32,client.bottom-146))/(modules+border*2));
    const int side=(modules+border*2)*scale,left=(client.right-side)/2,top=66;
    RECT square{left,top,left+side,top+side};FillRect(dc,&square,static_cast<HBRUSH>(GetStockObject(WHITE_BRUSH)));
    auto black=static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    for(int y=0;y<modules;y++)for(int x=0;x<modules;x++)if(view->code.getModule(x,y)){RECT cell{left+(x+border)*scale,top+(y+border)*scale,left+(x+border+1)*scale,top+(y+border+1)*scale};FillRect(dc,&cell,black);}
    wchar_t countdown[160]{};swprintf_s(countdown,L"Expires in %lld seconds\nCompare and confirm the same code on both devices.",std::max<int64_t>(0,view->expiresAt-std::time(nullptr)));
    RECT footer{16,top+side+12,client.right-16,client.bottom-8};DrawTextW(dc,countdown,-1,&footer,DT_CENTER|DT_WORDBREAK);EndPaint(window,&paint);return 0;
  }
  if(message==WM_CLOSE){DestroyWindow(window);return 0;}
  if(message==WM_NCDESTROY){KillTimer(window,1);SetWindowLongPtrW(window,GWLP_USERDATA,0);if(view&&view->owned)delete view;if(qrWindow==window)qrWindow=nullptr;}
  return DefWindowProcW(window,message,wp,lp);
}
}
void closePairingQr(){if(qrWindow)DestroyWindow(qrWindow);}
bool showPairingQr(HWND owner,const PairingQrPayload& payload){
  closePairingQr();if(std::time(nullptr)>=payload.expiresAt)return false;
  try{
    auto view=std::make_unique<QrView>(QrView{qrcodegen::QrCode::encodeText(payload.invitation.c_str(),qrcodegen::QrCode::Ecc::MEDIUM),payload.expiresAt});
    WNDCLASSW cls{};cls.hInstance=GetModuleHandleW(nullptr);cls.lpszClassName=QrClass;cls.lpfnWndProc=qrProc;cls.hCursor=LoadCursorW(nullptr,IDC_ARROW);
    if(!RegisterClassW(&cls)&&GetLastError()!=ERROR_CLASS_ALREADY_EXISTS)return false;
    RECT area{};SystemParametersInfoW(SPI_GETWORKAREA,0,&area,0);const int width=std::min<int>(650,area.right-area.left-32),height=std::min<int>(width+120,area.bottom-area.top-32);
    qrWindow=CreateWindowExW(WS_EX_TOOLWINDOW,QrClass,L"Pair your phone - scan QR code",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU,
      area.left+(area.right-area.left-width)/2,area.top+(area.bottom-area.top-height)/2,width,height,owner,nullptr,cls.hInstance,view.get());
    if(!qrWindow)return false;view->owned=true;view.release();ShowWindow(qrWindow,SW_SHOWNORMAL);SetForegroundWindow(qrWindow);return true;
  }catch(...){return false;}
}
