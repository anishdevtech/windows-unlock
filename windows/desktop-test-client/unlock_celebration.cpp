#include "unlock_celebration.hpp"
#include <objidl.h>
#include <gdiplus.h>
#include <algorithm>
#include <cmath>
using namespace Gdiplus;
namespace {
constexpr int Width=480,Height=340;
HWND popup{};ULONGLONG began{};bool demo{},motion{};ULONG_PTR token{};
bool initialize(){if(token)return true;GdiplusStartupInput input;return GdiplusStartup(&token,&input,nullptr)==Ok;}
float clamp(float t){return std::clamp(t,0.f,1.f);}
float ease(float t){return 1-std::pow(1-clamp(t),3.f);}
Color color(int alpha,int r,int g,int b){return Color(BYTE(std::clamp(alpha,0,255)),BYTE(r),BYTE(g),BYTE(b));}
void rounded(GraphicsPath& path,float x,float y,float w,float h,float r){path.AddArc(x,y,r*2,r*2,180,90);path.AddArc(x+w-r*2,y,r*2,r*2,270,90);path.AddArc(x+w-r*2,y+h-r*2,r*2,r*2,0,90);path.AddArc(x,y+h-r*2,r*2,r*2,90,90);path.CloseFigure();}
void draw(Graphics& g,float seconds,bool preview,bool animate){
  g.SetSmoothingMode(SmoothingModeAntiAlias);g.SetTextRenderingHint(TextRenderingHintAntiAliasGridFit);g.Clear(Color(0,0,0,0));
  float enter=animate?ease(seconds/.45f):1;float leave=animate?1-ease((seconds-2.1f)/.45f):1;int alpha=int(255*enter*leave);float lift=(1-enter)*22;
  g.TranslateTransform(0,lift);
  for(int i=18;i>0;--i){GraphicsPath shadow;rounded(shadow,30.f-i,26.f-i,420.f+i*2,280.f+i*2,28.f+float(i));SolidBrush brush(color(int(alpha*.0007f*(19-i)),24,185,160));g.FillPath(&brush,&shadow);}
  GraphicsPath card;rounded(card,30,26,420,280,28);LinearGradientBrush fill(Point(30,26),Point(450,306),color(alpha,20,34,49),color(alpha,10,17,28));g.FillPath(&fill,&card);Pen border(color(alpha/3,93,224,205),1);g.DrawPath(&border,&card);
  const float cx=240,cy=133;float ring=animate?ease((seconds-.12f)/.7f):1;
  for(int i=12;i>0;--i){Pen glow(color(int(alpha*.012f*(13-i)),50,231,184),float(i*2));g.DrawArc(&glow,cx-49,cy-49,98.f,98.f,-90.f,360.f*ring);}
  SolidBrush disc(color(alpha,20,55,58));g.FillEllipse(&disc,cx-43,cy-43,86.f,86.f);
  Pen track(color(alpha/5,100,231,213),2);g.DrawEllipse(&track,cx-49,cy-49,98.f,98.f);
  Pen circle(color(alpha,76,238,190),3);circle.SetStartCap(LineCapRound);circle.SetEndCap(LineCapRound);g.DrawArc(&circle,cx-49,cy-49,98.f,98.f,-90.f,360.f*ring);
  float tick=animate?ease((seconds-.45f)/.42f):1;PointF a(cx-19,cy),b(cx-4,cy+15),c(cx+23,cy-15);Pen check(color(alpha,159,255,221),5);check.SetStartCap(LineCapRound);check.SetEndCap(LineCapRound);check.SetLineJoin(LineJoinRound);
  if(tick<=.4f)g.DrawLine(&check,a,PointF(a.X+(b.X-a.X)*tick/.4f,a.Y+(b.Y-a.Y)*tick/.4f));else {g.DrawLine(&check,a,b);float p=(tick-.4f)/.6f;g.DrawLine(&check,b,PointF(b.X+(c.X-b.X)*p,b.Y+(c.Y-b.Y)*p));}
  if(animate){for(int i=0;i<14;i++){float angle=float(i)*6.2831853f/14;float p=clamp((seconds-.4f)/1.3f);float distance=65+55*ease(p);SolidBrush sparkle(color(int(alpha*(1-p)*.8f),100,244,212));float size=2+float(i%3);g.FillEllipse(&sparkle,cx+std::cos(angle)*distance-size/2,cy+std::sin(angle)*distance-size/2,size,size);}}
  FontFamily family(L"Segoe UI");Font label(&family,10,FontStyleBold,UnitPixel),title(&family,29,FontStyleBold,UnitPixel),subtitle(&family,14,FontStyleRegular,UnitPixel);StringFormat centered;centered.SetAlignment(StringAlignmentCenter);centered.SetLineAlignment(StringAlignmentCenter);
  SolidBrush muted(color(alpha,136,163,183)),white(color(alpha,235,247,250)),mint(color(alpha,109,238,204));
  g.DrawString(L"W I N D O W S   U N L O C K",-1,&label,RectF(40,43,400,20),&centered,&mint);
  g.DrawString(preview?L"Animation preview":L"Welcome back",-1,&title,RectF(40,202,400,43),&centered,&white);
  g.DrawString(preview?L"Preview only · no sign-in performed":L"Unlocked with your phone",-1,&subtitle,RectF(40,250,400,25),&centered,&muted);
}
void frame(HWND hwnd){
  float elapsed=float(GetTickCount64()-began)/1000.f;
  if(elapsed> (motion?2.6f:1.4f)){DestroyWindow(hwnd);return;}
  HDC screen=GetDC(nullptr),memory=CreateCompatibleDC(screen);BITMAPINFO info{};info.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);info.bmiHeader.biWidth=Width;info.bmiHeader.biHeight=-Height;info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=32;void* pixels{};HBITMAP bitmap=CreateDIBSection(screen,&info,DIB_RGB_COLORS,&pixels,nullptr,0);
  if(!bitmap||!pixels){if(bitmap)DeleteObject(bitmap);DeleteDC(memory);ReleaseDC(nullptr,screen);DestroyWindow(hwnd);return;}
  auto previous=SelectObject(memory,bitmap);
  {Bitmap canvas(Width,Height,Width*4,PixelFormat32bppPARGB,static_cast<BYTE*>(pixels));Graphics g(&canvas);draw(g,elapsed,demo,motion);}
  RECT rect{};GetWindowRect(hwnd,&rect);POINT position{rect.left,rect.top},origin{};SIZE size{Width,Height};BLENDFUNCTION blend{AC_SRC_OVER,0,255,AC_SRC_ALPHA};UpdateLayeredWindow(hwnd,screen,&position,&size,memory,&origin,0,&blend,ULW_ALPHA);
  SelectObject(memory,previous);DeleteObject(bitmap);DeleteDC(memory);ReleaseDC(nullptr,screen);
}
LRESULT CALLBACK procedure(HWND h,UINT m,WPARAM w,LPARAM l){if(m==WM_TIMER){frame(h);return 0;}if(m==WM_NCHITTEST)return HTTRANSPARENT;if(m==WM_DESTROY){KillTimer(h,1);popup=nullptr;return 0;}return DefWindowProcW(h,m,w,l);}
}
void closeUnlockCelebration(){if(popup)DestroyWindow(popup);}
void showUnlockCelebration(bool preview){
  if(!initialize())return;closeUnlockCelebration();demo=preview;BOOL animations=TRUE;SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION,0,&animations,0);motion=animations!=FALSE;began=GetTickCount64();
  WNDCLASSW c{};c.hInstance=GetModuleHandleW(nullptr);c.lpfnWndProc=procedure;c.lpszClassName=L"WindowsUnlockCelebration";RegisterClassW(&c);
  POINT cursor{};GetCursorPos(&cursor);MONITORINFO monitor{sizeof(monitor)};GetMonitorInfoW(MonitorFromPoint(cursor,MONITOR_DEFAULTTOPRIMARY),&monitor);auto r=monitor.rcWork;
  popup=CreateWindowExW(WS_EX_LAYERED|WS_EX_NOACTIVATE|WS_EX_TOOLWINDOW|WS_EX_TOPMOST|WS_EX_TRANSPARENT,c.lpszClassName,L"WINDOWS UNLOCK celebration",WS_POPUP,(r.left+r.right-Width)/2,(r.top+r.bottom-Height)/2,Width,Height,nullptr,nullptr,c.hInstance,nullptr);
  if(popup){frame(popup);ShowWindow(popup,SW_SHOWNOACTIVATE);SetTimer(popup,1,16,nullptr);}
}
bool renderUnlockCelebrationPreview(const std::filesystem::path& path){
  if(!initialize())return false;Bitmap image(Width,Height,PixelFormat32bppPARGB);{Graphics g(&image);draw(g,1.15f,false,true);}UINT count{},bytes{};GetImageEncodersSize(&count,&bytes);std::vector<BYTE> storage(bytes);auto encoders=reinterpret_cast<ImageCodecInfo*>(storage.data());GetImageEncoders(count,bytes,encoders);for(UINT i=0;i<count;i++)if(wcscmp(encoders[i].MimeType,L"image/png")==0)return image.Save(path.c_str(),&encoders[i].Clsid,nullptr)==Ok;return false;
}
