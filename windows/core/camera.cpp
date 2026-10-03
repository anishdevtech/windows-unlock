#include "camera.hpp"
#include <mfapi.h>
#include <mfidl.h>
#include <mfreadwrite.h>
#include <wincodec.h>
#include <wrl/client.h>
#include <condition_variable>
#include <mutex>
#include <stdexcept>
#include <thread>
using Microsoft::WRL::ComPtr;
namespace pu {
namespace {
void check(HRESULT h){if(FAILED(h))throw std::runtime_error("Camera unavailable, busy or disabled in Windows privacy settings");}
class Samples final:public IMFSourceReaderCallback {
  std::atomic<ULONG> refs{1};
public:
  std::mutex mutex;std::condition_variable ready;ComPtr<IMFSample> sample;HRESULT error=S_OK;bool received=false;
  STDMETHODIMP QueryInterface(REFIID id,void** out)override{if(!out)return E_POINTER;if(id==__uuidof(IUnknown)||id==__uuidof(IMFSourceReaderCallback)){*out=static_cast<IMFSourceReaderCallback*>(this);AddRef();return S_OK;}*out=nullptr;return E_NOINTERFACE;}
  STDMETHODIMP_(ULONG) AddRef()override{return ++refs;}STDMETHODIMP_(ULONG) Release()override{auto r=--refs;if(!r)delete this;return r;}
  STDMETHODIMP OnReadSample(HRESULT h,DWORD,DWORD flags,LONGLONG,IMFSample* s)override{std::lock_guard lock(mutex);error=(flags&MF_SOURCE_READERF_ENDOFSTREAM)?E_FAIL:h;sample=s;received=true;ready.notify_all();return S_OK;}
  STDMETHODIMP OnEvent(DWORD,IMFMediaEvent*)override{return S_OK;}STDMETHODIMP OnFlush(DWORD)override{return S_OK;}
};
}
struct Camera::Impl {
  ComPtr<IMFMediaSource> source;ComPtr<IMFSourceReader> reader;ComPtr<Samples> callback;UINT32 width{},height{};LONG stride{};std::jthread watchdog;
  Impl(std::chrono::steady_clock::time_point deadline,std::function<bool()> permitted){
    check(MFStartup(MF_VERSION));
    try { initialize(); }catch(...){if(source)source->Shutdown();reader.Reset();source.Reset();MFShutdown();throw;}
    watchdog=std::jthread([this,deadline,permitted=std::move(permitted)](std::stop_token stop){
      CoInitializeEx(nullptr,COINIT_MULTITHREADED);
      while(!stop.stop_requested()&&std::chrono::steady_clock::now()<deadline&&permitted())std::this_thread::sleep_for(std::chrono::milliseconds(100));
      if(!stop.stop_requested())source->Shutdown();CoUninitialize();
    });
  }
  void initialize(){
    ComPtr<IMFAttributes> attributes;check(MFCreateAttributes(&attributes,2));check(attributes->SetGUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID));
    IMFActivate** devices=nullptr;UINT32 count=0;check(MFEnumDeviceSources(attributes.Get(),&devices,&count));HRESULT result=count?devices[0]->ActivateObject(IID_PPV_ARGS(&source)):E_FAIL;
    for(UINT32 i=0;i<count;i++)devices[i]->Release();CoTaskMemFree(devices);check(result);
    callback.Attach(new Samples());check(MFCreateAttributes(&attributes,3));check(attributes->SetUnknown(MF_SOURCE_READER_ASYNC_CALLBACK,callback.Get()));check(attributes->SetUINT32(MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING,TRUE));check(MFCreateSourceReaderFromMediaSource(source.Get(),attributes.Get(),&reader));
    ComPtr<IMFMediaType> type;check(MFCreateMediaType(&type));check(type->SetGUID(MF_MT_MAJOR_TYPE,MFMediaType_Video));check(type->SetGUID(MF_MT_SUBTYPE,MFVideoFormat_RGB32));check(reader->SetCurrentMediaType(MF_SOURCE_READER_FIRST_VIDEO_STREAM,nullptr,type.Get()));check(reader->GetCurrentMediaType(MF_SOURCE_READER_FIRST_VIDEO_STREAM,&type));check(MFGetAttributeSize(type.Get(),MF_MT_FRAME_SIZE,&width,&height));
    if(!width||!height||uint64_t(width)*height>4096ULL*2160)throw std::runtime_error("Camera resolution unsupported");UINT32 rawStride=0;if(SUCCEEDED(type->GetUINT32(MF_MT_DEFAULT_STRIDE,&rawStride)))stride=LONG(rawStride);else stride=LONG(width*4);
  }
  ~Impl(){watchdog.request_stop();if(watchdog.joinable())watchdog.join();if(reader)reader->Flush(DWORD(MF_SOURCE_READER_ALL_STREAMS));if(source)source->Shutdown();reader.Reset();source.Reset();MFShutdown();}
  Bytes frame(){
    {std::lock_guard lock(callback->mutex);callback->received=false;callback->sample.Reset();}
    check(reader->ReadSample(MF_SOURCE_READER_FIRST_VIDEO_STREAM,0,nullptr,nullptr,nullptr,nullptr));
    ComPtr<IMFSample> sample;{std::unique_lock lock(callback->mutex);if(!callback->ready.wait_for(lock,std::chrono::seconds(3),[&]{return callback->received;}))throw std::runtime_error("Camera timed out");check(callback->error);sample=callback->sample;}
    if(!sample)throw std::runtime_error("No camera frame");ComPtr<IMFMediaBuffer> buffer;check(sample->ConvertToContiguousBuffer(&buffer));BYTE* data=nullptr;DWORD length=0;check(buffer->Lock(&data,nullptr,&length));
    Bytes pixels(size_t(width)*height*4);const auto pitch=size_t(stride<0?-stride:stride);
    if(pitch<width*4||length<pitch*(height-1)+width*4){buffer->Unlock();throw std::runtime_error("Invalid camera buffer");}
    for(UINT32 y=0;y<height;y++)memcpy(pixels.data()+size_t(y)*width*4,data+size_t(stride<0?height-1-y:y)*pitch,size_t(width)*4);buffer->Unlock();
    ComPtr<IWICImagingFactory> factory;check(CoCreateInstance(CLSID_WICImagingFactory,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&factory)));ComPtr<IWICBitmap> bitmap;check(factory->CreateBitmapFromMemory(width,height,GUID_WICPixelFormat32bppBGR,width*4,UINT(pixels.size()),pixels.data(),&bitmap));
    ComPtr<IWICBitmapScaler> scaled;check(factory->CreateBitmapScaler(&scaled));check(scaled->Initialize(bitmap.Get(),320,240,WICBitmapInterpolationModeFant));ComPtr<IWICFormatConverter> converted;check(factory->CreateFormatConverter(&converted));check(converted->Initialize(scaled.Get(),GUID_WICPixelFormat24bppBGR,WICBitmapDitherTypeNone,nullptr,0,WICBitmapPaletteTypeCustom));
    ComPtr<IStream> stream;check(CreateStreamOnHGlobal(nullptr,TRUE,&stream));ComPtr<IWICBitmapEncoder> encoder;check(factory->CreateEncoder(GUID_ContainerFormatJpeg,nullptr,&encoder));check(encoder->Initialize(stream.Get(),WICBitmapEncoderNoCache));ComPtr<IWICBitmapFrameEncode> frame;ComPtr<IPropertyBag2> options;check(encoder->CreateNewFrame(&frame,&options));PROPBAG2 property{};property.pstrName=const_cast<LPOLESTR>(L"ImageQuality");VARIANT quality{};quality.vt=VT_R4;quality.fltVal=.6f;check(options->Write(1,&property,&quality));check(frame->Initialize(options.Get()));check(frame->SetSize(320,240));WICPixelFormatGUID format=GUID_WICPixelFormat24bppBGR;check(frame->SetPixelFormat(&format));check(frame->WriteSource(converted.Get(),nullptr));check(frame->Commit());check(encoder->Commit());STATSTG stat{};check(stream->Stat(&stat,STATFLAG_NONAME));if(stat.cbSize.QuadPart>45000)throw std::runtime_error("Camera frame too large");LARGE_INTEGER zero{};check(stream->Seek(zero,STREAM_SEEK_SET,nullptr));Bytes jpeg(size_t(stat.cbSize.QuadPart));ULONG read=0;check(stream->Read(jpeg.data(),ULONG(jpeg.size()),&read));if(read!=jpeg.size())throw std::runtime_error("Incomplete camera frame");return jpeg;
  }
};
Camera::Camera(std::chrono::steady_clock::time_point deadline,std::function<bool()> permitted):impl_(std::make_unique<Impl>(deadline,std::move(permitted))){}Camera::~Camera()=default;Bytes Camera::frame(){return impl_->frame();}
}
