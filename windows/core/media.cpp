#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "media.hpp"
#include "camera.hpp"
#include "remote.hpp"
#include <mmsystem.h>
#include <bcrypt.h>
#include <objbase.h>
#include <array>
#include <mutex>
#include <algorithm>
#include <map>
namespace pu {
Bytes mediaKey(const Bytes& master,const std::string& direction){return sha256("windows-unlock-media-v1:"+direction+":"+b64url(master));}
Bytes decryptMediaPacket(const Bytes& key,const Json& packet,const std::string& session){
  auto iv=unb64url(packet.at("iv")),cipher=unb64url(packet.at("ciphertext"));
  if(key.size()!=32||iv.size()!=12||cipher.size()<17||cipher.size()>45016)throw std::runtime_error("Invalid media packet");
  BCRYPT_ALG_HANDLE alg{};BCRYPT_KEY_HANDLE handle{};
  struct Clean{BCRYPT_ALG_HANDLE& a;BCRYPT_KEY_HANDLE& k;~Clean(){if(k)BCryptDestroyKey(k);if(a)BCryptCloseAlgorithmProvider(a,0);}} clean{alg,handle};
  auto check=[](NTSTATUS s){if(s<0)throw std::runtime_error("Media authentication failed");};
  check(BCryptOpenAlgorithmProvider(&alg,BCRYPT_AES_ALGORITHM,nullptr,0));check(BCryptSetProperty(alg,BCRYPT_CHAINING_MODE,reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),sizeof(BCRYPT_CHAIN_MODE_GCM),0));
  check(BCryptGenerateSymmetricKey(alg,&handle,nullptr,0,const_cast<PUCHAR>(key.data()),ULONG(key.size()),0));
  const auto aad=session+":"+std::to_string(packet.at("sequence").get<uint64_t>());BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;BCRYPT_INIT_AUTH_MODE_INFO(info);
  info.pbNonce=iv.data();info.cbNonce=ULONG(iv.size());info.pbTag=cipher.data()+cipher.size()-16;info.cbTag=16;info.pbAuthData=reinterpret_cast<PUCHAR>(const_cast<char*>(aad.data()));info.cbAuthData=ULONG(aad.size());
  Bytes plain(cipher.size()-16);ULONG n{};check(BCryptDecrypt(handle,cipher.data(),ULONG(cipher.size()-16),&info,nullptr,0,plain.data(),ULONG(plain.size()),&n,0));plain.resize(n);return plain;
}
namespace {
constexpr size_t Chunk=1100,Header=16,MaxMessage=65536;
bool privateAddress(uint32_t ip){ip=ntohl(ip);return (ip>>24)==10||(ip>>20)==0xac1||(ip>>16)==0xc0a8;}
Json addresses(){
  ULONG size=16000;Bytes buffer(size);auto* adapters=reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
  auto result=GetAdaptersAddresses(AF_INET,GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST|GAA_FLAG_SKIP_DNS_SERVER,nullptr,adapters,&size);
  if(result==ERROR_BUFFER_OVERFLOW){buffer.resize(size);adapters=reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());result=GetAdaptersAddresses(AF_INET,GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST|GAA_FLAG_SKIP_DNS_SERVER,nullptr,adapters,&size);}
  Json list=Json::array();if(result==NO_ERROR)for(auto* a=adapters;a;a=a->Next)if(a->OperStatus==IfOperStatusUp)for(auto* p=a->FirstUnicastAddress;p;p=p->Next){auto* ip=reinterpret_cast<sockaddr_in*>(p->Address.lpSockaddr);if(privateAddress(ip->sin_addr.s_addr)&&list.size()<8){char text[INET_ADDRSTRLEN]{};inet_ntop(AF_INET,&ip->sin_addr,text,sizeof(text));if(std::find(list.begin(),list.end(),text)==list.end())list.push_back(text);}}
  return list;
}
void audioCheck(MMRESULT r){if(r!=MMSYSERR_NOERROR)throw std::runtime_error("Audio unavailable. Check Windows microphone privacy and default audio device.");}
struct Audio {
  HWAVEIN input{};HWAVEOUT output{};std::array<WAVEHDR,8> headers{};std::array<Bytes,8> buffers;size_t chunk{},cursor{};
  Audio(bool capture){
    WAVEFORMATEX format{};format.wFormatTag=WAVE_FORMAT_PCM;format.nChannels=capture?1:2;format.nSamplesPerSec=capture?16000:48000;format.wBitsPerSample=16;format.nBlockAlign=format.nChannels*2;format.nAvgBytesPerSec=format.nSamplesPerSec*format.nBlockAlign;chunk=format.nAvgBytesPerSec/50;
    try{if(capture){audioCheck(waveInOpen(&input,WAVE_MAPPER,&format,0,0,CALLBACK_NULL));for(size_t i=0;i<headers.size();i++){buffers[i].resize(chunk);headers[i].lpData=reinterpret_cast<LPSTR>(buffers[i].data());headers[i].dwBufferLength=DWORD(chunk);audioCheck(waveInPrepareHeader(input,&headers[i],sizeof(WAVEHDR)));audioCheck(waveInAddBuffer(input,&headers[i],sizeof(WAVEHDR)));}audioCheck(waveInStart(input));}
    else {audioCheck(waveOutOpen(&output,WAVE_MAPPER,&format,0,0,CALLBACK_NULL));for(size_t i=0;i<headers.size();i++){buffers[i].resize(chunk);headers[i].lpData=reinterpret_cast<LPSTR>(buffers[i].data());headers[i].dwBufferLength=DWORD(chunk);audioCheck(waveOutPrepareHeader(output,&headers[i],sizeof(WAVEHDR)));}}}catch(...){close();throw;}
  }
  void close(){if(input){waveInReset(input);for(auto& h:headers)if(h.dwFlags&WHDR_PREPARED)waveInUnprepareHeader(input,&h,sizeof(h));waveInClose(input);input=nullptr;}if(output){waveOutReset(output);for(auto& h:headers)if(h.dwFlags&WHDR_PREPARED)waveOutUnprepareHeader(output,&h,sizeof(h));waveOutClose(output);output=nullptr;}}
  ~Audio(){close();}
  std::vector<Bytes> read(){std::vector<Bytes> out;for(size_t i=0;i<headers.size();i++){auto& h=headers[cursor];if(!(h.dwFlags&WHDR_DONE))break;if(h.dwBytesRecorded==chunk)out.emplace_back(reinterpret_cast<unsigned char*>(h.lpData),reinterpret_cast<unsigned char*>(h.lpData)+h.dwBytesRecorded);h.dwBytesRecorded=0;audioCheck(waveInAddBuffer(input,&h,sizeof(h)));cursor=(cursor+1)%headers.size();}if(out.size()>4)out.erase(out.begin(),out.end()-4);return out;}
  void play(const Bytes& bytes){if(bytes.size()!=chunk)return;unsigned queued=0;for(auto& h:headers)if(h.dwFlags&WHDR_INQUEUE)queued++;if(queued>=4)return;for(auto& h:headers)if(!(h.dwFlags&WHDR_INQUEUE)){memcpy(h.lpData,bytes.data(),bytes.size());audioCheck(waveOutWrite(output,&h,sizeof(h)));return;}}
};
}
struct DirectMedia::Impl {
  SOCKET socket=INVALID_SOCKET;WSADATA wsa{};Json endpoint;std::string id,mode;Bytes up,down;std::function<bool()> permitted;std::jthread thread;std::atomic<bool> peerReady{false},alive{true};std::mutex mutex;Bytes latest;
  Impl(std::string session,std::string kind,Bytes key,std::function<bool()> allowed):id(std::move(session)),mode(std::move(kind)),up(mediaKey(key,"up")),down(mediaKey(key,"down")),permitted(std::move(allowed)){
    SecureZeroMemory(key.data(),key.size());if(WSAStartup(MAKEWORD(2,2),&wsa))throw std::runtime_error("LAN unavailable");
    try{socket=::socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);if(socket==INVALID_SOCKET)throw std::runtime_error("LAN unavailable");sockaddr_in local{};local.sin_family=AF_INET;local.sin_addr.s_addr=INADDR_ANY;local.sin_port=0;if(bind(socket,reinterpret_cast<sockaddr*>(&local),sizeof(local)))throw std::runtime_error("LAN bind failed");int length=sizeof(local);getsockname(socket,reinterpret_cast<sockaddr*>(&local),&length);u_long nonblocking=1;ioctlsocket(socket,FIONBIO,&nonblocking);int capacity=512*1024;setsockopt(socket,SOL_SOCKET,SO_RCVBUF,reinterpret_cast<char*>(&capacity),sizeof(capacity));setsockopt(socket,SOL_SOCKET,SO_SNDBUF,reinterpret_cast<char*>(&capacity),sizeof(capacity));
      endpoint={{"protocol","udp-aesgcm-v1"},{"addresses",addresses()},{"port",ntohs(local.sin_port)},{"sampleRate",mode=="audio-speaker-start"?48000:16000},{"channels",mode=="audio-speaker-start"?2:1},{"packetMs",20},{"maxFps",15}};
      thread=std::jthread([this](std::stop_token stop){run(stop);});
    }catch(...){if(socket!=INVALID_SOCKET)closesocket(socket);WSACleanup();throw;}
  }
  ~Impl(){thread.request_stop();if(thread.joinable())thread.join();closesocket(socket);WSACleanup();SecureZeroMemory(up.data(),up.size());SecureZeroMemory(down.data(),down.size());}
  void run(std::stop_token stop){
    CoInitializeEx(nullptr,COINIT_MULTITHREADED);sockaddr_in peer{};uint64_t sent=0,received=0;auto began=std::chrono::steady_clock::now(),lastHello=began,nextFrame=began;std::unique_ptr<Camera> camera;std::unique_ptr<Audio> audio;bool cameraFast=false;
    struct Assembly{uint64_t sequence{};uint16_t count{};std::map<uint16_t,Bytes> parts;std::chrono::steady_clock::time_point time;};Assembly assembly;
    auto send=[&](unsigned char type,const Bytes& payload){if(!peerReady)return;Bytes plain{type};plain.insert(plain.end(),payload.begin(),payload.end());auto body=encryptCameraFrame(down,plain,id+":down",++sent,{});body.erase("wrappedKey");auto message=body.dump();const auto count=(message.size()+Chunk-1)/Chunk;if(count>60)return;
      for(size_t i=0;i<count;i++){Bytes packet(Header+std::min(Chunk,message.size()-i*Chunk));memcpy(packet.data(),"WUM1",4);for(unsigned b=0;b<8;b++)packet[4+b]=static_cast<unsigned char>(sent>>(56-8*b));packet[12]=static_cast<unsigned char>(i>>8);packet[13]=static_cast<unsigned char>(i);packet[14]=static_cast<unsigned char>(count>>8);packet[15]=static_cast<unsigned char>(count);memcpy(packet.data()+Header,message.data()+i*Chunk,packet.size()-Header);sendto(socket,reinterpret_cast<char*>(packet.data()),int(packet.size()),0,reinterpret_cast<sockaddr*>(&peer),sizeof(peer));}};
    try{while(!stop.stop_requested()&&permitted()&&std::chrono::steady_clock::now()-began<std::chrono::seconds(mode=="camera-start"?60:600)){
      auto now=std::chrono::steady_clock::now();if(peerReady&&now-lastHello>std::chrono::seconds(3))break;if(!peerReady&&mode!="camera-start"&&now-began>std::chrono::seconds(15))break;
      // Bound per-tick work and assembly memory even when unauthenticated traffic arrives.
      for(unsigned attempt=0;attempt<64;attempt++){std::array<char,1200> bytes{};sockaddr_in source{};int length=sizeof(source);auto n=recvfrom(socket,bytes.data(),int(bytes.size()),0,reinterpret_cast<sockaddr*>(&source),&length);if(n<0)break;if(n<=int(Header)||memcmp(bytes.data(),"WUM1",4)||!privateAddress(source.sin_addr.s_addr))continue;if(peerReady&&(source.sin_addr.s_addr!=peer.sin_addr.s_addr||source.sin_port!=peer.sin_port))continue;
        const auto* b=reinterpret_cast<unsigned char*>(bytes.data());uint64_t seq=0;for(unsigned j=0;j<8;j++)seq=(seq<<8)|b[4+j];uint16_t index=(uint16_t(b[12])<<8)|b[13],count=(uint16_t(b[14])<<8)|b[15];if(!seq||seq<=received||!count||count>60||index>=count||size_t(n)-Header>Chunk)continue;
        if(assembly.sequence!=seq){if(assembly.sequence>seq&&now-assembly.time<std::chrono::milliseconds(200))continue;assembly={seq,count,{},now};}if(assembly.count!=count||now-assembly.time>std::chrono::milliseconds(200))continue;assembly.parts[index]=Bytes(b+Header,b+n);if(assembly.parts.size()!=count)continue;
        Bytes joined;for(uint16_t j=0;j<count;j++)joined.insert(joined.end(),assembly.parts.at(j).begin(),assembly.parts.at(j).end());assembly={};if(joined.size()>MaxMessage)continue;
        try{auto json=parse(std::string(joined.begin(),joined.end()));if(json.size()!=3||json.at("sequence")!=seq)continue;auto plain=decryptMediaPacket(up,json,id+":up");if(plain.empty())continue;const auto type=plain.front();if(!peerReady&&type!=0)continue;received=seq;
          if(type==0||type==4){peer=source;peerReady=true;lastHello=now;send(4,{});}else if(type==3){alive=false;break;}else if(type==2&&mode=="audio-speaker-start"&&audio){plain.erase(plain.begin());audio->play(plain);}
        }catch(...){/* Invalid ciphertext never changes peer, sequence or capture state. */}
      }
      if(!alive)break;
      if(mode=="camera-start"&&now>=nextFrame){if(!camera||cameraFast!=peerReady){camera.reset();cameraFast=peerReady;camera=std::make_unique<Camera>(began+std::chrono::seconds(60),permitted,cameraFast?640:320,cameraFast?480:240);}auto jpeg=camera->frame();if(!permitted())break;if(peerReady){if(!jpeg.empty())send(1,jpeg);}else {std::lock_guard lock(mutex);latest=std::move(jpeg);}nextFrame=now+std::chrono::milliseconds(peerReady?67:200);}
      if(peerReady&&mode!="camera-start"){if(!audio)audio=std::make_unique<Audio>(mode=="audio-microphone-start");if(mode=="audio-microphone-start")for(auto& pcm:audio->read())send(2,pcm);}
      std::this_thread::sleep_for(std::chrono::milliseconds(4));
    }}catch(...){/* End this session; permissions and OS device availability remain authoritative. */}
    send(3,{});audio.reset();camera.reset();peerReady=false;alive=false;CoUninitialize();
  }
};
DirectMedia::DirectMedia(std::string id,std::string mode,Bytes key,std::function<bool()> permitted):impl_(std::make_unique<Impl>(std::move(id),std::move(mode),std::move(key),std::move(permitted))){}
DirectMedia::~DirectMedia()=default;
Json DirectMedia::transport()const{return impl_->endpoint;}
Bytes DirectMedia::preview(){std::lock_guard lock(impl_->mutex);auto frame=std::move(impl_->latest);impl_->latest.clear();return frame;}
bool DirectMedia::connected()const{return impl_->peerReady;}
bool DirectMedia::running()const{return impl_->alive;}
}
