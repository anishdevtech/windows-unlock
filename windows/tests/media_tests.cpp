#include <winsock2.h>
#include <ws2tcpip.h>
#include <mmsystem.h>
#include "media.hpp"
#include "remote.hpp"
#include <iostream>
#include <thread>
using namespace pu;
namespace {
void expect(bool ok,const char* label){if(!ok)throw std::runtime_error(label);}
}
int main(){try{
  auto master=random(32);std::atomic<bool> allowed{true};DirectMedia server("udp-test","audio-speaker-start",master,[&]{return allowed.load();});
  auto transport=server.transport();if(transport.at("addresses").empty()){std::cout<<"No private LAN interface; UDP integration skipped\n";return 77;}
  SOCKET socket=::socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);expect(socket!=INVALID_SOCKET,"UDP test socket");struct Close{SOCKET s;~Close(){closesocket(s);}} close{socket};DWORD timeout=1000;setsockopt(socket,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<char*>(&timeout),sizeof(timeout));
  sockaddr_in destination{};destination.sin_family=AF_INET;destination.sin_port=htons(transport.at("port").get<unsigned short>());inet_pton(AF_INET,transport.at("addresses").at(0).get<std::string>().c_str(),&destination.sin_addr);
  auto send=[&](const Bytes& key,uint64_t seq,unsigned char type){auto message=encryptCameraFrame(key,Bytes{type},"udp-test:up",seq,{});message.erase("wrappedKey");auto text=message.dump();expect(text.size()<1100,"Test handshake fits one packet");Bytes packet(16+text.size());memcpy(packet.data(),"WUM1",4);for(unsigned b=0;b<8;b++)packet[4+b]=static_cast<unsigned char>(seq>>(56-8*b));packet[15]=1;memcpy(packet.data()+16,text.data(),text.size());expect(sendto(socket,reinterpret_cast<char*>(packet.data()),int(packet.size()),0,reinterpret_cast<sockaddr*>(&destination),sizeof(destination))==int(packet.size()),"UDP test send");};
  send(random(32),100,0);std::this_thread::sleep_for(std::chrono::milliseconds(50));expect(!server.connected(),"Forged hello cannot claim endpoint or activate audio");
  const auto up=mediaKey(master,"up"),down=mediaKey(master,"down");send(up,1,0);char bytes[1200]{};auto count=recv(socket,bytes,sizeof(bytes),0);expect(count>16,"Authenticated hello receives acknowledgement");auto ack=parse(std::string(bytes+16,bytes+count));expect(decryptMediaPacket(down,ack,"udp-test:down")==Bytes{4},"Acknowledgement authenticated under downlink key");
  if(waveOutGetNumDevs()>0){std::this_thread::sleep_for(std::chrono::milliseconds(100));expect(server.running(),"Speaker transport remains available");send(up,1,3);std::this_thread::sleep_for(std::chrono::milliseconds(50));expect(server.running(),"Replayed sequence cannot stop sharing");send(random(32),2,3);std::this_thread::sleep_for(std::chrono::milliseconds(50));expect(server.running(),"Forged stop cannot end session");send(up,2,3);for(unsigned i=0;i<100&&server.running();i++)std::this_thread::sleep_for(std::chrono::milliseconds(10));expect(!server.running(),"Authenticated stop promptly ends session");}
  allowed=false;SecureZeroMemory(master.data(),master.size());std::cout<<"UDP media authentication, directional encryption, replay and stop checks passed\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
