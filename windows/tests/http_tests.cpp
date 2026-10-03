#include "core.hpp"
#include <iostream>
int main(int argc,char**argv){try{
  if(argc!=2)throw std::runtime_error("Expected connection.json path");auto c=pu::parse(pu::read(pu::wide(argv[1])));auto url=c.at("relayUrl").get<std::string>(),pin=c.at("tlsPin").get<std::string>();
  auto result=pu::Http(url,pin,pu::b64url(pu::random(32))).call("GET","/health");if(result.at("status")!="ok")throw std::runtime_error("Unexpected health response");
  auto bad=pin;bad[10]=bad[10]=='A'?'B':'A';bool rejected=false;try{pu::Http(url,bad,pu::b64url(pu::random(32))).call("GET","/health");}catch(...){rejected=true;}
  if(!rejected)throw std::runtime_error("Incorrect pin accepted");
  rejected=false;try{pu::Http("http://127.0.0.1:8443",pin,"");}catch(...){rejected=true;}if(!rejected)throw std::runtime_error("Plaintext accepted");
  std::cout<<"WinHTTP trusted TLS, pin rejection and HTTPS-only checks passed\n";return 0;
}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}
