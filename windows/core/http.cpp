#include "core.hpp"
#include <winhttp.h>
#include <wincrypt.h>
#include <stdexcept>
#include <map>
#include <mutex>
namespace pu {
namespace {
struct Handle { HINTERNET h{};~Handle(){if(h)WinHttpCloseHandle(h);} operator HINTERNET()const{return h;} };
struct PinContext { std::string pin; bool rejected=false; bool checked=false; };
void CALLBACK certificateCallback(HINTERNET request,DWORD_PTR context,DWORD status,void*,DWORD){
  if(status!=WINHTTP_CALLBACK_STATUS_SENDING_REQUEST||!context)return;
  auto& p=*reinterpret_cast<PinContext*>(context);bool good=false;
  PCCERT_CONTEXT cert=nullptr;DWORD size=sizeof(cert);
  try{if(WinHttpQueryOption(request,WINHTTP_OPTION_SERVER_CERT_CONTEXT,&cert,&size)){
    BYTE* der=nullptr;DWORD n=0;
    if(CryptEncodeObjectEx(X509_ASN_ENCODING,X509_PUBLIC_KEY_INFO,&cert->pCertInfo->SubjectPublicKeyInfo,CRYPT_ENCODE_ALLOC_FLAG,nullptr,&der,&n)){
      good=p.pin=="system"||tlsPin(Bytes(der,der+n))==p.pin;LocalFree(der);
    }
  }}catch(...){good=false;}
  if(cert)CertFreeCertificateContext(cert);p.checked=true;
  // Abort after TLS, before HTTP Authorization/body is sent to a pin-mismatched peer.
  if(!good){p.rejected=true;WinHttpCloseHandle(request);}
}
}
struct Http::Connection {
  Handle session,connection;
  Connection(const std::wstring& host,INTERNET_PORT port){
    session.h=WinHttpOpen(L"WINDOWS-UNLOCK/0.4",WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0);
    if(!session.h)throw std::runtime_error("Network initialization failed");WinHttpSetTimeouts(session,5000,5000,5000,5000);
    DWORD protocols=WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2|WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;WinHttpSetOption(session,WINHTTP_OPTION_SECURE_PROTOCOLS,&protocols,sizeof(protocols));
    connection.h=WinHttpConnect(session,host.c_str(),port,0);if(!connection.h)throw std::runtime_error("Relay unavailable");
  }
};
Http::Http(const std::string& url,const std::string& pin,const std::string& token):pin_(pin),token_(token){
  auto w=wide(url);URL_COMPONENTS c{};c.dwStructSize=sizeof(c);c.dwHostNameLength=DWORD(-1);c.dwUrlPathLength=DWORD(-1);c.dwExtraInfoLength=DWORD(-1);c.dwUserNameLength=DWORD(-1);c.dwPasswordLength=DWORD(-1);
  if(!WinHttpCrackUrl(w.c_str(),DWORD(w.size()),0,&c)||c.nScheme!=INTERNET_SCHEME_HTTPS||c.dwUserNameLength||c.dwPasswordLength||c.dwExtraInfoLength)throw std::runtime_error("An HTTPS relay URL is required");
  host_=std::wstring(c.lpszHostName,c.dwHostNameLength);port_=c.nPort;prefix_=std::wstring(c.lpszUrlPath,c.dwUrlPathLength);while(!prefix_.empty()&&prefix_.back()==L'/')prefix_.pop_back();
  if(pin!="system"&&(!pin.starts_with("sha256/")||pin.size()!=51))throw std::runtime_error("Invalid relay certificate pin");
  // Reuse OS TLS/connection pools across short-lived relay wrappers. No credentials
  // are stored in this bounded cache; every request still authenticates its certificate.
  static std::mutex mutex;static std::map<std::wstring,std::shared_ptr<Connection>> pool;
  const auto id=host_+L":"+std::to_wstring(port_)+L":"+wide(pin_);std::lock_guard lock(mutex);
  if(auto i=pool.find(id);i!=pool.end())connection_=i->second;
  else {connection_=std::make_shared<Connection>(host_,port_);if(pool.size()>=8)pool.erase(pool.begin());pool[id]=connection_;}
}
Json Http::call(const std::string& method,const std::string& path,const Json* body)const{
  auto verb=wide(method),target=prefix_+wide(path);
  Handle request{WinHttpOpenRequest(connection_->connection,verb.c_str(),target.c_str(),nullptr,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE)};
  if(!request.h)throw std::runtime_error("Request initialization failed");DWORD redirects=WINHTTP_OPTION_REDIRECT_POLICY_NEVER;WinHttpSetOption(request,WINHTTP_OPTION_REDIRECT_POLICY,&redirects,sizeof(redirects));
  DWORD disabled=WINHTTP_DISABLE_COOKIES|WINHTTP_DISABLE_AUTHENTICATION;WinHttpSetOption(request,WINHTTP_OPTION_DISABLE_FEATURE,&disabled,sizeof(disabled));
  PinContext pin{pin_};WinHttpSetStatusCallback(request,certificateCallback,WINHTTP_CALLBACK_STATUS_SENDING_REQUEST,0);
  auto headers=std::wstring(body?L"Content-Type: application/json\r\n":L"")+L"Authorization: Bearer "+wide(token_)+L"\r\n";auto data=body?body->dump():std::string{};
  BOOL sent=WinHttpSendRequest(request,headers.c_str(),DWORD(headers.size()),data.empty()?WINHTTP_NO_REQUEST_DATA:data.data(),DWORD(data.size()),DWORD(data.size()),reinterpret_cast<DWORD_PTR>(&pin));
  if(pin.rejected){request.h=nullptr;throw std::runtime_error("Relay certificate pin mismatch");}
  if(!sent||!pin.checked||!WinHttpReceiveResponse(request,nullptr))throw std::runtime_error("Phone authentication unavailable; check TLS/network");
  DWORD status=0,size=sizeof(status);if(!WinHttpQueryHeaders(request,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,WINHTTP_HEADER_NAME_BY_INDEX,&status,&size,WINHTTP_NO_HEADER_INDEX))throw std::runtime_error("Invalid relay response");
  std::string result;for(;;){char buffer[4096];DWORD count=0;if(!WinHttpReadData(request,buffer,sizeof(buffer),&count))throw std::runtime_error("Relay read failed");if(!count)break;result.append(buffer,count);if(result.size()>65536)throw std::runtime_error("Response too large");}
  if(status<200||status>=300)throw RelayHttpError(status);return result.empty()?Json::object():parse(result);
}
}
