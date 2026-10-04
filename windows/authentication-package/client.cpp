#include "client.hpp"
#include "ipc.hpp"
#include <ntsecapi.h>
namespace pu::auth {
using native::require;
Client::Client(){require(LsaConnectUntrusted(&handle_)==0,"LSA unavailable");LSA_STRING name{USHORT(sizeof(PackageName)-1),USHORT(sizeof(PackageName)),const_cast<char*>(PackageName)};if(LsaLookupAuthenticationPackage(handle_,&name,&package_)!=0){LsaDeregisterLogonProcess(handle_);handle_=nullptr;throw std::runtime_error("Microsoft-signed LSA package not loaded");}}
Client::~Client(){if(handle_)LsaDeregisterLogonProcess(handle_);}
Json Client::call(const Json& request){auto bytes=request.dump();require(bytes.size()<MaxSubmission,"LSA message too large");PVOID buffer{};ULONG size{};NTSTATUS status{};const auto transport=LsaCallAuthenticationPackage(handle_,package_,bytes.data(),ULONG(bytes.size()),&buffer,&size,&status);struct Free{PVOID p;~Free(){if(p)LsaFreeReturnBuffer(p);}} free{buffer};require(transport==0&&status==0&&buffer&&size>0&&size<MaxSubmission,"LSA operation refused");return parse(std::string(static_cast<char*>(buffer),size));}
ULONG packageId(){HANDLE handle{};require(LsaConnectUntrusted(&handle)==0,"LSA unavailable");LSA_STRING name{USHORT(sizeof(PackageName)-1),USHORT(sizeof(PackageName)),const_cast<char*>(PackageName)};ULONG id{};auto status=LsaLookupAuthenticationPackage(handle,&name,&id);LsaDeregisterLogonProcess(handle);require(status==0,"Authentication package unavailable");return id;}
}
