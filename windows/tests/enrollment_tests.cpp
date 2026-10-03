#include "storage.hpp"
#include <iostream>
using namespace pu;using namespace pu::preview;using namespace pu::native;
template<class F> void rejects(F fn){bool rejected=false;try{fn();}catch(...){rejected=true;}require(rejected,"Expected invalid enrollment rejection");}
struct TestKeyCleanup {
  std::string id;
  ~TestKeyCleanup(){NCRYPT_PROV_HANDLE provider{};NCRYPT_KEY_HANDLE key{};
    if(NCryptOpenStorageProvider(&provider,MS_KEY_STORAGE_PROVIDER,0)==0){auto name=wide("WINDOWS-UNLOCK-"+id);
      if(NCryptOpenKey(provider,&key,name.c_str(),0,0)==0&&NCryptDeleteKey(key,0)!=0)NCryptFreeObject(key);
      NCryptFreeObject(provider);
    }
  }
};
int main(){try{
  const auto id=uuid();TestKeyCleanup cleanup{id};SigningKey key(id,true);
  Json c{{"mode","approval-preview"},{"windowsSignInEnabled",false},{"sid",utf8(currentSid())},{"id",id},{"name","Test laptop"},{"accountBindingId",uuid()},{"relayUrl","https://example.test"},{"tlsPin","system"},{"transportToken",b64url(random(32))},{"pairing",Json{{"id",uuid()},{"androidDeviceId",uuid()},{"phoneName","Test phone"},{"approvalJwk",key.jwk()},{"identityJwk",key.jwk()}}},{"windowsJwk",key.jwk()}};
  validateConfiguration(c);
  auto bad=c;bad["windowsSignInEnabled"]=true;rejects([&]{validateConfiguration(bad);});
  bad=c;bad["mode"]="production";rejects([&]{validateConfiguration(bad);});
  bad=c;bad["sid"]="invalid";rejects([&]{validateConfiguration(bad);});
  bad=c;bad["transportToken"]="short";rejects([&]{validateConfiguration(bad);});
  bad=c;bad["relayUrl"]="http://example.test";rejects([&]{validateConfiguration(bad);});
  bad=c;bad["windowsJwk"]["d"]="private";rejects([&]{validateConfiguration(bad);});
  bad=c;bad["pairing"]["approvalJwk"]["d"]="private";rejects([&]{validateConfiguration(bad);});
  bad=c;bad.erase("windowsJwk");bad["password"]="secret";rejects([&]{validateConfiguration(bad);});
  bad=c;bad["id"]=std::string(36,'-');rejects([&]{validateConfiguration(bad);});
  bad=c;bad["pairing"].erase("id");rejects([&]{validateConfiguration(bad);});
  bad=c;bad["pairing"]["androidDeviceId"]="invalid";rejects([&]{validateConfiguration(bad);});
  // Read/validate only. No ProgramData staging, SCM start, enrollment overwrite or registry calls.
  std::cout<<"Enrollment: disabled sign-in, strict schema, SID, token, HTTPS and public-only keys passed.\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
