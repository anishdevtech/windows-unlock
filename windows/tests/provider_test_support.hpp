#pragma once
#include "ipc.hpp"
#include <credentialprovider.h>
#include <shlguid.h>
#include <wrl/client.h>
#include <iostream>
#include <vector>
#include <atomic>
#include <filesystem>
using namespace pu::native;using Microsoft::WRL::ComPtr;
void check(bool value,const char* label){require(value,label);}
HRESULT text(const std::wstring& value,LPWSTR* out){if(!out)return E_POINTER;*out=static_cast<LPWSTR>(CoTaskMemAlloc((value.size()+1)*sizeof(wchar_t)));if(!*out)return E_OUTOFMEMORY;wcscpy_s(*out,value.size()+1,value.c_str());return S_OK;}
struct User final:ICredentialProviderUser {
  std::atomic<ULONG> refs{1};std::wstring sid;explicit User(std::wstring s):sid(std::move(s)){}
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id,void** out)override{if(!out)return E_POINTER;*out=nullptr;if(id!=IID_IUnknown&&id!=__uuidof(ICredentialProviderUser))return E_NOINTERFACE;*out=this;AddRef();return S_OK;}
  ULONG STDMETHODCALLTYPE AddRef()override{return ++refs;}ULONG STDMETHODCALLTYPE Release()override{auto n=--refs;if(!n)delete this;return n;}
  HRESULT STDMETHODCALLTYPE GetSid(LPWSTR* out)override{return text(sid,out);}
  HRESULT STDMETHODCALLTYPE GetProviderID(GUID* id)override{if(!id)return E_POINTER;*id={};return S_OK;}
  HRESULT STDMETHODCALLTYPE GetStringValue(REFPROPERTYKEY,LPWSTR* out)override{if(out)*out=nullptr;return E_NOTIMPL;}
  HRESULT STDMETHODCALLTYPE GetValue(REFPROPERTYKEY,PROPVARIANT* out)override{if(out)*out={};return E_NOTIMPL;}
};
struct Users final:ICredentialProviderUserArray {
  std::atomic<ULONG> refs{1};std::vector<ComPtr<ICredentialProviderUser>> list;unsigned filterCalls{};
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id,void** out)override{if(!out)return E_POINTER;*out=nullptr;if(id!=IID_IUnknown&&id!=__uuidof(ICredentialProviderUserArray))return E_NOINTERFACE;*out=this;AddRef();return S_OK;}
  ULONG STDMETHODCALLTYPE AddRef()override{return ++refs;}ULONG STDMETHODCALLTYPE Release()override{auto n=--refs;if(!n)delete this;return n;}
  HRESULT STDMETHODCALLTYPE SetProviderFilter(REFGUID)override{++filterCalls;return E_FAIL;}
  HRESULT STDMETHODCALLTYPE GetAccountOptions(CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS* out)override{if(!out)return E_POINTER;*out=CPAO_NONE;return S_OK;}
  HRESULT STDMETHODCALLTYPE GetCount(DWORD* out)override{if(!out)return E_POINTER;*out=DWORD(list.size());return S_OK;}
  HRESULT STDMETHODCALLTYPE GetAt(DWORD i,ICredentialProviderUser** out)override{if(!out)return E_POINTER;*out=nullptr;if(i>=list.size())return E_INVALIDARG;return list[i].CopyTo(out);}
  void add(const std::wstring& sid){ComPtr<ICredentialProviderUser> user;user.Attach(new User(sid));list.push_back(std::move(user));}
};
struct Events final:ICredentialProviderCredentialEvents {
  std::atomic<ULONG> refs{1};DWORD thread{GetCurrentThreadId()};unsigned updates{};bool wrongThread{};
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id,void** out)override{if(!out)return E_POINTER;*out=nullptr;if(id!=IID_IUnknown&&id!=__uuidof(ICredentialProviderCredentialEvents))return E_NOINTERFACE;*out=this;AddRef();return S_OK;}
  ULONG STDMETHODCALLTYPE AddRef()override{return ++refs;}ULONG STDMETHODCALLTYPE Release()override{auto n=--refs;if(!n)delete this;return n;}
  HRESULT STDMETHODCALLTYPE SetFieldState(ICredentialProviderCredential*,DWORD,CREDENTIAL_PROVIDER_FIELD_STATE)override{return S_OK;}
  HRESULT STDMETHODCALLTYPE SetFieldInteractiveState(ICredentialProviderCredential*,DWORD,CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE)override{return S_OK;}
  HRESULT STDMETHODCALLTYPE SetFieldString(ICredentialProviderCredential*,DWORD,LPCWSTR)override{++updates;if(GetCurrentThreadId()!=thread)wrongThread=true;return S_OK;}
  HRESULT STDMETHODCALLTYPE SetFieldCheckbox(ICredentialProviderCredential*,DWORD,BOOL,LPCWSTR)override{return S_OK;}
  HRESULT STDMETHODCALLTYPE SetFieldBitmap(ICredentialProviderCredential*,DWORD,HBITMAP)override{return S_OK;}
  HRESULT STDMETHODCALLTYPE SetFieldComboBoxSelectedItem(ICredentialProviderCredential*,DWORD,DWORD)override{return S_OK;}
  HRESULT STDMETHODCALLTYPE DeleteFieldComboBoxItem(ICredentialProviderCredential*,DWORD,DWORD)override{return S_OK;}
  HRESULT STDMETHODCALLTYPE AppendFieldComboBoxItem(ICredentialProviderCredential*,DWORD,LPCWSTR)override{return S_OK;}
  HRESULT STDMETHODCALLTYPE SetFieldSubmitButton(ICredentialProviderCredential*,DWORD,DWORD)override{return S_OK;}
  HRESULT STDMETHODCALLTYPE OnCreatingWindow(HWND* out)override{if(!out)return E_POINTER;*out=nullptr;return S_OK;}
};
