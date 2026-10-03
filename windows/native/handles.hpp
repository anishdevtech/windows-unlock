#pragma once
#include <windows.h>
#include <stdexcept>
#include <utility>

namespace pu::native {
class Handle {
  HANDLE value_{};
public:
  explicit Handle(HANDLE value=nullptr):value_(value){}
  ~Handle(){reset();}
  Handle(const Handle&)=delete;
  Handle& operator=(const Handle&)=delete;
  Handle(Handle&& other) noexcept:value_(std::exchange(other.value_,nullptr)){}
  Handle& operator=(Handle&& other) noexcept {if(this!=&other){reset();value_=std::exchange(other.value_,nullptr);}return *this;}
  HANDLE get() const {return value_;}
  explicit operator bool() const {return value_&&value_!=INVALID_HANDLE_VALUE;}
  void reset(HANDLE value=nullptr){if(*this)CloseHandle(value_);value_=value;}
};
inline void require(bool condition,const char* reason){if(!condition)throw std::runtime_error(reason);}
inline Handle event(){Handle result(CreateEventW(nullptr,TRUE,FALSE,nullptr));require(bool(result),"Event unavailable");return result;}
}
