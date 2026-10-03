#pragma once
#include "core.hpp"
#include <memory>
#include <functional>
namespace pu {
class Camera {
  struct Impl;std::unique_ptr<Impl> impl_;
public:
  Camera(std::chrono::steady_clock::time_point deadline,std::function<bool()> permitted);~Camera();Bytes frame();
};
}
