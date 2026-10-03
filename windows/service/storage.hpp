#pragma once
#include "core.hpp"
#include "ipc.hpp"
namespace pu::preview {
std::filesystem::path directory();
Json configuration();
void stage(const std::filesystem::path& desktopConfig);
void validateConfiguration(const Json& config);
}
