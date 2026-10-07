#pragma once
#include "crypto.hpp"
namespace pu::vault {
std::filesystem::path directory();
Json configuration();
void validate(const Json&);
void store(const Json&);
}
