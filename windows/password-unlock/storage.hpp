#pragma once
#include "crypto.hpp"
namespace pu::vault {
std::filesystem::path directory();
Json configuration();
void validate(const Json&);
void store(const Json&);
void storeSuccessReceipt(const std::string& bundle,const std::wstring& sid);
}
