#pragma once
#include <windows.h>
#include <string>
#include <cstdint>

struct PairingQrPayload { std::string invitation; int64_t expiresAt{}; };
bool showPairingQr(HWND owner, const PairingQrPayload& payload);
void closePairingQr();
