#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <TlHelp32.h>
class injection {
public:
    bool createremote(DWORD pid, std::vector<BYTE> shellcode);
    bool apcinject(DWORD pid, std::vector<BYTE> shellcode);
    bool earlybird(std::vector<BYTE> shellcode);
    DWORD findprocess(std::wstring procname);
};