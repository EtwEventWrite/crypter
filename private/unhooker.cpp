// VERY UNSTABLE - USE AT YOUR OWN RISK.

#include "unhooker.h"
#include <TlHelp32.h>
#include <DbgHelp.h>
#include <Psapi.h>
#pragma comment(lib, "dbghelp.lib")
unhooker::unhooker() { }
unhooker::~unhooker() {
    for (auto& region : scannedregion) {
        if (region.cleancopy) VirtualFree(region.cleancopy, 0, MEM_RELEASE);
    }
}
HMODULE unhooker::getmodulefromdisk(const std::wstring& modulename) {
    wchar_t sysdir[MAX_PATH];
    GetSystemDirectoryW(sysdir, MAX_PATH);
    std::wstring fullpath = sysdir;
    fullpath += L"\\";
    fullpath += modulename;
    return LoadLibraryExW(fullpath.c_str(), NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE);
}
bool unhooker::comparememory(const BYTE* addr1, const BYTE* addr2, size_t size) {
    __try { for (size_t i = 0; i < size; i++) if (addr1[i] != addr2[i]) return false; return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
LPVOID unhooker::findpatternmemory(LPVOID start, SIZE_T size, const pattern& pattern) {
    BYTE* data = (BYTE*)start;
    for (SIZE_T i = 0; i < size - pattern.bytes.size(); i++) {
        bool found = true;
        for (SIZE_T j = 0; j < pattern.bytes.size(); j++) {
            if (pattern.mask[j] == 'x' && pattern.bytes[j] != data[i + j]) { found = false; break; }
        }
        if (found) return (LPVOID)(data + i);
    }
    return nullptr;
}
bool unhooker::parseexports(HMODULE module, std::vector<std::string>& exports) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)module + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    PIMAGE_EXPORT_DIRECTORY expdir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)module + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* functions = (DWORD*)((BYTE*)module + expdir->AddressOfFunctions);
    DWORD* names = (DWORD*)((BYTE*)module + expdir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)module + expdir->AddressOfNameOrdinals);
    for (DWORD i = 0; i < expdir->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)module + names[i]);
        exports.push_back(name);
    }
    return true;
}
bool unhooker::detectinline() {
    inlinehooks.clear();
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (!ntdll || !kernel32) return false;
    HMODULE cleanntdll = getmodulefromdisk(L"ntdll.dll");
    HMODULE cleankernel32 = getmodulefromdisk(L"kernel32.dll");
    if (!cleanntdll || !cleankernel32) return false;
    std::vector<std::string> ntdllexports;
    std::vector<std::string> kernel32exports;
    parseexports(cleanntdll, ntdllexports);
    parseexports(cleankernel32, kernel32exports);
    for (const auto& funcname : ntdllexports) {
        if (funcname.find("Nt") != 0 && funcname.find("Zw") != 0) continue;
        FARPROC hookedaddr = GetProcAddress(ntdll, funcname.c_str());
        FARPROC cleanaddr = GetProcAddress(cleanntdll, funcname.c_str());
        if (!hookedaddr || !cleanaddr) continue;
        BYTE hookedbytes[64];
        BYTE cleanbytes[64];
        if (ReadProcessMemory(GetCurrentProcess(), hookedaddr, hookedbytes, 64, NULL) && ReadProcessMemory(GetCurrentProcess(), cleanaddr, cleanbytes, 64, NULL)) {
            if (!comparememory(hookedbytes, cleanbytes, 64)) {
                inlinehook hook;
                hook.targetaddr = hookedaddr;
                hook.originalbytes.assign(cleanbytes, cleanbytes + 64);
                hook.hookbytes.assign(hookedbytes, hookedbytes + 64);
                inlinehooks.push_back(hook);
            }
        }
    }
    for (const auto& funcname : kernel32exports) {
        if (funcname.find("Create") != 0 && funcname.find("Virtual") != 0 && funcname.find("Write") != 0 && funcname.find("Read") != 0) continue;
        FARPROC hookedaddr = GetProcAddress(kernel32, funcname.c_str());
        FARPROC cleanaddr = GetProcAddress(cleankernel32, funcname.c_str());
        if (!hookedaddr || !cleanaddr) continue;
        BYTE hookedbytes[32];
        BYTE cleanbytes[32];
        if (ReadProcessMemory(GetCurrentProcess(), hookedaddr, hookedbytes, 32, NULL) && ReadProcessMemory(GetCurrentProcess(), cleanaddr, cleanbytes, 32, NULL)) {
            if (!comparememory(hookedbytes, cleanbytes, 32)) {
                inlinehook hook;
                hook.targetaddr = hookedaddr;
                hook.originalbytes.assign(cleanbytes, cleanbytes + 32);
                hook.hookbytes.assign(hookedbytes, hookedbytes + 32);
                inlinehooks.push_back(hook);
            }
        }
    }
    FreeLibrary(cleanntdll);
    FreeLibrary(cleankernel32);
    return !inlinehooks.empty();
}
bool unhooker::fixrelocations(LPVOID newbase, LPVOID oldbase) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)oldbase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)oldbase + dos->e_lfanew);
    DWORD delta = (DWORD)((BYTE*)newbase - (BYTE*)oldbase);
    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0) return true;
    PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)oldbase + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    while (reloc->VirtualAddress) {
        DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* items = (WORD*)(reloc + 1);
        for (DWORD i = 0; i < count; i++) {
            if ((items[i] >> 12) == IMAGE_REL_BASED_HIGHLOW) {
                DWORD* patch = (DWORD*)((BYTE*)oldbase + reloc->VirtualAddress + (items[i] & 0xFFF));
                *patch += delta;
            }
        }
        reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
    }
    return true;
}
bool unhooker::manualmapclean(const std::wstring& modulename) {
    wchar_t sysdir[MAX_PATH];
    GetSystemDirectoryW(sysdir, MAX_PATH);
    std::wstring fullpath = sysdir + std::wstring(L"\\") + modulename;
    HANDLE hfile = CreateFileW(fullpath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hfile == INVALID_HANDLE_VALUE) return false;
    DWORD filesize = GetFileSize(hfile, NULL);
    if (filesize == INVALID_FILE_SIZE) { CloseHandle(hfile); return false; }
    BYTE* filedata = new BYTE[filesize];
    DWORD bytesread;
    ReadFile(hfile, filedata, filesize, &bytesread, NULL);
    CloseHandle(hfile);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)filedata;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { delete[] filedata; return false; }
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(filedata + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { delete[] filedata; return false; }
    SIZE_T imagesize = nt->OptionalHeader.SizeOfImage;
    LPVOID imagebase = VirtualAlloc(NULL, imagesize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!imagebase) { delete[] filedata; return false; }
    SIZE_T headersize = nt->OptionalHeader.SizeOfHeaders;
    memcpy(imagebase, filedata, headersize);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (section[i].SizeOfRawData) {
            LPVOID sectiondest = (BYTE*)imagebase + section[i].VirtualAddress;
            LPVOID sectionsrc = filedata + section[i].PointerToRawData;
            memcpy(sectiondest, sectionsrc, section[i].SizeOfRawData);
        }
    }
    fixrelocations(imagebase, filedata);
    PIMAGE_IMPORT_DESCRIPTOR importdesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)imagebase + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    while (importdesc->Name) {
        char* dllname = (char*)imagebase + importdesc->Name;
        HMODULE hmodule = LoadLibraryA(dllname);
        if (hmodule) {
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)imagebase + importdesc->FirstThunk);
            while (thunk->u1.AddressOfData) {
                if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)((BYTE*)imagebase + thunk->u1.AddressOfData);
                    FARPROC func = GetProcAddress(hmodule, import->Name);
                    if (func) thunk->u1.Function = (ULONG_PTR)func;
                }
                thunk++;
            }
        }
        importdesc++;
    }
    memoryregion region;
    region.baseaddr = imagebase;
    region.size = imagesize;
    region.protect = PAGE_EXECUTE_READ;
    region.cleancopy = imagebase;
    scannedregion.push_back(region);
    DWORD oldprotect;
    VirtualProtect(imagebase, imagesize, PAGE_EXECUTE_READ, &oldprotect);
    delete[] filedata;
    return true;
}
bool unhooker::overwritehooksfromdisk() {
    if (inlinehooks.empty()) detectinline();
    for (auto& hook : inlinehooks) {
        DWORD oldprotect;
        if (VirtualProtect(hook.targetaddr, hook.originalbytes.size(), PAGE_EXECUTE_READWRITE, &oldprotect)) {
            __try {
                memcpy(hook.targetaddr, hook.originalbytes.data(), hook.originalbytes.size());
                DWORD temp;
                VirtualProtect(hook.targetaddr, hook.originalbytes.size(), oldprotect, &temp);
                FlushInstructionCache(GetCurrentProcess(), hook.targetaddr, hook.originalbytes.size());
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
        }
    }
    return true;
}
bool unhooker::restorehook(inlinehook& hook) {
    DWORD oldprotect;
    if (VirtualProtect(hook.targetaddr, hook.originalbytes.size(), PAGE_EXECUTE_READWRITE, &oldprotect)) {
        __try {
            memcpy(hook.targetaddr, hook.originalbytes.data(), hook.originalbytes.size());
            DWORD temp;
            VirtualProtect(hook.targetaddr, hook.originalbytes.size(), oldprotect, &temp);
            FlushInstructionCache(GetCurrentProcess(), hook.targetaddr, hook.originalbytes.size());
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }
    return false;
}
bool unhooker::syscallstub() {
    HMODULE hcleantdll = getmodulefromdisk(L"ntdll.dll");
    if (!hcleantdll) return false;
    std::vector<std::string> exports;
    parseexports(hcleantdll, exports);
    for (const auto& funcname : exports) {
        if (funcname.find("Nt") != 0 && funcname.find("Zw") != 0) continue;
        FARPROC cleanfunc = GetProcAddress(hcleantdll, funcname.c_str());
        if (!cleanfunc) continue;
        BYTE stub[64];
        if (ReadProcessMemory(GetCurrentProcess(), cleanfunc, stub, sizeof(stub), NULL)) {
            LPVOID exemem = VirtualAlloc(NULL, sizeof(stub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (exemem) {
                memcpy(exemem, stub, sizeof(stub));
                DWORD oldprotect;
                VirtualProtect(exemem, sizeof(stub), PAGE_EXECUTE_READ, &oldprotect);
                memoryregion region;
                region.baseaddr = exemem;
                region.size = sizeof(stub);
                region.protect = PAGE_EXECUTE_READ;
                region.cleancopy = exemem;
                scannedregion.push_back(region);
            }
        }
    }
    FreeLibrary(hcleantdll);
    return true;
}
bool unhooker::usesyscall(FARPROC function) {
    char modulename[MAX_PATH];
    GetModuleFileNameA((HMODULE)function, modulename, MAX_PATH);
    if (strstr(modulename, "ntdll.dll") == NULL) return false;
    HMODULE hcleantdll = getmodulefromdisk(L"ntdll.dll");
    if (!hcleantdll) return false;
    FARPROC cleanfunc = GetProcAddress(hcleantdll, (LPCSTR)function);
    if (!cleanfunc) { FreeLibrary(hcleantdll); return false; }
    BYTE stub[32];
    if (ReadProcessMemory(GetCurrentProcess(), cleanfunc, stub, sizeof(stub), NULL)) {
        LPVOID exemem = VirtualAlloc(NULL, sizeof(stub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (exemem) {
            memcpy(exemem, stub, sizeof(stub));
            DWORD oldprotect;
            VirtualProtect(exemem, sizeof(stub), PAGE_EXECUTE_READ, &oldprotect);
            memcpy(function, exemem, sizeof(stub));
            VirtualFree(exemem, 0, MEM_RELEASE);
        }
    }
    FreeLibrary(hcleantdll);
    return true;
}
bool unhooker::createfreshmemorycopy() {
    HMODULE modules[] = { GetModuleHandleA("ntdll.dll"), GetModuleHandleA("kernel32.dll"), GetModuleHandleA("kernelbase.dll") };
    for (HMODULE hmodule : modules) {
        if (!hmodule) continue;
        MODULEINFO modinfo;
        if (GetModuleInformation(GetCurrentProcess(), hmodule, &modinfo, sizeof(modinfo))) {
            LPVOID newmem = VirtualAlloc(NULL, modinfo.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (newmem) {
                memcpy(newmem, modinfo.lpBaseOfDll, modinfo.SizeOfImage);
                DWORD oldprotect;
                VirtualProtect(newmem, modinfo.SizeOfImage, PAGE_EXECUTE_READ, &oldprotect);
                memoryregion region;
                region.baseaddr = newmem;
                region.size = modinfo.SizeOfImage;
                region.protect = PAGE_EXECUTE_READ;
                region.cleancopy = newmem;
                scannedregion.push_back(region);
            }
        }
    }
    return true;
}
bool unhooker::detecttrampoline() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    MODULEINFO modinfo;
    if (!GetModuleInformation(GetCurrentProcess(), ntdll, &modinfo, sizeof(modinfo))) return false;
    pattern jmppattern = { { 0xE9, 0x00, 0x00, 0x00, 0x00 }, "x????" };
    pattern pushretpattern = { { 0x68, 0x00, 0x00, 0x00, 0x00, 0xC3 }, "x????x" };
    BYTE* base = (BYTE*)modinfo.lpBaseOfDll;
    LPVOID jmpfound = findpatternmemory(base, modinfo.SizeOfImage, jmppattern);
    LPVOID pushretfound = findpatternmemory(base, modinfo.SizeOfImage, pushretpattern);
    return (jmpfound != nullptr || pushretfound != nullptr);
}
bool unhooker::unhookntdll() {
    bool success = false;
    detectinline();
    if (!inlinehooks.empty()) {
        for (auto& hook : inlinehooks) {
            if (restorehook(hook)) success = true;
        }
    }
    if (!success) success = manualmapclean(L"ntdll.dll");
    if (!success) syscallstub();
    return success;
}
bool unhooker::unhookall() {
    bool ntdll = unhookntdll();
    bool kernel32 = manualmapclean(L"kernel32.dll");
    bool kernelbase = manualmapclean(L"kernelbase.dll");
    return ntdll || kernel32 || kernelbase;
}
bool unhooker::isfunctionhooked(FARPROC function) {
    if (!function) return false;
    HMODULE module;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)function, &module);
    char modulename[MAX_PATH];
    GetModuleFileNameA(module, modulename, MAX_PATH);
    std::wstring wmodulename(modulename, modulename + strlen(modulename));
    HMODULE cleanmodule = getmodulefromdisk(wmodulename);
    if (!cleanmodule) return false;
    BYTE membytes[32];
    BYTE cleabytes[32];
    if (ReadProcessMemory(GetCurrentProcess(), function, membytes, 32, NULL)) {
        FARPROC cleanfunc = GetProcAddress(cleanmodule, (LPCSTR)function);
        if (cleanfunc && ReadProcessMemory(GetCurrentProcess(), cleanfunc, cleabytes, 32, NULL)) {
            bool hooked = !comparememory(membytes, cleabytes, 32);
            FreeLibrary(cleanmodule);
            return hooked;
        }
    }
    FreeLibrary(cleanmodule);
    return false;
}