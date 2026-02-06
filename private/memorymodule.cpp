// one of the most useful things in this project

#include "memorymodule.h"
#include <algorithm>
#include <Psapi.h>
#pragma comment(lib,"Psapi.lib")
memorymodule::memorymodule() : pcode(nullptr), isdll(false), disposed(false) {}
memorymodule::~memorymodule() { close(); }
bool memorymodule::load(std::vector<BYTE> data) {
    if (data.size() < sizeof(image_dos_header)) return false;
    image_dos_header* dos = (image_dos_header*)data.data();
    if (dos->e_magic != 0x5A4D) return false;
    if (data.size() < dos->e_lfanew + sizeof(image_nt_headers)) return false;
    image_nt_headers* ntheaders = (image_nt_headers*)(data.data() + dos->e_lfanew);
    if (ntheaders->Signature != 0x00004550) return false;
    isdll = (ntheaders->FileHeader.Characteristics & 0x2000) != 0;
    pcode = VirtualAlloc((LPVOID)ntheaders->OptionalHeader.ImageBase, ntheaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!pcode) pcode = VirtualAlloc(NULL, ntheaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!pcode) return false;
    memcpy(pcode, data.data(), ntheaders->OptionalHeader.SizeOfHeaders);
    copysections(ntheaders, pcode);
    LPVOID delta = (LPVOID)((ULONG_PTR)pcode - ntheaders->OptionalHeader.ImageBase);
    if (delta != nullptr) *(ULONG_PTR*)((BYTE*)pcode + dos->e_lfanew + offsetof(image_nt_headers, OptionalHeader) + offsetof(image_optional_header, ImageBase)) = (ULONG_PTR)pcode;
    performrelocation(ntheaders, pcode, delta);
    buildimporttable(ntheaders, pcode);
    finalsections(ntheaders, pcode);
    executetls(ntheaders, pcode);
    return true;
}
void memorymodule::copysections(image_nt_headers* ntheaders, LPVOID base) {
    image_section_header* section = reinterpret_cast<image_section_header*>(IMAGE_FIRST_SECTION(ntheaders));
    for (WORD i = 0; i < ntheaders->FileHeader.NumberOfSections; i++, section++) {
        if (section->SizeOfRawData) {
            LPVOID dest = (BYTE*)base + section->VirtualAddress;
            LPVOID src = (BYTE*)base + section->PointerToRawData;
            memcpy(dest, src, section->SizeOfRawData);
        }
    }
}
bool memorymodule::performrelocation(image_nt_headers* ntheaders, LPVOID base, LPVOID delta) {
    if (!ntheaders->OptionalHeader.DataDirectory[5].VirtualAddress) return true;
    IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)base + ntheaders->OptionalHeader.DataDirectory[5].VirtualAddress);
    while (reloc->VirtualAddress) {
        BYTE* dest = (BYTE*)base + reloc->VirtualAddress;
        WORD* relinfo = (WORD*)(reloc + 1);
        for (DWORD i = 0; i < (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2; i++, relinfo++) {
            int type = *relinfo >> 12;
            int offset = *relinfo & 0xFFF;
            if (type == IMAGE_REL_BASED_HIGHLOW) {
                DWORD* patch = (DWORD*)(dest + offset);
                *patch += (DWORD)delta;
            }
#ifdef _WIN64
            else if (type == IMAGE_REL_BASED_DIR64) {
                ULONGLONG* patch = (ULONGLONG*)(dest + offset);
                *patch += (ULONGLONG)delta;
            }
#endif
        }
        reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
    }
    return true;
}
bool memorymodule::buildimporttable(image_nt_headers* ntheaders, LPVOID base) {
    if (!ntheaders->OptionalHeader.DataDirectory[1].VirtualAddress) return true;
    image_import_descriptor* importdesc = (image_import_descriptor*)((BYTE*)base + ntheaders->OptionalHeader.DataDirectory[1].VirtualAddress);
    while (importdesc->Name) {
        char* dllname = (char*)((BYTE*)base + importdesc->Name);
        HMODULE hmodule = LoadLibraryA(dllname);
        if (!hmodule) return false;
        importmodules.push_back(hmodule);
        ULONG_PTR* thunk = (ULONG_PTR*)((BYTE*)base + importdesc->FirstThunk);
        if (importdesc->OriginalFirstThunk) {
            IMAGE_THUNK_DATA* origthunk = (IMAGE_THUNK_DATA*)((BYTE*)base + importdesc->OriginalFirstThunk);
            while (origthunk->u1.AddressOfData) {
                if (origthunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    *thunk = (ULONG_PTR)GetProcAddress(hmodule, (LPCSTR)(origthunk->u1.Ordinal & 0xFFFF));
                }
                else {
                    IMAGE_IMPORT_BY_NAME* import = (IMAGE_IMPORT_BY_NAME*)((BYTE*)base + origthunk->u1.AddressOfData);
                    *thunk = (ULONG_PTR)GetProcAddress(hmodule, import->Name);
                }
                thunk++;
                origthunk++;
            }
        }
        importdesc++;
    }
    return true;
}
void memorymodule::finalsections(image_nt_headers* ntheaders, LPVOID base) {
    image_section_header* section = reinterpret_cast<image_section_header*>(IMAGE_FIRST_SECTION(ntheaders));
    for (WORD i = 0; i < ntheaders->FileHeader.NumberOfSections; i++, section++) {
        DWORD protect = 0;
        if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (section->Characteristics & IMAGE_SCN_MEM_READ) {
                if (section->Characteristics & IMAGE_SCN_MEM_WRITE) protect = PAGE_EXECUTE_READWRITE;
                else protect = PAGE_EXECUTE_READ;
            }
            else protect = PAGE_EXECUTE;
        }
        else {
            if (section->Characteristics & IMAGE_SCN_MEM_READ) {
                if (section->Characteristics & IMAGE_SCN_MEM_WRITE) protect = PAGE_READWRITE;
                else protect = PAGE_READONLY;
            }
            else protect = PAGE_NOACCESS;
        }
        DWORD oldprotect;
        VirtualProtect((BYTE*)base + section->VirtualAddress, section->SizeOfRawData, protect, &oldprotect);
    }
}
void memorymodule::executetls(image_nt_headers* ntheaders, LPVOID base) {
    if (!ntheaders->OptionalHeader.DataDirectory[9].VirtualAddress) return;
    IMAGE_TLS_DIRECTORY* tls = (IMAGE_TLS_DIRECTORY*)((BYTE*)base + ntheaders->OptionalHeader.DataDirectory[9].VirtualAddress);
    if (tls->AddressOfCallBacks) {
        PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
        while (*callback) {
            (*callback)(base, DLL_PROCESS_ATTACH, nullptr);
            callback++;
        }
    }
}
LPVOID memorymodule::findexport(const char* funcname) {
    image_dos_header* dos = (image_dos_header*)pcode;
    image_nt_headers* ntheaders = (image_nt_headers*)((BYTE*)pcode + dos->e_lfanew);
    image_export_directory* exports = (image_export_directory*)((BYTE*)pcode + ntheaders->OptionalHeader.DataDirectory[0].VirtualAddress);
    DWORD* functions = (DWORD*)((BYTE*)pcode + exports->AddressOfFunctions);
    DWORD* names = (DWORD*)((BYTE*)pcode + exports->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)pcode + exports->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)pcode + names[i]);
        if (strcmp(name, funcname) == 0) {
            return (BYTE*)pcode + functions[ordinals[i]];
        }
    }
    return nullptr;
}
LPVOID memorymodule::getfunction(const char* funcname) {
    if (!pcode || disposed) return nullptr;
    if (!isdll) return nullptr;
    return findexport(funcname);
}
bool memorymodule::isloaded() {
    return pcode != nullptr && !disposed;
}
void memorymodule::close() {
    if (disposed) return;
    for (HMODULE module : importmodules) {
        FreeLibrary(module);
    }
    importmodules.clear();
    if (pcode) {
        VirtualFree(pcode, 0, MEM_RELEASE);
        pcode = nullptr;
    }
    disposed = true;
}