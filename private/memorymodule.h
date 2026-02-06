#pragma once
#include <Windows.h>
#include <vector>
#include <string>
class memorymodule {
private:
    struct image_dos_header {
        WORD e_magic;
        WORD e_cblp;
        WORD e_cp;
        WORD e_crlc;
        WORD e_cparhdr;
        WORD e_minalloc;
        WORD e_maxalloc;
        WORD e_ss;
        WORD e_sp;
        WORD e_csum;
        WORD e_ip;
        WORD e_cs;
        WORD e_lfarlc;
        WORD e_ovno;
        WORD e_res[4];
        WORD e_oemid;
        WORD e_oeminfo;
        WORD e_res2[10];
        LONG e_lfanew;
    };
    struct image_file_header {
        WORD Machine;
        WORD NumberOfSections;
        DWORD TimeDateStamp;
        DWORD PointerToSymbolTable;
        DWORD NumberOfSymbols;
        WORD SizeOfOptionalHeader;
        WORD Characteristics;
    };
    struct image_data_directory {
        DWORD VirtualAddress;
        DWORD Size;
    };
    struct image_optional_header {
        WORD Magic;
        BYTE MajorLinkerVersion;
        BYTE MinorLinkerVersion;
        DWORD SizeOfCode;
        DWORD SizeOfInitializedData;
        DWORD SizeOfUninitializedData;
        DWORD AddressOfEntryPoint;
        DWORD BaseOfCode;
        ULONGLONG ImageBase;
        DWORD SectionAlignment;
        DWORD FileAlignment;
        WORD MajorOperatingSystemVersion;
        WORD MinorOperatingSystemVersion;
        WORD MajorImageVersion;
        WORD MinorImageVersion;
        WORD MajorSubsystemVersion;
        WORD MinorSubsystemVersion;
        DWORD Win32VersionValue;
        DWORD SizeOfImage;
        DWORD SizeOfHeaders;
        DWORD CheckSum;
        WORD Subsystem;
        WORD DllCharacteristics;
        ULONGLONG SizeOfStackReserve;
        ULONGLONG SizeOfStackCommit;
        ULONGLONG SizeOfHeapReserve;
        ULONGLONG SizeOfHeapCommit;
        DWORD LoaderFlags;
        DWORD NumberOfRvaAndSizes;
        image_data_directory DataDirectory[16];
    };
    struct image_nt_headers {
        DWORD Signature;
        image_file_header FileHeader;
        image_optional_header OptionalHeader;
    };
    struct image_section_header {
        BYTE Name[8];
        DWORD VirtualSize;
        DWORD VirtualAddress;
        DWORD SizeOfRawData;
        DWORD PointerToRawData;
        DWORD PointerToRelocations;
        DWORD PointerToLinenumbers;
        WORD NumberOfRelocations;
        WORD NumberOfLinenumbers;
        DWORD Characteristics;
    };
    struct image_import_descriptor {
        DWORD OriginalFirstThunk;
        DWORD TimeDateStamp;
        DWORD ForwarderChain;
        DWORD Name;
        DWORD FirstThunk;
    };
    struct image_export_directory {
        DWORD Characteristics;
        DWORD TimeDateStamp;
        WORD MajorVersion;
        WORD MinorVersion;
        DWORD Name;
        DWORD Base;
        DWORD NumberOfFunctions;
        DWORD NumberOfNames;
        DWORD AddressOfFunctions;
        DWORD AddressOfNames;
        DWORD AddressOfNameOrdinals;
    };

    LPVOID pcode;
    bool isdll;
    bool disposed;
    std::vector<HMODULE> importmodules;

    bool loadmodule(std::vector<BYTE> data);
    void copysections(image_nt_headers* ntheaders, LPVOID base);
    bool performrelocation(image_nt_headers* ntheaders, LPVOID base, LPVOID delta);
    bool buildimporttable(image_nt_headers* ntheaders, LPVOID base);
    void finalsections(image_nt_headers* ntheaders, LPVOID base);
    void executetls(image_nt_headers* ntheaders, LPVOID base);
    LPVOID findexport(const char* funcname);

public:
    memorymodule();
    ~memorymodule();
    bool load(std::vector<BYTE> data);
    void close();
    LPVOID getfunction(const char* funcname);
    bool isloaded();
};