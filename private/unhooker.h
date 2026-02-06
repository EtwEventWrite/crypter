#pragma once
#include <Windows.h>
#include <vector>
#include <string>
struct pattern { std::vector<BYTE> bytes; std::string mask; };
struct inlinehook { LPVOID targetaddr; std::vector<BYTE> originalbytes; std::vector<BYTE> hookbytes; };
struct memoryregion { LPVOID baseaddr; SIZE_T size; DWORD protect; LPVOID cleancopy; };
class unhooker {
private:
    std::vector<inlinehook> inlinehooks;
    std::vector<memoryregion> scannedregion;
    HMODULE getmodulefromdisk(const std::wstring& modulename);
    bool comparememory(const BYTE* addr1, const BYTE* addr2, size_t size);
    LPVOID findpatternmemory(LPVOID start, SIZE_T size, const pattern& pattern);
    bool fixrelocations(LPVOID newbase, LPVOID oldbase);
    bool parseexports(HMODULE module, std::vector<std::string>& exports);
public:
    unhooker();
    ~unhooker();
    bool detectinline();
    bool manualmapclean(const std::wstring& modulename);
    bool overwritehooksfromdisk();
    bool syscallstub();
    bool createfreshmemorycopy();
    bool detecttrampoline();
    bool unhookntdll();
    bool isfunctionhooked(FARPROC function);
    bool unhookall();
    bool restorehook(inlinehook& hook);
    bool usesyscall(FARPROC function);
};