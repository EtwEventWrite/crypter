#pragma once
#include <Windows.h>
#include <intrin.h>
class hardwarebreakpoint {
private:
    static LPVOID pABuF;
    static LPVOID pCtx;
    static LONG WINAPI exceptionhandler(PEXCEPTION_POINTERS exceptions);
    static void enablebreakpoint(PCONTEXT ctx, LPVOID address, int index);
    static ULONG_PTR setbits(ULONG_PTR dw, int lowbit, int bits, ULONG_PTR newvalue);
public:
    static bool bypass();
};