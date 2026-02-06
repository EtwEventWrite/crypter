#pragma once
#include <Windows.h>
#include <vector>
#include <string>
class esetbypass {
private:
    typedef void(*esetcallback)();
    esetcallback originalfunction;
    LPVOID hookedaddress;
    static void bypasscallback();
    LPVOID searchaob(std::vector<BYTE> pattern, std::string mask, std::string modulename);
    bool hookfunction(LPVOID address, esetcallback callback);
    bool unhook();

public:
    bool bypass();
};