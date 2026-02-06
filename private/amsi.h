#pragma once
#include <windows.h>
#include <amsi.h>
#include <string>

class amsibypass {
private:
    HMODULE hamsi;
    HMODULE hntdll;
    std::string base64decode(const std::string& encoded);

public:
    amsibypass();
    ~amsibypass();
    bool patchamsiscanbuffer();
    bool patchamsiinit();
    bool memorypatch();
    bool hookamsiopensession();
    bool disableregistry();
    bool patchetw();
    bool dynamicamsi();
    bool corruptamsicontext();
    bool threadbypass();
    bool allinone();
};