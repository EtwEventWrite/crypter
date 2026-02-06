#pragma once
#include <Windows.h>
#include <string>
#include <vector>
class antianalysis {
private:
    bool checkcpuid();
    bool checkcpucores();
    bool checkram();
    bool checkdisk();
    bool checkuptime();
    bool checkprocesses();
    bool checkdrivers();
    bool checkwindows();
    bool checkdebugger();
    bool checkvmreg();
    bool checkvmacpi();
    bool checkvmmac();
    bool checksandboxuser();
    bool checksleep();
public:
    bool runallchecks();
    bool isvm();
    bool issandbox();
    bool isdebugged();
};