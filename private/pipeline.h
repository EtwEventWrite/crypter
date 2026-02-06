#pragma once
#include "obfuscator.h"
#include "virtualizer.h"
#include "arm64_virtualizer.h"
#include <string>
#include <vector>
class pipeline {
private:
    obfuscator obf;
    virtualizer x64vm;
    arm64_virtualizer arm64vm;

    std::string compiler = "cl";
    std::string linkerflags = "/MT /O2 /GS-";

public:
    bool full_pipeline(const std::string& sourcefile, const std::string& outputexe);
    bool obfuscate_only(const std::string& sourcefile, const std::string& outputcpp);
    bool virtualize_only(const std::string& binaryfile, const std::string& outputbin);
    bool compile_obfuscated(const std::string& sourcefile, const std::string& outputexe);
};