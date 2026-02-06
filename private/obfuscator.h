#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <random>
#include <map>
class obfuscator {
private:
    std::vector<BYTE> key;
    std::mt19937 rng;
    std::string randstr(int len);
    std::string encstr(std::string str);
    std::vector<BYTE> encdata(std::vector<BYTE> data);
    std::string insertjunk(std::string code);
    std::string renameidents(std::string code);
    std::string controlflow(std::string code);
    std::string adddeadcode(std::string code);
public:
    obfuscator();
    std::string obfuscatecpp(std::string source);
    std::vector<BYTE> obfuscatebinary(std::vector<BYTE> binary);
    bool saveobfuscated(std::string sourcepath, std::string outputpath);
};