// helper func

#include "pipeline.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdlib>
bool pipeline::full_pipeline(const std::string& sourcefile, const std::string& outputexe) {
    std::cout << "[private] Obfuscating source...\n";
    if (!obf.saveobfuscated(sourcefile, "temp_obf.cpp")) {
        std::cout << "failed to obfuscate source\n";
        return false;
    }

    std::cout << "[private] Compiling obfuscated code...\n";
    std::string compilecmd = compiler + " " + linkerflags + " temp_obf.cpp /Fe:temp_binary.exe";
    if (system(compilecmd.c_str()) != 0) {
        std::cout << "compilation failed\n";
        return false;
    }

    std::cout << "[private] Reading compiled binary...\n";
    std::ifstream bin("temp_binary.exe", std::ios::binary);
    if (!bin) {
        std::cout << "failed to read binary\n";
        return false;
    }
    std::vector<uint8_t> binary((std::istreambuf_iterator<char>(bin)), std::istreambuf_iterator<char>());
    bin.close();

    std::cout << "[private] Virtualizing binary...\n";
    auto virtualized = x64vm.virtualize(binary);

    std::cout << "[private] Creating loader stub...\n";
    std::string loader = R"(
#include <Windows.h>
#include <vector>
unsigned char virtualized[]={)";

    for (size_t i = 0; i < virtualized.size(); i++) {
        char buf[8];
        loader += buf;
        if (i % 20 == 19) loader += "\n";
    }
    loader += R"(};
int main() {
    DWORD oldprotect;
    VirtualProtect(virtualized,sizeof(virtualized),PAGE_EXECUTE_READWRITE,&oldprotect);
    ((void(*)())virtualized)();
    return 0;
})";

    std::ofstream loaderfile("loader.cpp");
    loaderfile << loader;
    loaderfile.close();

    std::cout << "[6] Compiling final executable...\n";
    std::string finalcmd = compiler + " " + linkerflags + " loader.cpp /Fe:" + outputexe;
    if (system(finalcmd.c_str()) != 0) {
        std::cout << "final compilation failed\n";
        return false;
    }

    std::remove("temp_obf.cpp");
    std::remove("temp_binary.exe");
    std::remove("loader.cpp");

    std::cout << "Pipeline complete: " << outputexe << "\n";
    return true;
}
bool pipeline::obfuscate_only(const std::string& sourcefile, const std::string& outputcpp) {
    return obf.saveobfuscated(sourcefile, outputcpp);
}
bool pipeline::virtualize_only(const std::string& binaryfile, const std::string& outputbin) {
    std::ifstream in(binaryfile, std::ios::binary);
    if (!in) return false;
    std::vector<uint8_t> binary((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    auto virtualized = x64vm.virtualize(binary);

    std::ofstream out(outputbin, std::ios::binary);
    out.write((char*)virtualized.data(), virtualized.size());
    out.close();

    return true;
}
bool pipeline::compile_obfuscated(const std::string& sourcefile, const std::string& outputexe) {
    if (!obf.saveobfuscated(sourcefile, "obfuscated.cpp")) return false;

    std::string cmd = compiler + " " + linkerflags + " obfuscated.cpp /Fe:" + outputexe;
    if (system(cmd.c_str()) != 0) return false;

    std::remove("obfuscated.cpp");
    return true;
}