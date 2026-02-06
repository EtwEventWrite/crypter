// half of this was AI because i got bored of coding

#include "obfuscator.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
obfuscator::obfuscator() {
    std::random_device rd;
    rng = std::mt19937(rd());
    key.resize(32);
    for (int i = 0; i < 32; i++) key[i] = rng() % 256;
}
std::string obfuscator::randstr(int len) {
    static const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
    std::string str;
    for (int i = 0; i < len; i++) str += chars[rng() % (sizeof(chars) - 1)];
    return str;
}
std::string obfuscator::encstr(std::string str) {
    std::string enc = "std::string " + randstr(8) + "=\"";
    for (char c : str) {
        enc += "\\x" + std::to_string((unsigned int)c);
    }
    enc += "\";";
    return enc;
}
std::vector<BYTE> obfuscator::encdata(std::vector<BYTE> data) {
    for (size_t i = 0; i < data.size(); i++) {
        data[i] ^= key[i % key.size()];
        data[i] = ((data[i] << 4) | (data[i] >> 4)) & 0xFF;
        data[i] = ~data[i];
    }
    return data;
}
std::string obfuscator::insertjunk(std::string code) {
    std::vector<std::string> junk = {
        "if(false){/*" + randstr(20) + "*/}",
        "for(int " + randstr(6) + "=0;" + randstr(6) + "<10;" + randstr(6) + "++){}",
        "volatile int " + randstr(6) + "=rand();",
        "#pragma comment(lib,\"" + randstr(8) + ".lib\")",
        "__asm{nop;nop;nop;}",
        "try{throw 0;}catch(...){}",
        "switch(rand()%2){case 0:break;case 1:break;}",
        "do{break;}while(true);",
        "goto " + randstr(6) + ";" + randstr(6) + ":;",
        "__noop(" + randstr(10) + ");"  
    };
    size_t pos = 0;
    while ((pos = code.find(';', pos)) != std::string::npos) {
        if (rng() % 3 == 0) {
            code.insert(pos + 1, junk[rng() % junk.size()]);
            pos += junk[0].size();
        }
        pos++;
    }
    return code;
}
std::string obfuscator::renameidents(std::string code) {
    std::map<std::string, std::string> renames;
    size_t pos = 0;
    while (pos < code.size()) {
        if (isalpha(code[pos]) || code[pos] == '_') {
            size_t start = pos;
            while (pos < code.size() && (isalnum(code[pos]) || code[pos] == '_')) pos++;
            std::string ident = code.substr(start, pos - start);
            if (ident.size() > 2 && !isdigit(ident[0]) &&
                ident != "main" && ident != "if" && ident != "for" && ident != "while" &&
                ident != "return" && ident != "int" && ident != "void" && ident != "char" &&
                ident != "bool" && ident != "float" && ident != "double" && ident != "class" &&
                ident != "struct" && ident != "namespace" && ident != "using" && ident != "include" &&
                ident != "define" && ident != "pragma" && ident != "Windows.h" && ident != "vector" &&
                ident != "string" && ident != "map" && ident != "BYTE" && ident != "DWORD" &&
                ident != "LPVOID" && ident != "HMODULE" && ident != "FARPROC" && ident != "HANDLE") {
                if (renames.find(ident) == renames.end()) {
                    renames[ident] = randstr(8 + renames.size() % 10);
                }
            }
        }
        else pos++;
    }
    for (const auto& r : renames) {
        size_t ppos = 0;
        while ((ppos = code.find(r.first, ppos)) != std::string::npos) {
            if ((ppos == 0 || !isalnum(code[ppos - 1]) && code[ppos - 1] != '_') &&
                (ppos + r.first.size() >= code.size() || !isalnum(code[ppos + r.first.size()]) && code[ppos + r.first.size()] != '_')) {
                code.replace(ppos, r.first.size(), r.second);
                ppos += r.second.size();
            }
            else ppos += r.first.size();
        }
    }
    return code;
}
std::string obfuscator::controlflow(std::string code) {
    std::vector<std::string> lines;
    std::string line;
    for (char c : code) {
        if (c == '\n') {
            if (!line.empty()) lines.push_back(line);
            line.clear();
        }
        else line += c;
    }
    if (!line.empty()) lines.push_back(line);
    for (size_t i = 0; i < lines.size(); i++) {
        if (rng() % 4 == 0) {
            std::string var = randstr(6);
            lines[i] = "int " + var + "=" + std::to_string(rng() % 100) + ";if(" + var + "!=" + std::to_string(rng() % 100) + "){" + lines[i] + "}";
        }
        if (rng() % 5 == 0) {
            std::string label = randstr(6);
            lines[i] = "goto " + label + ";" + label + ":" + lines[i];
        }
    }
    code.clear();
    for (const auto& l : lines) code += l + "\n";
    return code;
}
std::string obfuscator::adddeadcode(std::string code) {
    std::vector<std::string> dead = {
        "int " + randstr(6) + "[]={" + std::to_string(rng() % 100) + "," + std::to_string(rng() % 100) + "};",
        "char " + randstr(6) + "[100];memset(" + randstr(6) + ",0,100);",
        "float " + randstr(6) + "=3.14159f;",
        "double " + randstr(6) + "=2.71828;",
        "bool " + randstr(6) + "=true;",
        "void* " + randstr(6) + "=malloc(100);free(" + randstr(6) + ");",
        "Sleep(1);",
        "GetTickCount();",
        "rand();srand(time(NULL));",
        "MessageBoxA(NULL,\"" + randstr(10) + "\",\"" + randstr(8) + "\",MB_OK);"
    };
    size_t ins = code.find('{');
    if (ins != std::string::npos) {
        for (int i = 0; i < 3 + rng() % 5; i++) {
            code.insert(ins + 1, dead[rng() % dead.size()] + "\n");
        }
    }
    return code;
}
std::string obfuscator::obfuscatecpp(std::string source) {
    source = renameidents(source);
    source = insertjunk(source);
    source = controlflow(source);
    source = adddeadcode(source);
    std::string obfuscated = "#include <Windows.h>\n";
    obfuscated += "#include <vector>\n#include <string>\n#include <map>\n";
    obfuscated += "#include <random>\n#include <fstream>\n\n";
    obfuscated += "// For I am the honored one.\n";
    obfuscated += "// Key: ";
    for (BYTE b : key) {
        char buf[3];
        obfuscated += buf;
    }
    obfuscated += "\n\n";
    obfuscated += source;
    return obfuscated;
}
std::vector<BYTE> obfuscator::obfuscatebinary(std::vector<BYTE> binary) {
    std::vector<BYTE> obfuscated;
    obfuscated.push_back(0x4D);
    obfuscated.push_back(0x5A);
    for (BYTE b : key) obfuscated.push_back(b);
    std::vector<BYTE> enc = encdata(binary);
    for (BYTE b : enc) obfuscated.push_back(b);
    return obfuscated;
}
bool obfuscator::saveobfuscated(std::string sourcepath, std::string outputpath) {
    std::ifstream in(sourcepath);
    if (!in) return false;
    std::string source((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    std::string obfuscated = obfuscatecpp(source);

    std::ofstream out(outputpath);
    if (!out) return false;
    out << obfuscated;
    out.close();

    return true;
}