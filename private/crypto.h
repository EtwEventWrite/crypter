#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <wincrypt.h>
#pragma comment(lib,"crypt32.lib")
class crypto {
public:
    static std::vector<BYTE> xor_decrypt(std::vector<BYTE> data, std::vector<BYTE> key);
    static std::vector<BYTE> aes_decrypt(std::vector<BYTE> data, std::vector<BYTE> key, std::vector<BYTE> iv);
    static std::vector<BYTE> rc4_decrypt(std::vector<BYTE> data, std::vector<BYTE> key);
    static std::string base64_decode(std::string encoded);
    static std::vector<BYTE> gzip_decompress(std::vector<BYTE> data); // todo
};