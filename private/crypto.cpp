// unused crypto functions that were gonna be used in future versions

#include "crypto.h"
#include <vector>
#include <string>
std::vector<BYTE> crypto::xor_decrypt(std::vector<BYTE> data, std::vector<BYTE> key) {
    if (key.empty()) return data;
    for (size_t i = 0; i < data.size(); i++) {
        data[i] ^= key[i % key.size()];
    }
    return data;
}
std::vector<BYTE> crypto::aes_decrypt(std::vector<BYTE> data, std::vector<BYTE> key, std::vector<BYTE> iv) {
    HCRYPTPROV hprov;
    HCRYPTKEY hkey;
    HCRYPTHASH hhash;
    if (!CryptAcquireContext(&hprov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return {};
    if (!CryptCreateHash(hprov, CALG_SHA_256, 0, 0, &hhash)) { CryptReleaseContext(hprov, 0); return {}; }
    if (!CryptHashData(hhash, key.data(), (DWORD)key.size(), 0)) { CryptDestroyHash(hhash); CryptReleaseContext(hprov, 0); return {}; }
    if (!CryptDeriveKey(hprov, CALG_AES_256, hhash, 0, &hkey)) { CryptDestroyHash(hhash); CryptReleaseContext(hprov, 0); return {}; }
    CryptDestroyHash(hhash);
    DWORD datalen = (DWORD)data.size();
    if (!CryptDecrypt(hkey, 0, TRUE, 0, data.data(), &datalen)) { CryptDestroyKey(hkey); CryptReleaseContext(hprov, 0); return {}; }
    CryptDestroyKey(hkey);
    CryptReleaseContext(hprov, 0);
    data.resize(datalen);
    return data;
}
std::vector<BYTE> crypto::rc4_decrypt(std::vector<BYTE> data, std::vector<BYTE> key) {
    struct rc4_state { int x, y; BYTE m[256]; };
    rc4_state s;
    s.x = s.y = 0;
    for (int i = 0; i < 256; i++) s.m[i] = i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + s.m[i] + key[i % key.size()]) & 255;
        BYTE t = s.m[i];
        s.m[i] = s.m[j];
        s.m[j] = t;
    }
    for (size_t i = 0; i < data.size(); i++) {
        s.x = (s.x + 1) & 255;
        s.y = (s.y + s.m[s.x]) & 255;
        BYTE t = s.m[s.x];
        s.m[s.x] = s.m[s.y];
        s.m[s.y] = t;
        data[i] ^= s.m[(s.m[s.x] + s.m[s.y]) & 255];
    }
    return data;
}
std::string crypto::base64_decode(std::string encoded) {
    std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string decoded;
    int i = 0, j = 0, in_ = 0;
    unsigned char arr4[4], arr3[3];
    while (in_ < encoded.size() && encoded[in_] != '=' &&
        (isalnum(encoded[in_]) || encoded[in_] == '+' || encoded[in_] == '/')) {
        arr4[i++] = encoded[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++) arr4[i] = chars.find(arr4[i]);
            arr3[0] = (arr4[0] << 2) + ((arr4[1] & 0x30) >> 4);
            arr3[1] = ((arr4[1] & 0xf) << 4) + ((arr4[2] & 0x3c) >> 2);
            arr3[2] = ((arr4[2] & 0x3) << 6) + arr4[3];
            for (i = 0; i < 3; i++) decoded += arr3[i];
            i = 0;
        }
    }
    if (i) {
        for (j = i; j < 4; j++) arr4[j] = 0;
        for (j = 0; j < 4; j++) arr4[j] = chars.find(arr4[j]);
        arr3[0] = (arr4[0] << 2) + ((arr4[1] & 0x30) >> 4);
        arr3[1] = ((arr4[1] & 0xf) << 4) + ((arr4[2] & 0x3c) >> 2);
        arr3[2] = ((arr4[2] & 0x3) << 6) + arr4[3];
        for (j = 0; j < i - 1; j++) decoded += arr3[j];
    }
    return decoded;
}