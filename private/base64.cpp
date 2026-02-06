// i dont even use this lol, idk why i coded it in

#include "base64.h"
#include <cctype>

static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "abcdefghijklmnopqrstuvwxyz" "0123456789+/";

static inline bool is_base64(unsigned char c)
{
    return (isalnum(c) || c == '+' || c == '/');
}

std::string Base64Decode(const std::string& encoded)
{
    int in_len = encoded.size();
    int i = 0, j = 0, in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string result;
    while (in_len-- && encoded[in_] != '=' && is_base64(encoded[in_])) {
        char_array_4[i++] = encoded[in_++];
        if (i == 4) {
            for (i = 0; i < 4; i++) char_array_4[i] = base64_chars.find(char_array_4[i]);
            char_array_3[0] = (char_array_4[0] << 2) | ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0x0F) << 4) | ((char_array_4[2] & 0x3C) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x03) << 6) | char_array_4[3];
            result.append((char*)char_array_3, 3);
            i = 0;
        }
    }
    if (i) {
        for (j = i; j < 4; j++) char_array_4[j] = 0;
        for (j = 0; j < 4; j++) char_array_4[j] = base64_chars.find(char_array_4[j]);
        char_array_3[0] = (char_array_4[0] << 2) | ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0x0F) << 4) | ((char_array_4[2] & 0x3C) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x03) << 6) | char_array_4[3];
        result.append((char*)char_array_3, i - 1);
    }
    return result;
}
