#pragma once
#include <windows.h>
#include <vector>
#include <map>
#include <random>
#include <functional>
class virtualizer {
private:
    struct vmctx {
        std::vector<uint64_t> regs;
        uint64_t ip;
        uint64_t sp;
        uint64_t flags;
        std::vector<uint8_t> mem;
    };
    struct vmop {
        uint8_t opcode;
        std::vector<uint8_t> operands;
        const uint8_t* data;
    };
    std::mt19937_64 rng;
    std::vector<uint8_t> bytecode;
    std::map<uint8_t, std::function<void(vmctx&, const vmop&)>> handlers;
    vmctx ctx;
    void init_handlers();
    uint64_t rndimm();
    uint8_t rndreg();
    std::vector<uint8_t> encode_op(uint8_t opcode, const std::vector<uint64_t>& operands);
    std::vector<uint8_t> junk_bytes(size_t count);
public:
    virtualizer();
    std::vector<uint8_t> virtualize(const std::vector<uint8_t>& native_code);
    std::vector<uint8_t> execute();
};
