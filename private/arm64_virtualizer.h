#pragma once
#include <Windows.h>
#include <vector>
#include <map>
#include <random>
#include <array>
#include <functional>
#include <intrin.h>

class arm64_virtualizer {
private:
    struct vm_regs {
        std::array<uint64_t, 32> x;    // X0-X31
        std::array<uint64_t, 32> v;    // V0-V31 (SIMD)
        uint64_t sp;
        uint64_t pc;
        uint64_t nzcv;                 // PSTATE.NZCV
        uint64_t fpcr;
        uint64_t fpsr;
    };
    struct vm_instr {
        uint32_t opcode;
        std::vector<uint32_t> operands;
        uint32_t cond;
        uint32_t size;
    };
    struct vm_mem {
        std::vector<uint8_t> data;
        std::map<uint64_t, uint64_t> pages;
        uint64_t base;
    };
    vm_regs regs;
    vm_mem memory;
    std::vector<vm_instr> program;
    std::mt19937_64 rng;
    std::map<uint32_t, std::function<void(vm_instr&)>> handlers;
    uint32_t rnd32();
    uint64_t rnd64();
    uint32_t rnd_reg();
    uint32_t rnd_vreg();
    uint32_t rnd_cond();
    uint32_t rnd_shift();
    uint32_t decode_arm64(uint32_t instr);
    void add_junk_instr();
    void add_bogus_branch();
    void add_obfuscated_const();
    void add_spaghetti();
    void shuffle_blocks();
public:
    arm64_virtualizer();
    std::vector<uint8_t> virtualize(const std::vector<uint8_t>& arm64_code);
    void execute();
    void dump_state();
};