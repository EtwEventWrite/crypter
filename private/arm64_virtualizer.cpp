// not really a virtualizer

#include "arm64_virtualizer.h"
#include <algorithm>
#include <bitset>
#include <chrono>

arm64_virtualizer::arm64_virtualizer() : rng(std::random_device{}()) {
    memory.data.resize(1024 * 1024);
    memory.base = 0x100000;

    handlers[0x1A000000] = [&](vm_instr& instr) { // MOV (wide immediate)
        uint32_t rd = (instr.opcode >> 0) & 0x1F;
        uint64_t imm = ((instr.opcode >> 5) & 0xFFFF) << 16;
        imm |= (instr.opcode >> 21) & 0xFFFF;
        imm <<= ((instr.opcode >> 16) & 0x3F);
        regs.x[rd] = imm;
    };

    handlers[0x91000000] = [&](vm_instr& instr) { // ADD (immediate)
        uint32_t rd = (instr.opcode >> 0) & 0x1F;
        uint32_t rn = (instr.opcode >> 5) & 0x1F;
        uint32_t imm = (instr.opcode >> 10) & 0xFFF;
        uint32_t shift = (instr.opcode >> 22) & 0x3;
        if (shift == 1) imm <<= 12;
        regs.x[rd] = regs.x[rn] + imm;
    };

    handlers[0xD1000000] = [&](vm_instr& instr) { // SUB (immediate)
        uint32_t rd = (instr.opcode >> 0) & 0x1F;
        uint32_t rn = (instr.opcode >> 5) & 0x1F;
        uint32_t imm = (instr.opcode >> 10) & 0xFFF;
        uint32_t shift = (instr.opcode >> 22) & 0x3;
        if (shift == 1) imm <<= 12;
        regs.x[rd] = regs.x[rn] - imm;
    };

    handlers[0x8B000000] = [&](vm_instr& instr) { // ADD (shifted register)
        uint32_t rd = (instr.opcode >> 0) & 0x1F;
        uint32_t rn = (instr.opcode >> 5) & 0x1F;
        uint32_t rm = (instr.opcode >> 16) & 0x1F;
        uint32_t shift = (instr.opcode >> 22) & 0x3;
        uint32_t amount = (instr.opcode >> 10) & 0x3F;
        uint64_t shifted = regs.x[rm];
        if (shift == 0) shifted <<= amount;
        else if (shift == 1) shifted >>= amount;
        else if (shift == 2) shifted = (int64_t)shifted >> amount;
        regs.x[rd] = regs.x[rn] + shifted;
    };

    handlers[0xCB000000] = [&](vm_instr& instr) { // SUB (shifted register)
        uint32_t rd = (instr.opcode >> 0) & 0x1F;
        uint32_t rn = (instr.opcode >> 5) & 0x1F;
        uint32_t rm = (instr.opcode >> 16) & 0x1F;
        uint32_t shift = (instr.opcode >> 22) & 0x3;
        uint32_t amount = (instr.opcode >> 10) & 0x3F;
        uint64_t shifted = regs.x[rm];
        if (shift == 0) shifted <<= amount;
        else if (shift == 1) shifted >>= amount;
        else if (shift == 2) shifted = (int64_t)shifted >> amount;
        regs.x[rd] = regs.x[rn] - shifted;
    };

    handlers[0xCA000000] = [&](vm_instr& instr) { // EOR (shifted register)
        uint32_t rd = (instr.opcode >> 0) & 0x1F;
        uint32_t rn = (instr.opcode >> 5) & 0x1F;
        uint32_t rm = (instr.opcode >> 16) & 0x1F;
        uint32_t shift = (instr.opcode >> 22) & 0x3;
        uint32_t amount = (instr.opcode >> 10) & 0x3F;
        uint64_t shifted = regs.x[rm];
        if (shift == 0) shifted <<= amount;
        else if (shift == 1) shifted >>= amount;
        regs.x[rd] = regs.x[rn] ^ shifted;
    };

    handlers[0x58000000] = [&](vm_instr& instr) { // LDR (literal)
        uint32_t rt = (instr.opcode >> 0) & 0x1F;
        int32_t imm = (instr.opcode >> 5) & 0x7FFFF;
        imm <<= 2;
        uint64_t addr = regs.pc + imm;
        if (addr >= memory.base && addr < memory.base + memory.data.size()) {
            regs.x[rt] = *(uint64_t*)&memory.data[addr - memory.base];
        }
    };

    handlers[0x39000000] = [&](vm_instr& instr) { // STRB (immediate)
        uint32_t rt = (instr.opcode >> 0) & 0x1F;
        uint32_t rn = (instr.opcode >> 5) & 0x1F;
        uint32_t imm = (instr.opcode >> 10) & 0xFFF;
        uint64_t addr = regs.x[rn] + imm;
        if (addr >= memory.base && addr < memory.base + memory.data.size()) {
            memory.data[addr - memory.base] = regs.x[rt] & 0xFF;
        }
    };

    handlers[0xB9400000] = [&](vm_instr& instr) { // LDR (immediate)
        uint32_t rt = (instr.opcode >> 0) & 0x1F;
        uint32_t rn = (instr.opcode >> 5) & 0x1F;
        uint32_t imm = (instr.opcode >> 10) & 0xFFF;
        imm <<= 2;
        uint64_t addr = regs.x[rn] + imm;
        if (addr >= memory.base && addr < memory.base + memory.data.size()) {
            regs.x[rt] = *(uint32_t*)&memory.data[addr - memory.base];
        }
    };

    handlers[0x14000000] = [&](vm_instr& instr) { // B (unconditional)
        int32_t imm = (instr.opcode >> 0) & 0x3FFFFFF;
        imm <<= 2;
        regs.pc += imm;
    };

    handlers[0x34000000] = [&](vm_instr& instr) { // CBZ/CBNZ
        uint32_t rt = (instr.opcode >> 0) & 0x1F;
        int32_t imm = (instr.opcode >> 5) & 0x7FFFF;
        imm <<= 2;
        uint32_t bit = (instr.opcode >> 24) & 0x1;
        if ((bit == 0 && regs.x[rt] == 0) || (bit == 1 && regs.x[rt] != 0)) {
            regs.pc += imm;
        }
    };

    handlers[0x54000000] = [&](vm_instr& instr) { // B.cond
        uint32_t cond = (instr.opcode >> 0) & 0xF;
        int32_t imm = (instr.opcode >> 5) & 0x7FFFF;
        imm <<= 2;

        bool take = false;
        uint32_t n = (regs.nzcv >> 31) & 1;
        uint32_t z = (regs.nzcv >> 30) & 1;
        uint32_t c = (regs.nzcv >> 29) & 1;
        uint32_t v = (regs.nzcv >> 28) & 1;

        switch (cond) {
        case 0: take = z; break; // EQ
        case 1: take = !z; break; // NE
        case 2: take = c; break; // CS/HS
        case 3: take = !c; break; // CC/LO
        case 4: take = n; break; // MI
        case 5: take = !n; break; // PL
        case 6: take = v; break; // VS
        case 7: take = !v; break; // VC
        case 8: take = c && !z; break; // HI
        case 9: take = !c || z; break; // LS
        case 10: take = n == v; break; // GE
        case 11: take = n != v; break; // LT
        case 12: take = !z && (n == v); break; // GT
        case 13: take = z || (n != v); break; // LE
        case 14: take = true; break; // AL
        }

        if (take) regs.pc += imm;
    };

    handlers[0xD4000000] = [&](vm_instr& instr) { // BR/BLR/RET
        uint32_t rn = (instr.opcode >> 5) & 0x1F;
        uint32_t opc = (instr.opcode >> 21) & 0x3;
        if (opc == 0) { // BR
            regs.pc = regs.x[rn];
        }
        else if (opc == 1) { // BLR
            uint64_t lr = regs.pc;
            regs.pc = regs.x[rn];
            regs.x[30] = lr;
        }
        else if (opc == 2) { // RET
            regs.pc = regs.x[rn];
        }
    };

    handlers[0xD503201F] = [&](vm_instr& instr) { // NOP
        // Do nothing
    };
}

uint32_t arm64_virtualizer::rnd32() {
    return rng();
}

uint64_t arm64_virtualizer::rnd64() {
    return ((uint64_t)rng() << 32) | rng();
}

uint32_t arm64_virtualizer::rnd_reg() {
    return rng() % 30; // Skip X29(FP), X30(LR), X31(SP/ZR)
}

uint32_t arm64_virtualizer::rnd_vreg() {
    return rng() % 32;
}

uint32_t arm64_virtualizer::rnd_cond() {
    return rng() % 15;
}

uint32_t arm64_virtualizer::rnd_shift() {
    return rng() % 4;
}

uint32_t arm64_virtualizer::decode_arm64(uint32_t instr) {
    for (const auto& pair : handlers) {
        uint32_t mask = pair.first;
        if ((instr & 0xFF000000) == (mask & 0xFF000000)) {
            return mask;
        }
    }
}

void arm64_virtualizer::add_junk_instr() {
    static std::vector<uint32_t> junk_instrs = {
        0xD503201F, // NOP
        0xD503209F, // SEV
        0xD50320BF, // WFE
        0xD50320DF, // WFI
        0xD50320FF, // YIELD
        0xD503237F, // PACIA1716
        0xD50323FF, // AUTIA1716
        0x92400000 | (rnd_reg() << 0) | (rnd_reg() << 5), // AND (immediate)
        0x321E0000 | (rnd_reg() << 0) | (rnd_reg() << 5), // ORR (immediate)
        0x72000000 | (rnd_reg() << 0) | (rnd_reg() << 5), // ANDS (immediate)
    };

    vm_instr junk;
    junk.opcode = junk_instrs[rng() % junk_instrs.size()];
    junk.size = 4;
    program.push_back(junk);
}

void arm64_virtualizer::add_bogus_branch() {
    uint32_t opcode = 0x14000000; // B
    uint32_t imm = (rng() & 0x3FFFFFF);
    opcode |= (imm & 0x3FFFFFF);

    vm_instr branch;
    branch.opcode = opcode;
    branch.size = 4;
    program.push_back(branch);
}

void arm64_virtualizer::add_obfuscated_const() {
    uint64_t value = rnd64();
    uint32_t rd = rnd_reg();

    std::vector<uint32_t> instrs;

    if ((value & 0xFFFF) == value) {
        instrs.push_back(0x52800000 | (rd << 0) | ((value & 0xFFFF) << 5)); // MOVZ
    }
    else if (((value >> 16) & 0xFFFF) == (value >> 16)) {
        instrs.push_back(0x52800000 | (rd << 0) | ((1 << 21) | ((value >> 16) & 0xFFFF) << 5)); // MOVZ LSL #16
    }
    else if (((value >> 32) & 0xFFFF) == (value >> 32)) {
        instrs.push_back(0x52800000 | (rd << 0) | ((2 << 21) | ((value >> 32) & 0xFFFF) << 5)); // MOVZ LSL #32
    }
    else if (((value >> 48) & 0xFFFF) == (value >> 48)) {
        instrs.push_back(0x52800000 | (rd << 0) | ((3 << 21) | ((value >> 48) & 0xFFFF) << 5)); // MOVZ LSL #48
    }
    else {
        for (int i = 0; i < 4; i++) {
            uint16_t part = (value >> (i * 16)) & 0xFFFF;
            if (part != 0) {
                instrs.push_back(0x52800000 | (rd << 0) | ((i << 21) | (part << 5))); // MOVZ
                if (i > 0) {
                    uint16_t prev = (value >> ((i - 1) * 16)) & 0xFFFF;
                    if (prev != 0) {
                        instrs.push_back(0x52800000 | (rnd_reg() << 0) | (((i - 1) << 21) | (prev << 5)));
                    }
                }
            }
        }
    }

    for (auto instr : instrs) {
        vm_instr vi;
        vi.opcode = instr;
        vi.size = 4;
        program.push_back(vi);
    }
}

void arm64_virtualizer::add_spaghetti() {
    size_t start = program.size();

    for (int i = 0; i < 5 + (rng() % 10); i++) {
        add_junk_instr();
    }

    uint32_t cond = rnd_cond();
    uint32_t target = (rng() % 50) * 4;

    vm_instr branch;
    branch.opcode = 0x54000000 | (cond << 0) | ((target >> 2) << 5);
    branch.size = 4;
    program.push_back(branch);

    for (int i = 0; i < 3 + (rng() % 7); i++) {
        add_junk_instr();
    }

    vm_instr label;
    label.opcode = 0xD503201F; // NOP as label
    label.size = 4;
    program.insert(program.begin() + start + target / 4, label);
}

void arm64_virtualizer::shuffle_blocks() {
    if (program.size() < 10) return;

    size_t block_size = 4 + (rng() % 8);
    std::vector<std::vector<vm_instr>> blocks;

    for (size_t i = 0; i < program.size(); i += block_size) {
        size_t end = std::min<size_t>(i + block_size, program.size());
        blocks.emplace_back(program.begin() + i, program.begin() + end);
    }

    std::shuffle(blocks.begin(), blocks.end(), rng);

    program.clear();
    for (auto& block : blocks) {
        program.insert(program.end(), block.begin(), block.end());
    }

    for (size_t i = 0; i < program.size(); i++) {
        if ((program[i].opcode & 0xFC000000) == 0x14000000) {
            int32_t imm = (program[i].opcode & 0x3FFFFFF) << 2;
            size_t target_idx = i + (imm / 4);

            if (target_idx < program.size()) {
                size_t new_target = rng() % program.size();
                int32_t new_imm = (new_target - i) * 4;
                program[i].opcode = (program[i].opcode & ~0x3FFFFFF) | ((new_imm >> 2) & 0x3FFFFFF);
            }
        }
    }
}

std::vector<uint8_t> arm64_virtualizer::virtualize(const std::vector<uint8_t>& arm64_code) {
    program.clear();
    regs.x.fill(0);
    regs.v.fill(0);
    regs.sp = memory.base + memory.data.size();
    regs.pc = memory.base;
    regs.nzcv = 0;
    regs.fpcr = 0;
    regs.fpsr = 0;

    for (size_t i = 0; i < arm64_code.size(); i += 4) {
        if (i + 4 <= arm64_code.size()) {
            uint32_t instr = *(uint32_t*)&arm64_code[i];
            uint32_t type = decode_arm64(instr);

            vm_instr vi;
            vi.opcode = instr;
            vi.size = 4;

            if (type != 0 && (rng() % 3) != 0) {
                program.push_back(vi);

                if (rng() % 4 == 0) {
                    add_junk_instr();
                }

                if (rng() % 8 == 0) {
                    add_obfuscated_const();
                }

                if (rng() % 10 == 0) {
                    add_spaghetti();
                }
            }
            else {
                add_bogus_branch();
                program.push_back(vi);
            }
        }
    }

    shuffle_blocks();

    std::vector<uint8_t> virtualized;
    for (auto& instr : program) {
        uint8_t* ptr = (uint8_t*)&instr.opcode;
        virtualized.insert(virtualized.end(), ptr, ptr + instr.size);

        if (rng() % 5 == 0) {
            virtualized.push_back(rng() % 256);
            virtualized.push_back(rng() % 256);
        }
    }

    return virtualized;
}

void arm64_virtualizer::execute() {
    regs.pc = memory.base;

    while (regs.pc < memory.base + program.size() * 4) {
        size_t idx = (regs.pc - memory.base) / 4;
        if (idx >= program.size()) break;

        vm_instr& instr = program[idx];
        uint32_t type = decode_arm64(instr.opcode);

        auto it = handlers.find(type);
        if (it != handlers.end()) {
            it->second(instr);
        }

        if ((instr.opcode & 0xFF000000) != 0x14000000 &&
            (instr.opcode & 0xFF000000) != 0x54000000 &&
            (instr.opcode & 0xFF000000) != 0x34000000 &&
            (instr.opcode & 0xFC000000) != 0xD4000000) {
            regs.pc += 4;
        }
    }
}

void arm64_virtualizer::dump_state() {
    printf("ARM64 Virtual Machine State:\n");
    for (int i = 0; i < 32; i++) {
        if (regs.x[i] != 0) {
            printf("X%-2d = 0x%016llX\n", i, regs.x[i]);
        }
    }
    printf("SP  = 0x%016llX\n", (unsigned long long)regs.sp);
    printf("PC  = 0x%016llX\n", (unsigned long long)regs.pc);
    printf("NZCV= 0x%016llX\n", (unsigned long long)regs.nzcv);
}