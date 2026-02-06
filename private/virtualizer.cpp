// not really a virtualizer

#include "virtualizer.h"
#include <algorithm>
#include <intrin.h>

virtualizer::virtualizer() :rng(std::random_device{}()) {
    init_handlers();
}

void virtualizer::init_handlers() {
    handlers[0x00] = [](vmctx& ctx, const vmop& op) {
        if (op.operands.size() >= 9) {
            uint8_t reg = op.operands[0];
            uint64_t imm = *(uint64_t*)&op.operands[1];
            ctx.regs[reg % ctx.regs.size()] = imm;
        }
    };
    handlers[0x01] = [](vmctx& ctx, const vmop& op) {
        if (op.operands.size() >= 2) {
            uint8_t r1 = op.operands[0];
            uint8_t r2 = op.operands[1];
            ctx.regs[r1 % ctx.regs.size()] += ctx.regs[r2 % ctx.regs.size()];
        }
    };
    handlers[0x02] = [](vmctx& ctx, const vmop& op) {
        if (op.operands.size() >= 2) {
            uint8_t r1 = op.operands[0];
            uint8_t r2 = op.operands[1];
            ctx.regs[r1 % ctx.regs.size()] -= ctx.regs[r2 % ctx.regs.size()];
        }
    };
    handlers[0x03] = [](vmctx& ctx, const vmop& op) {
        if (op.operands.size() >= 2) {
            uint8_t r1 = op.operands[0];
            uint8_t r2 = op.operands[1];
            ctx.regs[r1 % ctx.regs.size()] ^= ctx.regs[r2 % ctx.regs.size()];
        }
    };
    handlers[0x04] = [](vmctx& ctx, const vmop& op) {
        if (!op.operands.empty()) {
            uint8_t reg = op.operands[0];
            ctx.sp -= 8;
            *(uint64_t*)&ctx.mem[ctx.sp % ctx.mem.size()] = ctx.regs[reg % ctx.regs.size()];
        }
    };
    handlers[0x05] = [](vmctx& ctx, const vmop& op) {
        if (!op.operands.empty()) {
            uint8_t reg = op.operands[0];
            ctx.regs[reg % ctx.regs.size()] = *(uint64_t*)&ctx.mem[ctx.sp % ctx.mem.size()];
            ctx.sp += 8;
        }
    };
    handlers[0x06] = [](vmctx& ctx, const vmop& op) {
        if (op.operands.size() >= 8) {
            ctx.ip = *(uint64_t*)&op.operands[0];
        }
    };
    handlers[0x07] = [](vmctx& ctx, const vmop& op) {
        if (op.operands.size() >= 8) {
            ctx.sp -= 8;
            *(uint64_t*)&ctx.mem[ctx.sp % ctx.mem.size()] = ctx.ip;
            ctx.ip = *(uint64_t*)&op.operands[0];
        }
    };
    handlers[0x08] = [](vmctx& ctx, const vmop& op) {
        ctx.ip = *(uint64_t*)&ctx.mem[ctx.sp % ctx.mem.size()];
        ctx.sp += 8;
    };
    handlers[0x09] = [](vmctx& ctx, const vmop& op) {
        if (op.operands.size() >= 9) {
            uint8_t reg = op.operands[0];
            uint64_t addr = *(uint64_t*)&op.operands[1];
            ctx.regs[reg % ctx.regs.size()] = *(uint64_t*)&ctx.mem[addr % ctx.mem.size()];
        }
    };
    handlers[0x0a] = [](vmctx& ctx, const vmop& op) {
        if (op.operands.size() >= 9) {
            uint8_t reg = op.operands[0];
            uint64_t addr = *(uint64_t*)&op.operands[1];
            *(uint64_t*)&ctx.mem[addr % ctx.mem.size()] = ctx.regs[reg % ctx.regs.size()];
        }
    };
}

uint64_t virtualizer::rndimm() {
    return rng();
}

uint8_t virtualizer::rndreg() {
    return rng() % 16;
}

std::vector<uint8_t> virtualizer::junk_bytes(size_t count) {
    std::vector<uint8_t> junk(count);
    for (auto& b : junk)b = rng() % 256;
    return junk;
}

std::vector<uint8_t> virtualizer::encode_op(uint8_t opcode, const std::vector<uint64_t>& operands) {
    std::vector<uint8_t> encoded;
    encoded.push_back(opcode);
    for (auto op : operands) {
        uint8_t* ptr = (uint8_t*)&op;
        encoded.insert(encoded.end(), ptr, ptr + sizeof(op));
    }
    return encoded;
}

std::vector<uint8_t> virtualizer::virtualize(const std::vector<uint8_t>& native_code) {
    bytecode.clear();
    ctx.regs.assign(16, 0);
    ctx.mem.assign(65536, 0);
    ctx.ip = 0;
    ctx.sp = ctx.mem.size() - 8;
    ctx.flags = 0;
    auto junk = junk_bytes(rng() % 8);
    size_t i = 0;
    while (i < native_code.size()) {
        uint8_t op = native_code[i];
        switch (op) {
        case 0x48:
            if (i + 1 < native_code.size()) {
                uint8_t next = native_code[i + 1];
                if (next == 0xb8) {
                    uint64_t imm = *(uint64_t*)&native_code[i + 2];
                    bytecode.insert(bytecode.end(), junk.begin(), junk.end());
                    auto enc = encode_op(0x00, { rndreg(),imm });
                    bytecode.insert(bytecode.end(), enc.begin(), enc.end());
                    i += 10;
                }
                else if (next == 0x89) {
                    bytecode.insert(bytecode.end(), junk.begin(), junk.end());
                    auto enc = encode_op(0x0a, { rndreg(),rndimm() });
                    bytecode.insert(bytecode.end(), enc.begin(), enc.end());
                    i += 3;
                }
                else if (next == 0x83 && i + 3 < native_code.size() && native_code[i + 2] == 0xc0) {
                    bytecode.insert(bytecode.end(), junk.begin(), junk.end());
                    auto enc = encode_op(0x01, { rndreg(),(uint64_t)native_code[i + 3] });
                    bytecode.insert(bytecode.end(), enc.begin(), enc.end());
                    i += 4;
                }
            }
            break;
        case 0xff:
            if (i + 1 < native_code.size() && native_code[i + 1] == 0x15) {
                bytecode.insert(bytecode.end(), junk.begin(), junk.end());
                auto enc = encode_op(0x07, { rndimm() });
                bytecode.insert(bytecode.end(), enc.begin(), enc.end());
                i += 6;
            }
            break;
        case 0xe8: {
            bytecode.insert(bytecode.end(), junk.begin(), junk.end());
            int32_t rel = *(int32_t*)&native_code[i + 1];
            auto enc = encode_op(0x07, { (uint64_t)(i + rel + 5) });
            bytecode.insert(bytecode.end(), enc.begin(), enc.end());
            i += 5;
            break; }
        case 0xc3:
            bytecode.insert(bytecode.end(), junk.begin(), junk.end());
            bytecode.push_back(0x08);
            i++;
            break;
        default:
            bytecode.push_back(native_code[i]);
            i++;
            break;
        }
        if (rng() % 3 == 0)bytecode.insert(bytecode.end(), junk.begin(), junk.end());
    }
    return bytecode;
}

std::vector<uint8_t> virtualizer::execute() {
    std::vector<uint8_t> output;
    while (ctx.ip < bytecode.size()) {
        uint8_t opcode = bytecode[ctx.ip++];
        vmop op;
        op.opcode = opcode;
        auto it = handlers.find(opcode);
        if (it != handlers.end()) {
            size_t oplen = 0;
            switch (opcode) {
            case 0x00:case 0x09:case 0x0a:oplen = 9; break;
            case 0x06:case 0x07:oplen = 8; break;
            case 0x01:case 0x02:case 0x03:case 0x04:case 0x05:oplen = 1; break;
            case 0x08:oplen = 0; break;
            }
            if (ctx.ip + oplen <= bytecode.size()) {
                op.operands.assign(bytecode.begin() + ctx.ip, bytecode.begin() + ctx.ip + oplen);
                ctx.ip += oplen;
                it->second(ctx, op);
            }
        }
    }
    for (auto r : ctx.regs) {
        uint8_t* p = (uint8_t*)&r;
        output.insert(output.end(), p, p + 8);
    }
    uint8_t* f = (uint8_t*)&ctx.flags;
    output.insert(output.end(), f, f + 8);
    size_t tail = 256;
    output.insert(output.end(), ctx.mem.end() - tail, ctx.mem.end());
    return output;
}
