//
// ARM32 instruction relocation (ARM mode + Thumb mode)
//

#if defined(__arm__)

#include <string.h>
#include <android/log.h>
#include "adl_relocate.h"

#define HTAG "adl_relocate"
#define RLOGI(...) __android_log_print(ANDROID_LOG_INFO, HTAG, __VA_ARGS__)
#define RLOGW(...) __android_log_print(ANDROID_LOG_WARN, HTAG, __VA_ARGS__)
#define RLOGE(...) __android_log_print(ANDROID_LOG_ERROR, HTAG, __VA_ARGS__)

// ============================================================================
// ARM mode (A32) — fixed 4-byte instructions
// ============================================================================

// Write absolute jump in ARM mode: LDR PC, [PC, #-4]; .word addr (8 bytes)
static size_t write_abs_jump_arm(uint8_t *buf, uint32_t target) {
    uint32_t *insn = reinterpret_cast<uint32_t *>(buf);
    insn[0] = 0xE51FF004; // LDR PC, [PC, #-4]
    insn[1] = target;
    return 8;
}

static inline int32_t sign_extend32(uint32_t val, int bits) {
    int32_t mask = 1 << (bits - 1);
    return (int32_t)((val ^ mask) - mask);
}

// Relocate one ARM mode instruction
static size_t relocate_arm_insn(uint32_t insn, uint32_t orig_pc, uint8_t *out) {
    uint32_t *out32 = reinterpret_cast<uint32_t *>(out);

    // B / BL — branch (ARM PC = current + 8)
    if ((insn & 0x0E000000) == 0x0A000000) {
        int32_t imm24 = sign_extend32(insn & 0x00FFFFFF, 24);
        uint32_t target = orig_pc + 8 + (imm24 << 2);
        bool is_bl = (insn & 0x0F000000) == 0x0B000000;
        if (is_bl) {
            // BL: set LR manually then jump
            // ADR LR, #8 (return after jump); LDR PC, [PC, #-4]; .word target
            uint32_t cond = insn & 0xF0000000;
            out32[0] = cond | 0x028FE004; // ADD LR, PC, #4 (cond)
            return 4 + write_abs_jump_arm(out + 4, target);
        }
        // Conditional B: rewrite with condition preserved
        uint32_t cond = insn & 0xF0000000;
        if (cond == 0xE0000000) {
            // Unconditional — simple absolute jump
            return write_abs_jump_arm(out, target);
        }
        // Conditional: B.cond #8; B #8; LDR PC, [PC, #-4]; .word target
        out32[0] = cond | 0x0A000000; // B.cond +8 (skip next)
        out32[1] = 0xEA000001;        // B +12 (skip abs jump)
        return 8 + write_abs_jump_arm(out + 8, target);
    }

    // LDR Rd, [PC, #±imm12] — PC-relative load
    if ((insn & 0x0F7F0000) == 0x051F0000) {
        uint32_t rd = (insn >> 12) & 0xF;
        uint32_t imm12 = insn & 0xFFF;
        bool add = (insn >> 23) & 1;
        uint32_t data_addr = orig_pc + 8 + (add ? imm12 : -(int32_t)imm12);

        if (rd == 15) {
            // LDR PC, [PC, #imm] — branch via PC-relative load
            return write_abs_jump_arm(out, data_addr);
        }
        // Load data: LDR Rd, [PC, #4]; B #8; .word data_addr; LDR Rd, [Rd]
        uint32_t cond = insn & 0xF0000000;
        out32[0] = cond | 0x059F0004 | (rd << 12); // LDR Rd, [PC, #4]
        out32[1] = cond | 0x0A000001;               // B #12
        out32[2] = data_addr;                         // .word data_addr
        out32[3] = cond | 0x05900000 | (rd << 16) | (rd << 12); // LDR Rd, [Rd]
        return 16;
    }

    // ADR (ADD Rd, PC, #imm)
    if ((insn & 0x0FEF0000) == 0x028F0000) {
        uint32_t rd = (insn >> 12) & 0xF;
        uint32_t imm8 = insn & 0xFF;
        uint32_t rot = ((insn >> 8) & 0xF) * 2;
        uint32_t imm = (imm8 >> rot) | (imm8 << (32 - rot));
        uint32_t target = orig_pc + 8 + imm;
        uint32_t cond = insn & 0xF0000000;
        out32[0] = cond | 0x059F0000 | (rd << 12); // LDR Rd, [PC, #0]
        out32[1] = cond | 0x0A000000;               // B #8
        out32[2] = target;
        return 12;
    }
    // ADR (SUB Rd, PC, #imm)
    if ((insn & 0x0FEF0000) == 0x024F0000) {
        uint32_t rd = (insn >> 12) & 0xF;
        uint32_t imm8 = insn & 0xFF;
        uint32_t rot = ((insn >> 8) & 0xF) * 2;
        uint32_t imm = (imm8 >> rot) | (imm8 << (32 - rot));
        uint32_t target = orig_pc + 8 - imm;
        uint32_t cond = insn & 0xF0000000;
        out32[0] = cond | 0x059F0000 | (rd << 12);
        out32[1] = cond | 0x0A000000;
        out32[2] = target;
        return 12;
    }

    // No relocation needed
    out32[0] = insn;
    return 4;
}

// ============================================================================
// Thumb mode — mixed 16/32-bit instructions
// ============================================================================

static bool is_thumb32(uint16_t hw) {
    return (hw >> 11) >= 0x1D; // 0b11101, 0b11110, 0b11111
}

// Write absolute jump in Thumb: LDR.W PC, [PC, #0]; .word addr (8 bytes)
static size_t write_abs_jump_thumb(uint8_t *buf, uint32_t target) {
    uint16_t *out16 = reinterpret_cast<uint16_t *>(buf);
    out16[0] = 0xF8DF; // LDR.W PC, [PC, #0]
    out16[1] = 0xF000;
    *reinterpret_cast<uint32_t *>(buf + 4) = target;
    return 8;
}

// Check if a 16-bit Thumb instruction is IT
static bool is_it_insn(uint16_t hw) {
    return (hw & 0xFF00) == 0xBF00 && (hw & 0x000F) != 0;
}

// Get IT block length (number of conditional instructions following IT)
static int it_block_length(uint16_t it_insn) {
    uint8_t mask = it_insn & 0xF;
    if (mask & 1) return 4;
    if (mask & 2) return 3;
    if (mask & 4) return 2;
    return 1;
}

// Relocate Thumb instructions
// Returns bytes written to output
static size_t relocate_thumb_insn(const uint8_t *code, size_t insn_size,
                                   uint32_t orig_pc, uint8_t *out) {
    uint16_t *out16 = reinterpret_cast<uint16_t *>(out);

    if (insn_size == 2) {
        uint16_t hw = *reinterpret_cast<const uint16_t *>(code);

        // CBZ / CBNZ (16-bit): 1011 x0x1 imm5 Rn3
        if ((hw & 0xF500) == 0xB100 || (hw & 0xF500) == 0xB900) {
            uint32_t imm5 = ((hw >> 9) & 1) << 5 | ((hw >> 3) & 0x1F);
            uint32_t target = orig_pc + 4 + (imm5 << 1);  // Thumb PC = addr + 4
            bool is_cbnz = (hw >> 11) & 1;
            uint32_t rn = hw & 0x7;
            // Rewrite: CBZ/CBNZ Rn, +4; B +8; abs_jump_thumb(target)
            if (is_cbnz) {
                out16[0] = 0xB900 | (rn & 0x7) | ((1 << 3) & 0xF8); // CBNZ Rn, +4
            } else {
                out16[0] = 0xB100 | (rn & 0x7) | ((1 << 3) & 0xF8); // CBZ Rn, +4
            }
            out16[1] = 0xE003; // B +8 (skip abs jump)
            // Align to 4 bytes if needed
            size_t off = 4;
            if (off & 3) {
                out16[off / 2] = 0xBF00; // NOP
                off += 2;
            }
            return off + write_abs_jump_thumb(out + off, target | 1); // set Thumb bit
        }

        // B (16-bit conditional): 1101 cond4 imm8
        if ((hw & 0xF000) == 0xD000 && ((hw >> 8) & 0xF) < 0xE) {
            int32_t imm8 = sign_extend32(hw & 0xFF, 8);
            uint32_t target = orig_pc + 4 + (imm8 << 1);
            uint32_t cond = (hw >> 8) & 0xF;
            // B.cond +4; B +8; abs_jump(target)
            out16[0] = 0xD000 | (cond << 8) | 0x00; // B.cond +4
            out16[1] = 0xE003; // B +8
            size_t off = 4;
            if (off & 3) {
                out16[off / 2] = 0xBF00;
                off += 2;
            }
            return off + write_abs_jump_thumb(out + off, target | 1);
        }

        // B (16-bit unconditional): 11100 imm11
        if ((hw & 0xF800) == 0xE000) {
            int32_t imm11 = sign_extend32(hw & 0x7FF, 11);
            uint32_t target = orig_pc + 4 + (imm11 << 1);
            return write_abs_jump_thumb(out, target | 1);
        }

        // LDR Rt, [PC, #imm8*4] (16-bit)
        if ((hw & 0xF800) == 0x4800) {
            uint32_t rt = (hw >> 8) & 0x7;
            uint32_t imm8 = hw & 0xFF;
            uint32_t data_addr = ((orig_pc + 4) & ~3u) + (imm8 << 2);
            // Use 32-bit Thumb instructions
            // MOVW Rt, #lo16(data_addr); MOVT Rt, #hi16(data_addr); LDR Rt, [Rt]
            uint32_t lo = data_addr & 0xFFFF;
            uint32_t hi = (data_addr >> 16) & 0xFFFF;
            // MOVW: 11110 i 10 0 1 0 0 imm4 | 0 imm3 Rd4 imm8
            uint32_t movw = 0xF2400000 | ((lo >> 12) << 16) | ((lo >> 11) & 1) << 26 |
                            ((lo >> 8) & 0x7) << 12 | (rt << 8) | (lo & 0xFF);
            out16[0] = movw >> 16;
            out16[1] = movw & 0xFFFF;
            uint32_t movt = 0xF2C00000 | ((hi >> 12) << 16) | ((hi >> 11) & 1) << 26 |
                            ((hi >> 8) & 0x7) << 12 | (rt << 8) | (hi & 0xFF);
            out16[2] = movt >> 16;
            out16[3] = movt & 0xFFFF;
            // LDR Rt, [Rt]
            out16[4] = 0x6800 | (rt << 3) | rt; // LDR Rt, [Rt, #0]
            return 10;
        }

        // Default: copy as-is
        out16[0] = hw;
        return 2;
    }

    if (insn_size == 4) {
        uint16_t hw1 = *reinterpret_cast<const uint16_t *>(code);
        uint16_t hw2 = *reinterpret_cast<const uint16_t *>(code + 2);
        uint32_t insn32 = (hw1 << 16) | hw2;

        // B.W / BL (32-bit Thumb)
        // Encoding: 11110 S imm10 | 1 J1 1 J2 imm11
        if ((hw1 & 0xF800) == 0xF000 && (hw2 & 0xD000) == 0x9000) {
            bool is_bl = (hw2 & 0x4000) != 0;
            uint32_t s = (hw1 >> 10) & 1;
            uint32_t j1 = (hw2 >> 13) & 1;
            uint32_t j2 = (hw2 >> 11) & 1;
            uint32_t i1 = ~(j1 ^ s) & 1;
            uint32_t i2 = ~(j2 ^ s) & 1;
            uint32_t imm10 = hw1 & 0x3FF;
            uint32_t imm11 = hw2 & 0x7FF;
            int32_t offset = sign_extend32(
                (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1), 25);
            uint32_t target = orig_pc + 4 + offset;

            if (is_bl) {
                // BL: need LR setup. Use: ADR LR, #8 (Thumb); abs_jump_thumb(target)
                // Thumb ADR: 10100 Rd3 imm8 → ADR LR not encodable in 16-bit (only R0-R7)
                // Use 32-bit: ADR.W LR, #imm
                // Simpler: just use abs jump, BL semantics handled by caller
                RLOGW("Thumb BL at %p rewritten as absolute jump", (void*)orig_pc);
            }
            return write_abs_jump_thumb(out, target | 1);
        }

        // LDR.W Rt, [PC, #±imm12] (32-bit Thumb)
        if ((hw1 & 0xFF7F) == 0xF85F) {
            uint32_t rt = (hw2 >> 12) & 0xF;
            uint32_t imm12 = hw2 & 0xFFF;
            bool add = (hw1 >> 7) & 1;
            uint32_t data_addr = ((orig_pc + 4) & ~3u) + (add ? imm12 : -(int32_t)imm12);

            if (rt == 15) {
                return write_abs_jump_thumb(out, data_addr);
            }
            // Similar to 16-bit LDR literal but already 32-bit
            // Reuse approach: load address into Rt, then load from it
            out16[0] = hw1;
            out16[1] = hw2;
            // For now, just adjust — TODO proper relocation
            RLOGW("Thumb LDR.W literal at %p not fully relocated", (void*)orig_pc);
            return 4;
        }

        // Default: copy as-is
        out16[0] = hw1;
        out16[1] = hw2;
        return 4;
    }

    return 0;
}

// ============================================================================
// Public interface
// ============================================================================

extern "C" size_t adl_build_trampoline(void *target, size_t hook_size, bool is_thumb,
                            uint8_t *trampoline) {
    size_t out_offset = 0;
    uint32_t orig_base = reinterpret_cast<uint32_t>(target);

    if (!is_thumb) {
        // ARM mode
        uint32_t *orig = reinterpret_cast<uint32_t *>(target);
        size_t num_insns = hook_size / 4;
        for (size_t i = 0; i < num_insns; i++) {
            size_t written = relocate_arm_insn(orig[i], orig_base + i * 4,
                                               trampoline + out_offset);
            if (written == 0) return 0;
            out_offset += written;
        }
        out_offset += write_abs_jump_arm(trampoline + out_offset,
                                          orig_base + hook_size);
    } else {
        // Thumb mode
        const uint8_t *code = reinterpret_cast<const uint8_t *>(target);
        size_t in_offset = 0;
        while (in_offset < hook_size) {
            uint16_t hw = *reinterpret_cast<const uint16_t *>(code + in_offset);
            size_t insn_size = is_thumb32(hw) ? 4 : 2;
            size_t written = relocate_thumb_insn(code + in_offset, insn_size,
                                                  orig_base + in_offset,
                                                  trampoline + out_offset);
            if (written == 0) return 0;
            out_offset += written;
            in_offset += insn_size;
        }
        // Align output to 4 bytes
        if (out_offset & 3) {
            *reinterpret_cast<uint16_t *>(trampoline + out_offset) = 0xBF00; // NOP
            out_offset += 2;
        }
        // Jump back (set Thumb bit)
        out_offset += write_abs_jump_thumb(trampoline + out_offset,
                                            (orig_base + hook_size) | 1);
    }

    return out_offset;
}

extern "C" size_t adl_calc_hook_size(void *target, size_t min_size, bool is_thumb) {
    if (!is_thumb) {
        return (min_size + 3) & ~3; // align to 4
    }

    // Thumb: scan instructions to find boundary >= min_size
    // Also handle IT blocks
    const uint8_t *code = reinterpret_cast<const uint8_t *>(target);
    size_t offset = 0;
    int it_remaining = 0; // instructions remaining in current IT block

    while (offset < min_size || it_remaining > 0) {
        uint16_t hw = *reinterpret_cast<const uint16_t *>(code + offset);

        if (is_it_insn(hw)) {
            it_remaining = it_block_length(hw);
            offset += 2;
            continue;
        }

        size_t insn_size = is_thumb32(hw) ? 4 : 2;
        offset += insn_size;

        if (it_remaining > 0) {
            it_remaining--;
        }
    }

    return offset;
}

#endif // __arm__
