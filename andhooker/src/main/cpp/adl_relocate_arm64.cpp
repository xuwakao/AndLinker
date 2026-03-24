//
// ARM64 instruction relocation for inline hook trampoline
//

#if defined(__aarch64__)

#include <string.h>
#include <android/log.h>
#include "adl_relocate.h"

#define HTAG "adl_relocate"
#define RLOGI(...) __android_log_print(ANDROID_LOG_INFO, HTAG, __VA_ARGS__)
#define RLOGW(...) __android_log_print(ANDROID_LOG_WARN, HTAG, __VA_ARGS__)
#define RLOGE(...) __android_log_print(ANDROID_LOG_ERROR, HTAG, __VA_ARGS__)

#define ARM64_HOOK_SIZE 16

// Write absolute jump: LDR X17, #8; BR X17; .quad addr (16 bytes)
static size_t write_abs_jump(uint8_t *buf, uint64_t target) {
    uint32_t *insn = reinterpret_cast<uint32_t *>(buf);
    insn[0] = 0x58000051; // LDR X17, #8
    insn[1] = 0xD61F0220; // BR X17
    *reinterpret_cast<uint64_t *>(buf + 8) = target;
    return 16;
}

// Sign-extend a value of given bit width
static inline int64_t sign_extend(uint64_t val, int bits) {
    int64_t mask = 1LL << (bits - 1);
    return (int64_t)((val ^ mask) - mask);
}

// Relocate one ARM64 instruction.
// Returns bytes written to output buffer.
static size_t relocate_insn(uint32_t insn, uint64_t orig_pc,
                            uint8_t *out, uint64_t new_pc) {
    uint32_t *out32 = reinterpret_cast<uint32_t *>(out);

    // ---- B / BL (unconditional branch) ----
    // Encoding: [0] x 0 0 1 0 1 imm26
    // B:  bit31=0, BL: bit31=1
    if ((insn & 0x7C000000) == 0x14000000) {
        int64_t imm26 = sign_extend(insn & 0x03FFFFFF, 26);
        uint64_t target = orig_pc + (imm26 << 2);
        bool is_bl = (insn >> 31) & 1;
        if (is_bl) {
            // BL needs to set LR to return to next instruction in trampoline
            // ADR LR, #16; (points past the abs jump)
            out32[0] = 0x10000080 | 30; // ADR X30, #16
            return 4 + write_abs_jump(out + 4, target);
        }
        return write_abs_jump(out, target);
    }

    // ---- B.cond (conditional branch) ----
    // Encoding: 0101 0100 imm19 0 cond4
    if ((insn & 0xFF000010) == 0x54000000) {
        int64_t imm19 = sign_extend((insn >> 5) & 0x7FFFF, 19);
        uint64_t target = orig_pc + (imm19 << 2);
        uint32_t cond = insn & 0xF;
        // B.cond #8 (skip B); B #24 (skip abs jump); abs_jump(target)
        out32[0] = 0x54000040 | cond; // B.cond +8
        out32[1] = 0x14000005;        // B +24 (skip 16-byte abs jump + this B)
        return 8 + write_abs_jump(out + 8, target);
    }

    // ---- CBZ / CBNZ ----
    // Encoding: sf 0 1 1 0 1 0 op imm19 Rt
    if ((insn & 0x7E000000) == 0x34000000) {
        int64_t imm19 = sign_extend((insn >> 5) & 0x7FFFF, 19);
        uint64_t target = orig_pc + (imm19 << 2);
        uint32_t rt = insn & 0x1F;
        // CBZ/CBNZ Rt, +8; B +20; abs_jump(target)
        // Preserve sf, op bits from original; only change imm19 to +8 (imm19=2)
        out32[0] = (insn & 0xFF00001F) | (2 << 5); // keep sf/op/Rt, set imm19=2 (+8 bytes)
        out32[1] = 0x14000005; // B +20 (skip 16-byte abs jump)
        return 8 + write_abs_jump(out + 8, target);
    }

    // ---- TBZ / TBNZ ----
    // Encoding: b5 0 1 1 0 1 1 op b40 imm14 Rt
    if ((insn & 0x7E000000) == 0x36000000) {
        int64_t imm14 = sign_extend((insn >> 5) & 0x3FFF, 14);
        uint64_t target = orig_pc + (imm14 << 2);
        // TBZ/TBNZ bit, Rt, +8; B +24; abs_jump(target)
        uint32_t new_insn = (insn & 0xFFF8001F) | (2 << 5); // offset = +8
        out32[0] = new_insn;
        out32[1] = 0x14000005; // B +24
        return 8 + write_abs_jump(out + 8, target);
    }

    // ---- ADRP ----
    // Encoding: 1 immlo2 1 0 0 0 0 immhi19 Rd5
    if ((insn & 0x9F000000) == 0x90000000) {
        uint64_t immhi = (insn >> 5) & 0x7FFFF;
        uint64_t immlo = (insn >> 29) & 0x3;
        int64_t imm = sign_extend((immhi << 2) | immlo, 21);
        uint64_t target = (orig_pc & ~0xFFFULL) + (imm << 12);
        uint32_t rd = insn & 0x1F;
        // LDR Xd, #8; B #12; .quad target
        out32[0] = 0x58000040 | rd; // LDR Xd, #8
        out32[1] = 0x14000003;      // B #12 (skip .quad)
        *reinterpret_cast<uint64_t *>(out + 8) = target;
        return 16;
    }

    // ---- ADR ----
    // Encoding: 0 immlo2 1 0 0 0 0 immhi19 Rd5
    if ((insn & 0x9F000000) == 0x10000000) {
        uint64_t immhi = (insn >> 5) & 0x7FFFF;
        uint64_t immlo = (insn >> 29) & 0x3;
        int64_t imm = sign_extend((immhi << 2) | immlo, 21);
        uint64_t target = orig_pc + imm;
        uint32_t rd = insn & 0x1F;
        RLOGI("  ADR X%u: immhi=0x%llx immlo=0x%llx imm=%lld target=0x%llx",
              rd, (unsigned long long)immhi, (unsigned long long)immlo,
              (long long)imm, (unsigned long long)target);
        out32[0] = 0x58000040 | rd; // LDR Xd, #8
        out32[1] = 0x14000003;      // B #12
        *reinterpret_cast<uint64_t *>(out + 8) = target;
        return 16;
    }

    // ---- LDR literal (all variants) ----
    // Covers: LDR Wt, LDR Xt, LDRSW, LDR St, LDR Dt, LDR Qt
    // Common encoding: xx 011 x00 imm19 Rt
    if ((insn & 0x3B000000) == 0x18000000) {
        int64_t imm19 = sign_extend((insn >> 5) & 0x7FFFF, 19);
        uint64_t data_addr = orig_pc + (imm19 << 2);
        uint32_t rt = insn & 0x1F;
        uint32_t opc = (insn >> 30) & 0x3;
        bool is_simd = (insn >> 26) & 1;

        if (!is_simd && opc == 0x1) {
            // LDR Xt, literal — 64-bit GP register
            // LDR X_tmp, #12; LDR Xt, [X_tmp]; B #12; .quad data_addr
            // Use X17 as temp if Xt != X17, else use X16
            uint32_t tmp = (rt != 17) ? 17 : 16;
            out32[0] = 0x58000060 | tmp;              // LDR Xtmp, #12
            out32[1] = 0xF9400000 | (tmp << 5) | rt;  // LDR Xt, [Xtmp]
            out32[2] = 0x14000003;                     // B #12
            *reinterpret_cast<uint64_t *>(out + 12) = data_addr;
            return 20;
        } else if (!is_simd && opc == 0x0) {
            // LDR Wt, literal — 32-bit GP register
            uint32_t tmp = (rt != 17) ? 17 : 16;
            out32[0] = 0x58000060 | tmp;
            out32[1] = 0xB9400000 | (tmp << 5) | rt;  // LDR Wt, [Xtmp]
            out32[2] = 0x14000003;
            *reinterpret_cast<uint64_t *>(out + 12) = data_addr;
            return 20;
        } else if (!is_simd && opc == 0x2) {
            // LDRSW Xt, literal
            uint32_t tmp = (rt != 17) ? 17 : 16;
            out32[0] = 0x58000060 | tmp;
            out32[1] = 0xB9800000 | (tmp << 5) | rt;  // LDRSW Xt, [Xtmp]
            out32[2] = 0x14000003;
            *reinterpret_cast<uint64_t *>(out + 12) = data_addr;
            return 20;
        } else {
            // SIMD/FP literal load — complex, fallback to address calculation
            // Load address into X17, then use the appropriate LDR [X17]
            RLOGW("ARM64 relocate: SIMD LDR literal at %p, using fallback", (void*)orig_pc);
            uint32_t size_bits = opc;  // 00=32, 01=64, 10=128
            out32[0] = 0x58000060 | 17;  // LDR X17, #12
            if (size_bits == 0) {
                out32[1] = 0xBD400220 | rt;  // LDR St, [X17]
            } else if (size_bits == 1) {
                out32[1] = 0xFD400220 | rt;  // LDR Dt, [X17]
            } else {
                out32[1] = 0x3DC00220 | rt;  // LDR Qt, [X17]
            }
            out32[2] = 0x14000003;
            *reinterpret_cast<uint64_t *>(out + 12) = data_addr;
            return 20;
        }
    }

    // ---- No relocation needed ----
    out32[0] = insn;
    return 4;
}

// Public interface implementation for ARM64
extern "C" size_t adl_build_trampoline(void *target, size_t hook_size, bool is_thumb,
                            uint8_t *trampoline) {
    (void)is_thumb; // ARM64 has no Thumb mode

    uint32_t *orig = reinterpret_cast<uint32_t *>(target);
    uint64_t orig_pc = reinterpret_cast<uint64_t>(target);
    size_t out_offset = 0;
    size_t num_insns = hook_size / 4;

    for (size_t i = 0; i < num_insns; i++) {
        uint64_t tramp_pc = reinterpret_cast<uint64_t>(trampoline) + out_offset;
        RLOGI("relocate insn[%zu]: 0x%08x @ PC=0x%llx -> tramp@0x%llx",
              i, orig[i], (unsigned long long)(orig_pc + i * 4),
              (unsigned long long)tramp_pc);
        size_t written = relocate_insn(orig[i], orig_pc + i * 4,
                                       trampoline + out_offset, tramp_pc);
        if (written == 0) {
            RLOGE("ARM64 relocate failed at insn %zu", i);
            return 0;
        }
        RLOGI("  -> wrote %zu bytes", written);
        out_offset += written;
    }

    // Append absolute jump back to original function + hook_size
    out_offset += write_abs_jump(trampoline + out_offset, orig_pc + hook_size);
    return out_offset;
}

extern "C" size_t adl_calc_hook_size(void *target, size_t min_size, bool is_thumb) {
    (void)target;
    (void)is_thumb;
    return (min_size + 3) & ~3;
}

#endif // __aarch64__
