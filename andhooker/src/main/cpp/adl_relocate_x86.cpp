//
// x86/x86_64 instruction relocation
//

#if defined(__i386__) || defined(__x86_64__)

#include <string.h>
#include <android/log.h>
#include "adl_relocate.h"

#define HTAG "adl_relocate"
#define RLOGI(...) __android_log_print(ANDROID_LOG_INFO, HTAG, __VA_ARGS__)
#define RLOGW(...) __android_log_print(ANDROID_LOG_WARN, HTAG, __VA_ARGS__)
#define RLOGE(...) __android_log_print(ANDROID_LOG_ERROR, HTAG, __VA_ARGS__)

#if defined(__i386__)
#define HOOK_MIN_SIZE 5   // JMP rel32
static const bool kIs64 = false;
#else
#define HOOK_MIN_SIZE 14  // FF 25 00 00 00 00 + .quad
static const bool kIs64 = true;
#endif

// ============================================================================
// Minimal instruction length decoder
// ============================================================================

static size_t x86_insn_len(const uint8_t *code) {
    const uint8_t *p = code;
    bool has_rex = false;

    // Skip prefixes
    for (;;) {
        uint8_t b = *p;
        if (b == 0x66 || b == 0x67 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65) {
            p++; continue;
        }
        if (kIs64 && b >= 0x40 && b <= 0x4F) { has_rex = true; p++; continue; }
        break;
    }

    uint8_t op = *p++;

    // Simple 1-byte
    if (op == 0x90 || op == 0xC3 || op == 0xCB || op == 0xCC) return p - code;
    if ((op & 0xF8) == 0x50 || (op & 0xF8) == 0x58) return p - code; // PUSH/POP reg
    if (op == 0xC9) return p - code; // LEAVE

    // imm8
    if (op == 0x6A) return p - code + 1;
    if (op == 0xCD) return p - code + 1; // INT imm8

    // imm32
    if (op == 0x68) return p - code + 4;

    // MOV reg, imm
    if ((op & 0xF8) == 0xB8) return p - code + (kIs64 && has_rex ? 8 : 4);
    if ((op & 0xF8) == 0xB0) return p - code + 1;

    // JMP/Jcc rel8
    if (op == 0xEB || (op >= 0x70 && op <= 0x7F)) return p - code + 1;
    // JMP/CALL rel32
    if (op == 0xE9 || op == 0xE8) return p - code + 4;

    // RET imm16
    if (op == 0xC2) return p - code + 2;

    // Helper for ModR/M decoding
    auto modrm_len = [&](bool has_imm, size_t imm_sz) -> size_t {
        uint8_t modrm = *p++;
        uint8_t mod = modrm >> 6;
        uint8_t rm = modrm & 7;
        size_t extra = 0;
        if (mod == 3) { /* register */ }
        else {
            if (rm == 4 && mod != 3) p++; // SIB
            if (mod == 0 && rm == 5) extra = 4; // disp32 or RIP-rel
            else if (mod == 1) extra = 1;
            else if (mod == 2) extra = 4;
        }
        return p - code + extra + (has_imm ? imm_sz : 0);
    };

    // 83 /r ib, 81 /r id
    if (op == 0x83) return modrm_len(true, 1);
    if (op == 0x81) return modrm_len(true, 4);
    if (op == 0x80) return modrm_len(true, 1);
    if (op == 0xC7) return modrm_len(true, 4); // MOV r/m, imm32
    if (op == 0xC6) return modrm_len(true, 1); // MOV r/m8, imm8

    // ModR/M-only opcodes (no immediate)
    if (op == 0x89 || op == 0x8B || op == 0x8D || op == 0x85 ||
        op == 0x87 || op == 0x01 || op == 0x03 || op == 0x09 ||
        op == 0x0B || op == 0x21 || op == 0x23 || op == 0x29 ||
        op == 0x2B || op == 0x31 || op == 0x33 || op == 0x39 ||
        op == 0x3B || op == 0x63 || op == 0xFF || op == 0xFE ||
        op == 0xF7 || op == 0xD1 || op == 0xD3) {
        return modrm_len(false, 0);
    }

    // TEST r/m, imm
    if (op == 0xF6) return modrm_len(true, 1);

    // 0F xx — two-byte opcode
    if (op == 0x0F) {
        uint8_t op2 = *p++;
        if (op2 >= 0x80 && op2 <= 0x8F) return p - code + 4; // Jcc rel32
        if (op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF ||
            op2 == 0xAF || op2 == 0x40 || op2 == 0x4F ||
            op2 == 0x10 || op2 == 0x11 || op2 == 0x28 || op2 == 0x29 ||
            op2 == 0x2E || op2 == 0x2F || op2 == 0x51 || op2 == 0x54 ||
            op2 == 0x57 || op2 == 0x58 || op2 == 0x59 || op2 == 0x5C) {
            return modrm_len(false, 0);
        }
        if (op2 == 0x1F) return modrm_len(false, 0); // NOP r/m
        if (op2 >= 0x40 && op2 <= 0x4F) return modrm_len(false, 0); // CMOVcc
        RLOGW("x86: unknown 2-byte opcode 0F %02x", op2);
        return 0;
    }

    RLOGW("x86: unknown opcode %02x", op);
    return 0;
}

// ============================================================================
// PC-relative relocation
// ============================================================================

static size_t relocate_x86_insn(const uint8_t *insn, size_t len,
                                 uintptr_t orig_addr, uint8_t *out,
                                 uintptr_t new_addr) {
    // CALL rel32
    if (insn[0] == 0xE8 && len == 5) {
        int32_t orig_rel;
        memcpy(&orig_rel, insn + 1, 4);
        uintptr_t target = orig_addr + 5 + orig_rel;
#if defined(__x86_64__)
        // x64: use abs jump (14 bytes)
        out[0] = 0xFF; out[1] = 0x15;
        *reinterpret_cast<uint32_t *>(out + 2) = 2; // RIP+2 (skip JMP)
        out[6] = 0xEB; out[7] = 0x08; // JMP +8 (skip .quad)
        *reinterpret_cast<uint64_t *>(out + 8) = target;
        return 16;
#else
        int32_t new_rel = static_cast<int32_t>(target - new_addr - 5);
        out[0] = 0xE8;
        memcpy(out + 1, &new_rel, 4);
        return 5;
#endif
    }

    // JMP rel32
    if (insn[0] == 0xE9 && len == 5) {
        int32_t orig_rel;
        memcpy(&orig_rel, insn + 1, 4);
        uintptr_t target = orig_addr + 5 + orig_rel;
#if defined(__x86_64__)
        out[0] = 0xFF; out[1] = 0x25;
        *reinterpret_cast<uint32_t *>(out + 2) = 0;
        *reinterpret_cast<uint64_t *>(out + 6) = target;
        return 14;
#else
        int32_t new_rel = static_cast<int32_t>(target - new_addr - 5);
        out[0] = 0xE9;
        memcpy(out + 1, &new_rel, 4);
        return 5;
#endif
    }

    // Jcc rel8 → expand to Jcc rel32
    if ((insn[0] >= 0x70 && insn[0] <= 0x7F) && len == 2) {
        int8_t orig_rel = static_cast<int8_t>(insn[1]);
        uintptr_t target = orig_addr + 2 + orig_rel;
        out[0] = 0x0F;
        out[1] = 0x80 + (insn[0] - 0x70);
        int32_t new_rel = static_cast<int32_t>(target - new_addr - 6);
        memcpy(out + 2, &new_rel, 4);
        return 6;
    }

    // JMP rel8 → expand to JMP rel32
    if (insn[0] == 0xEB && len == 2) {
        int8_t orig_rel = static_cast<int8_t>(insn[1]);
        uintptr_t target = orig_addr + 2 + orig_rel;
        out[0] = 0xE9;
        int32_t new_rel = static_cast<int32_t>(target - new_addr - 5);
        memcpy(out + 1, &new_rel, 4);
        return 5;
    }

    // 0F 8x Jcc rel32
    if (insn[0] == 0x0F && len == 6 && insn[1] >= 0x80 && insn[1] <= 0x8F) {
        int32_t orig_rel;
        memcpy(&orig_rel, insn + 2, 4);
        uintptr_t target = orig_addr + 6 + orig_rel;
        out[0] = 0x0F;
        out[1] = insn[1];
        int32_t new_rel = static_cast<int32_t>(target - new_addr - 6);
        memcpy(out + 2, &new_rel, 4);
        return 6;
    }

    // Not PC-relative: copy as-is
    memcpy(out, insn, len);
    return len;
}

static bool is_pc_relative(const uint8_t *insn, size_t len) {
    if (insn[0] == 0xE8 || insn[0] == 0xE9) return true;
    if (insn[0] == 0xEB) return true;
    if (insn[0] >= 0x70 && insn[0] <= 0x7F) return true;
    if (insn[0] == 0x0F && len > 1 && insn[1] >= 0x80 && insn[1] <= 0x8F) return true;
#if defined(__x86_64__)
    // RIP-relative: check ModR/M for mod=00, rm=101
    size_t i = 0;
    while (i < len && (insn[i] == 0x66 || insn[i] == 0x67 || insn[i] == 0xF2 ||
                        insn[i] == 0xF3 || (insn[i] >= 0x40 && insn[i] <= 0x4F))) i++;
    i++; // opcode
    if (insn[i-1] == 0x0F) i++; // 2-byte opcode
    if (i < len) {
        uint8_t modrm = insn[i];
        if ((modrm >> 6) == 0 && (modrm & 7) == 5) return true;
    }
#endif
    return false;
}

// ============================================================================
// Public interface
// ============================================================================

extern "C" size_t adl_build_trampoline(void *target, size_t hook_size, bool is_thumb,
                            uint8_t *trampoline) {
    (void)is_thumb;
    const uint8_t *code = reinterpret_cast<const uint8_t *>(target);
    uintptr_t orig_base = reinterpret_cast<uintptr_t>(target);
    uintptr_t tramp_base = reinterpret_cast<uintptr_t>(trampoline);
    size_t in_offset = 0;
    size_t out_offset = 0;

    while (in_offset < hook_size) {
        size_t len = x86_insn_len(code + in_offset);
        if (len == 0) {
            RLOGE("x86: failed to decode at offset %zu", in_offset);
            return 0;
        }

        if (is_pc_relative(code + in_offset, len)) {
            size_t written = relocate_x86_insn(code + in_offset, len,
                                                orig_base + in_offset,
                                                trampoline + out_offset,
                                                tramp_base + out_offset);
            out_offset += written;
        } else {
            memcpy(trampoline + out_offset, code + in_offset, len);
            out_offset += len;
        }
        in_offset += len;
    }

    // Jump back
#if defined(__i386__)
    uint8_t *jmp = trampoline + out_offset;
    jmp[0] = 0xE9;
    int32_t rel = static_cast<int32_t>((orig_base + in_offset) -
                                        (tramp_base + out_offset) - 5);
    memcpy(jmp + 1, &rel, 4);
    out_offset += 5;
#else
    uint8_t *jmp = trampoline + out_offset;
    jmp[0] = 0xFF; jmp[1] = 0x25;
    *reinterpret_cast<uint32_t *>(jmp + 2) = 0;
    *reinterpret_cast<uint64_t *>(jmp + 6) = orig_base + in_offset;
    out_offset += 14;
#endif

    return out_offset;
}

extern "C" size_t adl_calc_hook_size(void *target, size_t min_size, bool is_thumb) {
    (void)is_thumb;
    const uint8_t *code = reinterpret_cast<const uint8_t *>(target);
    size_t total = 0;
    while (total < min_size) {
        size_t len = x86_insn_len(code + total);
        if (len == 0) {
            // Try prologue detection as fallback
            if (total == 0) {
                // push ebp/rbp; mov ebp/rbp, esp/rsp
                if (kIs64 && code[0] == 0x55 && code[1] == 0x48 &&
                    code[2] == 0x89 && code[3] == 0xE5) {
                    return 4; // push rbp; mov rbp, rsp
                }
                if (!kIs64 && code[0] == 0x55 && code[1] == 0x89 && code[2] == 0xE5) {
                    return 3; // push ebp; mov ebp, esp
                }
            }
            RLOGE("x86: cannot determine hook size at offset %zu", total);
            return 0;
        }
        total += len;
    }
    return total;
}

#endif // __i386__ || __x86_64__
