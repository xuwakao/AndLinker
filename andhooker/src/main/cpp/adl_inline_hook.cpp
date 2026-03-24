//
// Inline hook implementation — uses per-architecture relocators
//

#include <sys/mman.h>
#include <sys/user.h>
#include <string.h>
#include <errno.h>
#include <android/log.h>

#include "adl_hook.h"
#include "adl_hub.h"
#include "adl_relocate.h"

#define HOOKER_TAG "adl_hooker"
#define HLOGI(...) __android_log_print(ANDROID_LOG_INFO, HOOKER_TAG, __VA_ARGS__)
#define HLOGE(...) __android_log_print(ANDROID_LOG_ERROR, HOOKER_TAG, __VA_ARGS__)
#define HLOGW(...) __android_log_print(ANDROID_LOG_WARN, HOOKER_TAG, __VA_ARGS__)

// Architecture hook entry sizes
#if defined(__aarch64__)
#define HOOK_MIN_SIZE 16
#elif defined(__arm__)
#define ARM_HOOK_MIN_SIZE 8
#define THUMB_HOOK_MIN_SIZE 8
#elif defined(__i386__)
#define HOOK_MIN_SIZE 5
#elif defined(__x86_64__)
#define HOOK_MIN_SIZE 14
#endif

// ============================================================================
// Hook record
// ============================================================================

struct inline_hook_record {
    void *target;
    size_t hook_size;
    uint8_t orig_bytes[64];
    void *trampoline;
    bool is_thumb;
    adl_hub_data_t *hub_data;  // hub data (owns lifecycle)
    void *hub_entry;           // hub code entry point
    inline_hook_record *next;
};

static inline_hook_record *g_inline_hooks = NULL;

// ============================================================================
// Memory utilities
// ============================================================================

static int make_writable(void *addr, size_t size) {
    uintptr_t page_start = reinterpret_cast<uintptr_t>(addr) & ~(PAGE_SIZE - 1);
    uintptr_t page_end = (reinterpret_cast<uintptr_t>(addr) + size + PAGE_SIZE - 1)
                         & ~(PAGE_SIZE - 1);
    if (mprotect(reinterpret_cast<void *>(page_start), page_end - page_start,
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        HLOGE("mprotect RWX failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static void flush_cache(void *addr, size_t size) {
    __builtin___clear_cache(reinterpret_cast<char *>(addr),
                            reinterpret_cast<char *>(addr) + size);
}

// ============================================================================
// Thread-safe ordered write
// ============================================================================

static void ordered_write_hook(void *target, void *new_func, size_t hook_size,
                                bool is_thumb) {
    uint8_t *code = reinterpret_cast<uint8_t *>(target);

#if defined(__aarch64__)
    (void)is_thumb;
    // Step 1: write target address (bytes 8-15)
    *reinterpret_cast<uint64_t *>(code + 8) = reinterpret_cast<uint64_t>(new_func);
    __asm__ __volatile__("dmb ish" ::: "memory");
    // Step 2: write jump instruction (bytes 0-7) — atomically activates hook
    uint32_t insn[2] = { 0x58000051, 0xD61F0220 }; // LDR X17, #8; BR X17
    *reinterpret_cast<uint64_t *>(code) = *reinterpret_cast<uint64_t *>(insn);
    __asm__ __volatile__("dmb ish" ::: "memory");

#elif defined(__arm__)
    if (!is_thumb) {
        // ARM: LDR PC, [PC, #-4]; .word addr (8 bytes)
        *reinterpret_cast<uint32_t *>(code + 4) =
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(new_func));
        __asm__ __volatile__("dmb ish" ::: "memory");
        *reinterpret_cast<uint32_t *>(code) = 0xE51FF004;
        __asm__ __volatile__("dmb ish" ::: "memory");
    } else {
        // Thumb: LDR.W PC, [PC, #0]; .word addr (8 bytes)
        *reinterpret_cast<uint32_t *>(code + 4) =
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(new_func));
        __asm__ __volatile__("dmb ish" ::: "memory");
        uint16_t thumb_ldr[2] = { 0xF8DF, 0xF000 };
        *reinterpret_cast<uint32_t *>(code) = *reinterpret_cast<uint32_t *>(thumb_ldr);
        __asm__ __volatile__("dmb ish" ::: "memory");
    }

#elif defined(__i386__)
    (void)is_thumb;
    // JMP rel32 (5 bytes) — write rel32 first, then opcode
    int32_t rel = static_cast<int32_t>(
        reinterpret_cast<uintptr_t>(new_func) - reinterpret_cast<uintptr_t>(code) - 5);
    memcpy(code + 1, &rel, 4);
    __asm__ __volatile__("mfence" ::: "memory");
    code[0] = 0xE9;
    __asm__ __volatile__("mfence" ::: "memory");

#elif defined(__x86_64__)
    (void)is_thumb;
    // FF 25 00 00 00 00 + .quad addr (14 bytes)
    *reinterpret_cast<uint64_t *>(code + 6) = reinterpret_cast<uint64_t>(new_func);
    __asm__ __volatile__("mfence" ::: "memory");
    // Write the 6-byte opcode prefix
    code[0] = 0xFF; code[1] = 0x25;
    *reinterpret_cast<uint32_t *>(code + 2) = 0;
    __asm__ __volatile__("mfence" ::: "memory");
#endif

    flush_cache(target, hook_size);
}

static void ordered_write_unhook(void *target, const uint8_t *orig_bytes, size_t hook_size) {
    uint8_t *code = reinterpret_cast<uint8_t *>(target);

    // Reverse order: write front first (deactivates hook), then back
    size_t half = hook_size / 2;
    if (half == 0) half = hook_size;

    memcpy(code, orig_bytes, half);
#if defined(__i386__) || defined(__x86_64__)
    __asm__ __volatile__("mfence" ::: "memory");
#else
    __asm__ __volatile__("dmb ish" ::: "memory");
#endif
    if (half < hook_size) {
        memcpy(code + half, orig_bytes + half, hook_size - half);
    }
#if defined(__i386__) || defined(__x86_64__)
    __asm__ __volatile__("mfence" ::: "memory");
#else
    __asm__ __volatile__("dmb ish" ::: "memory");
#endif

    flush_cache(target, hook_size);
}

// ============================================================================
// Public API
// ============================================================================

int adl_inline_hook(void *target_func, void *new_func, void **orig_func) {
    if (target_func == NULL || new_func == NULL) {
        HLOGE("adl_inline_hook: invalid arguments");
        return -1;
    }

    bool is_thumb = false;
    size_t min_hook_size;

#if defined(__aarch64__)
    min_hook_size = HOOK_MIN_SIZE;
    // ARM64 BTI: if first instruction is HINT (BTI variant), skip it
    // BTI insns: 0xD503245F (bti c), 0xD503247F (bti j), 0xD50324DF (bti jc), 0xD503201F (nop/hint)
    {
        uint32_t first_insn = *reinterpret_cast<uint32_t *>(target_func);
        if ((first_insn & 0xFFFFFF1F) == 0xD503241F || // bti c/j/jc
            first_insn == 0xD503245F) {                  // bti c specifically
            HLOGI("ARM64 BTI detected at %p (insn=0x%08x), hooking after BTI",
                  target_func, first_insn);
            target_func = reinterpret_cast<void *>(
                reinterpret_cast<uintptr_t>(target_func) + 4);
        }
    }
#elif defined(__arm__)
    uintptr_t target_addr = reinterpret_cast<uintptr_t>(target_func);
    is_thumb = (target_addr & 1) != 0;
    if (is_thumb) {
        target_func = reinterpret_cast<void *>(target_addr & ~1u);
        min_hook_size = THUMB_HOOK_MIN_SIZE;
    } else {
        min_hook_size = ARM_HOOK_MIN_SIZE;
    }
#elif defined(__i386__) || defined(__x86_64__)
    min_hook_size = HOOK_MIN_SIZE;
#endif

    // Calculate actual hook size (handles instruction boundaries, IT blocks, etc.)
    size_t hook_size = adl_calc_hook_size(target_func, min_hook_size, is_thumb);
    if (hook_size == 0) {
        HLOGE("adl_inline_hook: failed to calculate hook size for %p", target_func);
        return -1;
    }
    if (hook_size > sizeof(((inline_hook_record*)0)->orig_bytes)) {
        HLOGE("adl_inline_hook: hook size %zu exceeds max", hook_size);
        return -1;
    }

    // Allocate trampoline
    void *trampoline = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (trampoline == MAP_FAILED) {
        HLOGE("adl_inline_hook: mmap trampoline failed: %s", strerror(errno));
        return -1;
    }

    // Save original bytes
    uint8_t orig_bytes[64];
    memcpy(orig_bytes, target_func, hook_size);

    // Build trampoline with relocated instructions
    size_t tramp_size = adl_build_trampoline(target_func, hook_size, is_thumb,
                                              reinterpret_cast<uint8_t *>(trampoline));
    if (tramp_size == 0) {
        HLOGE("adl_inline_hook: failed to build trampoline for %p", target_func);
        munmap(trampoline, PAGE_SIZE);
        return -1;
    }
    flush_cache(trampoline, tramp_size);

    // Make target writable
    if (make_writable(target_func, hook_size) != 0) {
        munmap(trampoline, PAGE_SIZE);
        return -1;
    }

    // Set up trampoline pointer for orig_func
    void *trampoline_for_caller = trampoline;
#if defined(__arm__)
    if (is_thumb) {
        trampoline_for_caller = reinterpret_cast<void *>(
            reinterpret_cast<uintptr_t>(trampoline) | 1);
    }
#endif

    // Create hub for automatic recursion prevention
    adl_hub_data_t *hub_data = new adl_hub_data_t();
    hub_data->orig_addr = target_func;
    hub_data->proxy_func = new_func;
    hub_data->trampoline = trampoline_for_caller;

    void *hub_entry = adl_hub_create(hub_data);
    void *jump_target;

    if (hub_entry != NULL) {
        // Hub available: target jumps to hub, hub manages proxy/trampoline dispatch
        jump_target = hub_entry;
        HLOGI("Inline hook with hub: %p -> hub@%p -> proxy@%p (trampoline@%p)",
              target_func, hub_entry, new_func, trampoline);
    } else {
        // Hub not available (non-ARM64): fall back to direct jump to proxy
        jump_target = new_func;
        HLOGW("Inline hook without hub (no recursion guard): %p -> %p", target_func, new_func);
    }

    // Write hook with ordered writes (thread-safe)
    ordered_write_hook(target_func, jump_target, hook_size, is_thumb);

    // Return trampoline to caller
    if (orig_func != NULL) {
        *orig_func = trampoline_for_caller;
    }

    // Save record
    inline_hook_record *record = new inline_hook_record();
    record->target = target_func;
    record->hook_size = hook_size;
    memcpy(record->orig_bytes, orig_bytes, hook_size);
    record->trampoline = trampoline;
    record->is_thumb = is_thumb;
    record->hub_data = hub_data;
    record->hub_entry = hub_entry;
    record->next = g_inline_hooks;
    g_inline_hooks = record;

    return 0;
}

int adl_inline_unhook(void *target_func) {
    if (target_func == NULL) return -1;

#if defined(__arm__)
    target_func = reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(target_func) & ~1u);
#endif

    inline_hook_record **pp = &g_inline_hooks;
    while (*pp != NULL) {
        if ((*pp)->target == target_func) {
            inline_hook_record *record = *pp;

            if (make_writable(target_func, record->hook_size) != 0) return -1;

            // Ordered unhook write
            ordered_write_unhook(target_func, record->orig_bytes, record->hook_size);

            // Do NOT munmap trampoline — JIT or other threads may still reference it.
            // The 4KB page will be reclaimed when the process exits.
            *pp = record->next;
            delete record;

            HLOGI("Inline unhook: %p restored", target_func);
            return 0;
        }
        pp = &(*pp)->next;
    }

    HLOGE("adl_inline_unhook: no hook record for %p", target_func);
    return -1;
}
