//
// Hub mechanism: TLS frame stack + runtime code generation
//

#include <sys/mman.h>
#include <sys/user.h>
#include <string.h>
#include <stdlib.h>
#include <android/log.h>

#include "adl_hub.h"

#define HTAG "adl_hub"
#define HLOGI(...) __android_log_print(ANDROID_LOG_INFO, HTAG, __VA_ARGS__)
#define HLOGE(...) __android_log_print(ANDROID_LOG_ERROR, HTAG, __VA_ARGS__)

// ============================================================================
// TLS frame stack
// ============================================================================

typedef struct {
    void *orig_addr;
} adl_hub_frame_t;

typedef struct {
    int count;
    adl_hub_frame_t frames[ADL_HUB_FRAME_MAX];
} adl_hub_stack_t;

static pthread_key_t g_hub_tls_key;
static bool g_hub_initialized = false;

// Pre-allocated stack pool (avoid malloc in hot path)
static adl_hub_stack_t g_stack_pool[ADL_HUB_STACK_POOL_SIZE];
static volatile uint8_t g_stack_pool_used[ADL_HUB_STACK_POOL_SIZE];

static adl_hub_stack_t *alloc_stack(void) {
    // Try pre-allocated pool first (lock-free)
    for (int i = 0; i < ADL_HUB_STACK_POOL_SIZE; i++) {
        uint8_t expected = 0;
        if (__atomic_compare_exchange_n(&g_stack_pool_used[i], &expected, 1,
                                         false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            memset(&g_stack_pool[i], 0, sizeof(adl_hub_stack_t));
            return &g_stack_pool[i];
        }
    }
    // Pool exhausted — mmap a new one
    void *mem = mmap(NULL, sizeof(adl_hub_stack_t), PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (mem == MAP_FAILED) return NULL;
    memset(mem, 0, sizeof(adl_hub_stack_t));
    return static_cast<adl_hub_stack_t *>(mem);
}

static void free_stack(void *ptr) {
    adl_hub_stack_t *stack = static_cast<adl_hub_stack_t *>(ptr);
    // Check if it's from the pool
    if (stack >= g_stack_pool && stack < g_stack_pool + ADL_HUB_STACK_POOL_SIZE) {
        int idx = static_cast<int>(stack - g_stack_pool);
        __atomic_store_n(&g_stack_pool_used[idx], 0, __ATOMIC_RELEASE);
    } else {
        munmap(stack, sizeof(adl_hub_stack_t));
    }
}

static adl_hub_stack_t *get_thread_stack(void) {
    adl_hub_stack_t *stack = static_cast<adl_hub_stack_t *>(
        pthread_getspecific(g_hub_tls_key));
    if (stack == NULL) {
        stack = alloc_stack();
        if (stack != NULL) {
            pthread_setspecific(g_hub_tls_key, stack);
        }
    }
    return stack;
}

void adl_hub_init(void) {
    if (g_hub_initialized) return;
    g_hub_initialized = true;
    memset(g_stack_pool, 0, sizeof(g_stack_pool));
    memset((void *)g_stack_pool_used, 0, sizeof(g_stack_pool_used));
    pthread_key_create(&g_hub_tls_key, free_stack);
    HLOGI("hub initialized (pool=%d, max_depth=%d)",
          ADL_HUB_STACK_POOL_SIZE, ADL_HUB_FRAME_MAX);
}

// ============================================================================
// Push / Pop (called by hub assembly)
// ============================================================================

extern "C" void *adl_hub_push(adl_hub_data_t *data, void *return_addr) {
    (void)return_addr;
    adl_hub_stack_t *stack = get_thread_stack();
    if (stack == NULL) {
        // Can't allocate TLS — fall through to trampoline (safe)
        return data->trampoline;
    }

    // Check recursion: scan current thread's frame stack
    for (int i = 0; i < stack->count; i++) {
        if (stack->frames[i].orig_addr == data->orig_addr) {
            // Recursive call detected — skip proxy, call original
            return data->trampoline;
        }
    }

    // Not recursive — push frame and call proxy
    if (stack->count < ADL_HUB_FRAME_MAX) {
        stack->frames[stack->count].orig_addr = data->orig_addr;
        stack->count++;
    }

    return data->proxy_func;
}

extern "C" void adl_hub_pop(adl_hub_data_t *data) {
    adl_hub_stack_t *stack = static_cast<adl_hub_stack_t *>(
        pthread_getspecific(g_hub_tls_key));
    if (stack == NULL || stack->count <= 0) return;

    // Pop the top frame (should match data->orig_addr)
    stack->count--;
}

// ============================================================================
// ARM64 Hub code generation
// ============================================================================

#if defined(__aarch64__)

// Hub code layout in mmap'd page:
//
// [hub_entry]     — save regs, call push, restore regs, jump to result
// [hub_return]    — save return value regs, call pop, restore, return to caller
// [hub_data_ptr]  — 8 bytes: pointer to adl_hub_data_t
// [push_fn_ptr]   — 8 bytes: pointer to adl_hub_push
// [pop_fn_ptr]    — 8 bytes: pointer to adl_hub_pop
// [saved_lr_slot] — 8 bytes: per-call saved LR (TLS would be better, but this is simpler)
//
// Note: saved_lr_slot is NOT thread-safe for concurrent calls. We use TLS for this.

// For thread-safe LR saving, we use a trick:
// hub_entry replaces LR with hub_return address before jumping to proxy.
// But we need to save the REAL caller's LR somewhere the hub_return can find it.
// We save it on the stack (the hub_entry already does stp/ldp on sp).
// Actually, simpler: we DON'T restore LR in hub_entry. Instead:
//   - hub_entry saves LR to TLS
//   - hub_entry sets LR = hub_return
//   - proxy executes and `ret` returns to hub_return
//   - hub_return calls pop, then jumps to saved LR from TLS

// Per-thread saved LR (simple approach: store in hub_stack)
// Actually, we can store it in the frame we just pushed.

// Let's simplify: add return_addr to the frame struct.

// Revised approach for hub_entry + hub_return:
//
// hub_entry:
//   stp x0,x1,[sp,#-0xe0]!    // save all param regs + LR + x16
//   ...save x2-x8, q0-q7, lr...
//   ldr x0, [hub_data_ptr]     // arg0 = hub_data
//   ldr lr, [sp, #0xd0]        // arg1 = saved LR (caller's return addr)
//   mov x1, lr
//   ldr x16, [push_fn_ptr]
//   blr x16                     // x0 = target (proxy or trampoline)
//   mov x16, x0
//   // Restore all regs EXCEPT LR — set LR to hub_return
//   ...restore x0-x8, q0-q7...
//   adr lr, hub_return          // proxy will `ret` to hub_return
//   ldp x0, x1, [sp], #0xe0    // restore x0,x1 and reclaim stack
//   br x16                      // jump to proxy or trampoline
//
// hub_return:
//   stp x0, x1, [sp, #-0x30]!  // save return value registers
//   stp q0, q1, [sp, #0x10]    // save SIMD return values
//   ldr x0, [hub_data_ptr]
//   ldr x16, [pop_fn_ptr]
//   blr x16                     // adl_hub_pop
//   ldp q0, q1, [sp, #0x10]
//   ldp x0, x1, [sp], #0x30    // restore return values
//   // Now we need the real caller's LR — it's in our TLS stack
//   // Actually we need a different approach...

// The problem: after proxy returns, we need the original caller's return address.
// ShadowHook solves this by requiring SHADOWHOOK_POP_STACK in the proxy.
// We want fully automatic.
//
// Simplest safe solution:
// - hub_entry saves real LR on the actual stack (above the save area)
// - hub_entry sets LR = hub_return
// - proxy ret → hub_return
// - hub_return reads saved LR from stack, calls pop, ret to real caller
//
// But the stack space used by hub_entry is freed before proxy executes...
// Actually no — we DON'T free it. We leave a small "return frame" on the stack.

// Final approach: Keep 16 bytes on stack throughout proxy execution:
//   [sp+0]: saved real LR
//   [sp+8]: hub_data pointer
// proxy sees sp+16 as its stack base.

#define HUB_CODE_SIZE 512

static void generate_hub_code_arm64(uint8_t *code, adl_hub_data_t *data) {
    uint32_t *p = reinterpret_cast<uint32_t *>(code);
    int i = 0;

    // ========== hub_entry ==========
    // Reserve 16 bytes on stack for return frame (real_lr + hub_data_ptr)
    // Then save all param registers in a separate block

    // sub sp, sp, #0x10                    // return frame: [sp]=real_lr, [sp+8]=hub_data
    p[i++] = 0xD10043FF;
    // str lr, [sp, #0]                     // save real LR
    p[i++] = 0xF90003FE;
    // ldr x17, .L_hub_data                 // load hub_data_ptr (will be patched)
    // We'll use a fixed offset from current PC to the data area at end of code
    // For now, use x17 as temp. We'll patch the literal pool offset later.
    // str x17, [sp, #8]                    // save hub_data_ptr
    // Actually simpler: just hardcode hub_data address via LDR literal
    // We'll place the literal pool at a known offset

    // Save all parameter registers
    // stp x0, x1, [sp, #-0xd0]!
    p[i++] = 0xA9B407E0; // stp x0, x1, [sp, #-0xc0]! (adjust for our 16-byte frame)
    // Wait, this gets complex. Let me use a cleaner approach.

    // START OVER with cleaner layout:
    i = 0;

    // === hub_entry ===
    // Step 1: Save all registers we need (params + LR) in one block
    // stp x0, x1, [sp, #-0xe0]!
    p[i++] = 0xA9B207E0; // stp x0, x1, [sp, #-0xe0]!
    // stp x2, x3, [sp, #0x10]
    p[i++] = 0xA9010FE2;
    // stp x4, x5, [sp, #0x20]
    p[i++] = 0xA90217E4;
    // stp x6, x7, [sp, #0x30]
    p[i++] = 0xA9031FE6;
    // str x8, [sp, #0x40]
    p[i++] = 0xF90023E8;
    // stp q0, q1, [sp, #0x50]
    p[i++] = 0xAD8297E0; // stp q0, q1, [sp, #0x50]
    // stp q2, q3, [sp, #0x70]
    p[i++] = 0xAD838FE2;
    // stp q4, q5, [sp, #0x90]
    p[i++] = 0xAD8497E4; // stp q4, q5, [sp, #0x90]
    // stp q6, q7, [sp, #0xb0]
    p[i++] = 0xAD858FE6; // stp q6, q7, [sp, #0xb0]
    // str lr, [sp, #0xd0]
    p[i++] = 0xF9006BFE;
    // str x16, [sp, #0xd8]               // save x16 (we'll use it)
    p[i++] = 0xF9006FF0;

    // Step 2: Call adl_hub_push(hub_data, return_addr)
    int data_literal_offset_from_here = (HUB_CODE_SIZE - 3 * 8) - (i * 4); // will adjust
    // Load hub_data_ptr into x0 via PC-relative (literal pool at end)
    // LDR X0, [PC, #offset_to_data_literal]
    // We'll patch this offset after we know all instruction positions
    int ldr_data_idx = i;
    p[i++] = 0x58000000; // LDR X0, #0 (placeholder, will patch)
    // mov x1, lr (caller's return address, already saved)
    p[i++] = 0xAA1E03E1;
    // LDR X16, [PC, #offset_to_push_fn_literal]
    int ldr_push_idx = i;
    p[i++] = 0x58000010; // LDR X16, #0 (placeholder)
    // blr x16
    p[i++] = 0xD63F0200;
    // mov x16, x0 (save result: proxy or trampoline address)
    p[i++] = 0xAA0003F0;

    // Step 3: Set LR to hub_return (so proxy ret comes back to us)
    // ADR LR, hub_return
    int adr_return_idx = i;
    p[i++] = 0x1000001E; // ADR X30, #0 (placeholder, will patch)

    // Step 4: Restore all parameter registers (but NOT LR — we set it to hub_return)
    // ldp q6, q7, [sp, #0xb0]
    p[i++] = 0xADC58FE6;
    // ldp q4, q5, [sp, #0x90]
    p[i++] = 0xADC497E4;
    // ldp q2, q3, [sp, #0x70]
    p[i++] = 0xADC38FE2;
    // ldp q0, q1, [sp, #0x50]
    p[i++] = 0xADC297E0;
    // ldr x8, [sp, #0x40]
    p[i++] = 0xF94023E8;
    // ldp x6, x7, [sp, #0x30]
    p[i++] = 0xA9431FE6;
    // ldp x4, x5, [sp, #0x20]
    p[i++] = 0xA94217E4;
    // ldp x2, x3, [sp, #0x10]
    p[i++] = 0xA9410FE2;
    // ldp x0, x1, [sp], #0xe0            // restore x0,x1 and free save area
    // BUT we need to keep sp adjusted because hub_return needs saved LR
    // So DON'T free save area yet — just restore x0,x1 from [sp]
    p[i++] = 0xA94007E0; // ldp x0, x1, [sp, #0x00]
    // NOTE: sp still points to save area. We'll clean up in hub_return.

    // Step 5: Jump to proxy or trampoline
    // br x16
    p[i++] = 0xD61F0200;

    // ========== hub_return ==========
    // proxy has returned. Return value in x0 (and possibly x1, q0).
    // We need to: call pop, restore real LR, clean up stack, return.
    int hub_return_offset = i;

    // Save return value registers
    // stp x0, x1, [sp, #-0x20]!          // push return values (on top of existing save area)
    // Actually save area is still on stack. Let's use a different region.
    // The save area from hub_entry is still at sp. Real LR is at [sp, #0xd0].
    // We can use [sp, #0xd8] area (x16 save) as scratch.

    // Save x0 temporarily
    // str x0, [sp, #0xd8]
    p[i++] = 0xF9006FE0;

    // Call adl_hub_pop(hub_data)
    int ldr_data2_idx = i;
    p[i++] = 0x58000000; // LDR X0, #0 (placeholder — hub_data)
    int ldr_pop_idx = i;
    p[i++] = 0x58000010; // LDR X16, #0 (placeholder — pop_fn)
    p[i++] = 0xD63F0200; // blr x16

    // Restore x0
    // ldr x0, [sp, #0xd8]
    p[i++] = 0xF9406FE0;

    // Restore real LR
    // ldr lr, [sp, #0xd0]
    p[i++] = 0xF9406BFE;

    // Clean up save area
    // add sp, sp, #0xe0
    p[i++] = 0x910383FF;

    // Return to real caller
    // ret
    p[i++] = 0xD65F03C0;

    // ========== Literal pool ==========
    // Align to 8 bytes
    if (i & 1) p[i++] = 0xD503201F; // NOP for alignment

    int literal_base = i;
    // [0] hub_data_ptr
    int data_literal_idx = i;
    *reinterpret_cast<uint64_t *>(&p[i]) = reinterpret_cast<uint64_t>(data);
    i += 2;
    // [1] push_fn_ptr
    int push_literal_idx = i;
    *reinterpret_cast<uint64_t *>(&p[i]) = reinterpret_cast<uint64_t>(&adl_hub_push);
    i += 2;
    // [2] pop_fn_ptr
    int pop_literal_idx = i;
    *reinterpret_cast<uint64_t *>(&p[i]) = reinterpret_cast<uint64_t>(&adl_hub_pop);
    i += 2;

    // ========== Patch LDR literal offsets ==========
    // LDR Xd, #imm19 — imm19 = (target - PC) / 4, encoded in bits [23:5]

    auto patch_ldr_literal = [&](int insn_idx, int literal_word_idx, int rd) {
        int offset = (literal_word_idx - insn_idx) * 4; // byte offset
        int imm19 = offset / 4; // instruction offset
        p[insn_idx] = 0x58000000 | ((imm19 & 0x7FFFF) << 5) | rd;
    };

    // hub_entry: LDR X0, hub_data
    patch_ldr_literal(ldr_data_idx, data_literal_idx, 0);
    // hub_entry: LDR X16, push_fn
    patch_ldr_literal(ldr_push_idx, push_literal_idx, 16);
    // hub_return: LDR X0, hub_data
    patch_ldr_literal(ldr_data2_idx, data_literal_idx, 0);
    // hub_return: LDR X16, pop_fn
    patch_ldr_literal(ldr_pop_idx, pop_literal_idx, 16);

    // Patch ADR LR, hub_return
    {
        int offset = (hub_return_offset - adr_return_idx) * 4;
        int immhi = (offset >> 2) & 0x7FFFF;
        int immlo = offset & 0x3;
        p[adr_return_idx] = 0x10000000 | (immlo << 29) | (immhi << 5) | 30; // ADR X30
    }

    HLOGI("hub code generated: %d instructions, entry@%p, return@%p+%d",
          i, code, code, hub_return_offset * 4);
}

#endif // __aarch64__

void *adl_hub_create(adl_hub_data_t *data) {
    adl_hub_init();

#if defined(__aarch64__)
    void *code = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (code == MAP_FAILED) {
        HLOGE("hub mmap failed");
        return NULL;
    }

    generate_hub_code_arm64(static_cast<uint8_t *>(code), data);
    __builtin___clear_cache(static_cast<char *>(code),
                            static_cast<char *>(code) + HUB_CODE_SIZE);
    return code;
#else
    // ARM32/x86 hub not implemented yet — fall back to direct jump (no recursion guard)
    HLOGE("hub not implemented for this architecture, falling back to direct hook");
    return NULL;
#endif
}

void adl_hub_destroy(void *hub_entry) {
    if (hub_entry != NULL) {
        // Don't munmap — may be referenced by other threads
        // munmap(hub_entry, PAGE_SIZE);
    }
}
