//
// ARM64 hub assembly template for inline hook recursion prevention
//
// This template is compiled by the assembler (correct instruction encoding),
// then copied to mmap'd executable memory at runtime.
// Placeholder addresses (0xDEAD...) are patched with real values.
//

#if defined(__aarch64__)

// Placeholder values — replaced at runtime by adl_hub.cpp
#define PLACEHOLDER_HUB_DATA    0xDEAD000000000001
#define PLACEHOLDER_PUSH_FN     0xDEAD000000000002
#define PLACEHOLDER_POP_FN      0xDEAD000000000003

.text
.balign 16

// ============================================================================
// Hub entry template
// Called when hooked function is invoked. Saves all registers, calls push
// to decide proxy vs trampoline, restores registers, jumps to result.
// On return from proxy, automatically calls pop.
// ============================================================================

.globl adl_hub_template_entry
.type adl_hub_template_entry, %function
adl_hub_template_entry:
    // --- Prologue: save all parameter registers + LR ---
    // Allocate 0xe0 = 224 bytes on stack
    stp     x0, x1, [sp, #-0xe0]!
    stp     x2, x3, [sp, #0x10]
    stp     x4, x5, [sp, #0x20]
    stp     x6, x7, [sp, #0x30]
    str     x8,     [sp, #0x40]         // indirect result register
    stp     x9, x10,[sp, #0x48]         // save scratch regs (callee may expect them)
    stp     q0, q1, [sp, #0x60]         // SIMD/FP parameter registers
    stp     q2, q3, [sp, #0x80]
    stp     q4, q5, [sp, #0xa0]
    stp     q6, q7, [sp, #0xc0]

    // --- Save original LR for hub_return to restore later ---
    str     lr, [sp, #0x58]             // save at gap between x10 and q0

    // --- Call adl_hub_push(hub_data, return_addr) ---
    // Load hub_data pointer (will be patched)
    ldr     x0, .L_hub_data
    mov     x1, lr                      // caller's return address
    // Load push function address (will be patched)
    ldr     x16, .L_push_fn
    blr     x16                         // x0 = proxy or trampoline address
    mov     x16, x0                     // save decision in x16

    // --- Set LR to hub_return so proxy ret comes back to us ---
    adr     lr, .L_hub_return

    // --- Restore all parameter registers ---
    ldp     q6, q7, [sp, #0xc0]
    ldp     q4, q5, [sp, #0xa0]
    ldp     q2, q3, [sp, #0x80]
    ldp     q0, q1, [sp, #0x60]
    ldp     x9, x10,[sp, #0x48]
    ldr     x8,     [sp, #0x40]
    ldp     x6, x7, [sp, #0x30]
    ldp     x4, x5, [sp, #0x20]
    ldp     x2, x3, [sp, #0x10]
    // Do NOT free stack frame yet (hub_return needs saved LR)
    // Just restore x0, x1 from [sp]
    ldp     x0, x1, [sp]

    // --- Jump to proxy or trampoline ---
    br      x16

// ============================================================================
// Hub return: proxy has returned, need to pop frame and return to real caller
// ============================================================================
.L_hub_return:
    // Save return value registers (x0, x1 for integer, q0 for float/double)
    // We still have our 0xe0 stack frame from hub_entry
    // Use the same area to temporarily save return values
    stp     x0, x1, [sp]               // save return values over the old x0,x1 slots
    str     q0,     [sp, #0x60]         // save FP return value over old q0 slot

    // Call adl_hub_pop(hub_data)
    ldr     x0, .L_hub_data
    ldr     x16, .L_pop_fn
    blr     x16

    // Restore return values
    ldr     q0,     [sp, #0x60]
    ldp     x0, x1, [sp]

    // Restore real LR (saved by hub_entry, it's the caller's original LR)
    // hub_entry saved it at the position where blr x16 was called
    // Actually, hub_entry saved caller's LR via "mov x1, lr" then push changed LR to hub_return
    // The original LR was passed to push as x1, but we didn't save it on stack...
    // We need to save the original LR somewhere accessible from hub_return.
    // Solution: use x9 slot (we saved x9 at [sp, #0x48])
    // Actually the simplest: save original LR at a dedicated stack slot in hub_entry.

    // We saved x9 at [sp, #0x48] and x10 at [sp, #0x50].
    // Let's repurpose [sp, #0xd8] (just past q6,q7 area which ends at 0xe0) for saved LR.
    // But our frame is exactly 0xe0... let me use [sp, #0x58] (between x10 and q0)
    // Actually there's a gap: x8 at 0x40, x9,x10 at 0x48, then q0 starts at 0x60.
    // [sp, #0x58] is free!
    ldr     lr, [sp, #0x58]             // restore original LR (saved in hub_entry)

    // Free the stack frame
    add     sp, sp, #0xe0

    // Return to original caller
    ret

// ============================================================================
// Literal pool (addresses to be patched at runtime)
// ============================================================================
.balign 8
.L_hub_data:
    .quad   PLACEHOLDER_HUB_DATA
.L_push_fn:
    .quad   PLACEHOLDER_PUSH_FN
.L_pop_fn:
    .quad   PLACEHOLDER_POP_FN

.globl adl_hub_template_end
adl_hub_template_end:
    nop

.size adl_hub_template_entry, adl_hub_template_end - adl_hub_template_entry

#endif // __aarch64__
