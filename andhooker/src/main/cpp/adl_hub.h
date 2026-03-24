//
// Hub mechanism for automatic inline hook recursion prevention
// Reference: ShadowHook (ByteDance) hub architecture
//

#ifndef ANDHOOKER_ADL_HUB_H
#define ANDHOOKER_ADL_HUB_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

// Max recursion depth per thread
#define ADL_HUB_FRAME_MAX 16

// Max threads with pre-allocated stacks
#define ADL_HUB_STACK_POOL_SIZE 128

// Hub data: one per hook point
typedef struct adl_hub_data {
    void *orig_addr;       // original function address (for recursion matching)
    void *proxy_func;      // user's proxy function
    void *trampoline;      // trampoline to call original function
} adl_hub_data_t;

// Initialize hub subsystem (call once at startup)
void adl_hub_init(void);

// Generate hub code for a hook point. Returns mmap'd executable memory.
// The hub entry will:
//   1. Save all registers
//   2. Call adl_hub_push to decide proxy vs trampoline
//   3. Restore all registers
//   4. Jump to the decision result
//   5. On return from proxy, call adl_hub_pop automatically
//
// Returns hub_entry address (what target should be patched to jump to),
// or NULL on failure.
void *adl_hub_create(adl_hub_data_t *data);

// Destroy hub code (free mmap'd memory)
void adl_hub_destroy(void *hub_entry);

// Called by hub assembly — DO NOT call directly
void *adl_hub_push(adl_hub_data_t *data, void *return_addr);
void adl_hub_pop(adl_hub_data_t *data);

#ifdef __cplusplus
}
#endif

#endif //ANDHOOKER_ADL_HUB_H
