//
// Hub mechanism for automatic inline hook recursion prevention
// Supports: shared hub pages, multi-hook proxy chains, reentrant control
//

#ifndef ANDHOOKER_ADL_HUB_H
#define ANDHOOKER_ADL_HUB_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ADL_HUB_FRAME_MAX 16
#define ADL_HUB_STACK_POOL_SIZE 128
#define ADL_HUB_SLOT_SIZE 256       // bytes per hub slot (template ~176 + alignment)
#define ADL_HUB_FLAG_ALLOW_REENTRANT 0x1

// Proxy node in the hook chain
typedef struct adl_hub_proxy {
    void *func;                      // proxy function pointer
    void *orig;                      // what this proxy's "orig" points to (next proxy or trampoline)
    bool enabled;
    struct adl_hub_proxy *next;      // next in chain (older hooks)
} adl_hub_proxy_t;

// Hub data: one per hooked function address
typedef struct adl_hub_data {
    void *orig_addr;                 // original function address (for recursion matching)
    adl_hub_proxy_t *proxies;        // proxy chain (head = most recent hook)
    void *trampoline;                // trampoline to call original function
    uint32_t flags;                  // ADL_HUB_FLAG_ALLOW_REENTRANT etc.
    void *hub_slot;                  // hub code slot address (for destroy)
} adl_hub_data_t;

// Initialize hub subsystem
void adl_hub_init(void);

// Create hub code for a hook point (allocates from shared page)
void *adl_hub_create(adl_hub_data_t *data);

// Destroy hub code (mark slot as free)
void adl_hub_destroy(void *hub_entry);

// Add a proxy to an existing hub data's chain (for multi-hook)
// Returns the "orig" pointer that the new proxy should use
void *adl_hub_add_proxy(adl_hub_data_t *data, void *proxy_func);

// Remove a proxy from the chain
// Returns 0 if removed, -1 if not found
int adl_hub_remove_proxy(adl_hub_data_t *data, void *proxy_func);

// Called by hub assembly — DO NOT call directly
void *adl_hub_push(adl_hub_data_t *data, void *return_addr);
void adl_hub_pop(adl_hub_data_t *data);

#ifdef __cplusplus
}
#endif

#endif //ANDHOOKER_ADL_HUB_H
