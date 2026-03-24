//
// Hub mechanism: TLS frame stack + runtime code from assembly template
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
    for (int i = 0; i < ADL_HUB_STACK_POOL_SIZE; i++) {
        uint8_t expected = 0;
        if (__atomic_compare_exchange_n(&g_stack_pool_used[i], &expected, 1,
                                         false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            memset(&g_stack_pool[i], 0, sizeof(adl_hub_stack_t));
            return &g_stack_pool[i];
        }
    }
    void *mem = mmap(NULL, sizeof(adl_hub_stack_t), PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (mem == MAP_FAILED) return NULL;
    memset(mem, 0, sizeof(adl_hub_stack_t));
    return static_cast<adl_hub_stack_t *>(mem);
}

static void free_stack(void *ptr) {
    adl_hub_stack_t *stack = static_cast<adl_hub_stack_t *>(ptr);
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
        return data->trampoline;
    }

    // Check recursion
    for (int i = 0; i < stack->count; i++) {
        if (stack->frames[i].orig_addr == data->orig_addr) {
            return data->trampoline;  // recursive — skip proxy
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
    (void)data;
    adl_hub_stack_t *stack = static_cast<adl_hub_stack_t *>(
        pthread_getspecific(g_hub_tls_key));
    if (stack == NULL || stack->count <= 0) return;
    stack->count--;
}

// ============================================================================
// Hub code creation from assembly template
// ============================================================================

#if defined(__aarch64__)

// Assembly template symbols (defined in adl_hub_arm64.S)
extern "C" void adl_hub_template_entry(void);
extern "C" void adl_hub_template_end(void);

// Placeholder values matching adl_hub_arm64.S
#define PLACEHOLDER_HUB_DATA    0xDEAD000000000001ULL
#define PLACEHOLDER_PUSH_FN     0xDEAD000000000002ULL
#define PLACEHOLDER_POP_FN      0xDEAD000000000003ULL

static void patch_placeholder(uint8_t *code, size_t size,
                               uint64_t placeholder, uint64_t value) {
    for (size_t i = 0; i <= size - 8; i += 4) {
        uint64_t *p = reinterpret_cast<uint64_t *>(code + i);
        if (*p == placeholder) {
            *p = value;
            return;
        }
    }
    HLOGE("patch_placeholder: 0x%llx not found!", (unsigned long long)placeholder);
}

void *adl_hub_create(adl_hub_data_t *data) {
    adl_hub_init();

    uintptr_t tmpl_start = reinterpret_cast<uintptr_t>(adl_hub_template_entry);
    uintptr_t tmpl_end = reinterpret_cast<uintptr_t>(adl_hub_template_end);
    size_t tmpl_size = tmpl_end - tmpl_start;

    if (tmpl_size == 0 || tmpl_size > PAGE_SIZE) {
        HLOGE("hub template size invalid: %zu", tmpl_size);
        return NULL;
    }

    // Allocate executable page
    void *code = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (code == MAP_FAILED) {
        HLOGE("hub mmap failed");
        return NULL;
    }

    // Copy template
    memcpy(code, reinterpret_cast<void *>(tmpl_start), tmpl_size);

    // Patch placeholders with real addresses
    patch_placeholder(static_cast<uint8_t *>(code), tmpl_size,
                      PLACEHOLDER_HUB_DATA, reinterpret_cast<uint64_t>(data));
    patch_placeholder(static_cast<uint8_t *>(code), tmpl_size,
                      PLACEHOLDER_PUSH_FN, reinterpret_cast<uint64_t>(&adl_hub_push));
    patch_placeholder(static_cast<uint8_t *>(code), tmpl_size,
                      PLACEHOLDER_POP_FN, reinterpret_cast<uint64_t>(&adl_hub_pop));

    // Flush instruction cache
    __builtin___clear_cache(static_cast<char *>(code),
                            static_cast<char *>(code) + tmpl_size);

    HLOGI("hub created: template=%zu bytes, entry@%p, data@%p",
          tmpl_size, code, data);
    return code;
}

#else // !__aarch64__

void *adl_hub_create(adl_hub_data_t *data) {
    adl_hub_init();
    (void)data;
    HLOGE("hub not implemented for this architecture");
    return NULL;
}

#endif

void adl_hub_destroy(void *hub_entry) {
    (void)hub_entry;
    // Don't munmap — other threads may still reference it
}
