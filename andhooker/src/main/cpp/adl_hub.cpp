//
// Hub mechanism: shared pages, proxy chains, TLS frame stack, reentrant control
//

#include <sys/mman.h>
#include <sys/user.h>
#include <string.h>
#include <stdlib.h>
#include <android/log.h>

#include "adl_hub.h"

#define HTAG "adl_hub"
//#define ADL_HUB_VERBOSE
#ifdef ADL_HUB_VERBOSE
#define HLOGI(...) __android_log_print(ANDROID_LOG_INFO, HTAG, __VA_ARGS__)
#else
#define HLOGI(...)
#endif
#define HLOGE(...) __android_log_print(ANDROID_LOG_ERROR, HTAG, __VA_ARGS__)

// ============================================================================
// TLS frame stack
// ============================================================================

typedef struct {
    void *orig_addr;
    uint32_t flags;
} adl_hub_frame_t;

typedef struct {
    int count;
    adl_hub_frame_t frames[ADL_HUB_FRAME_MAX];
} adl_hub_stack_t;

static pthread_key_t g_hub_tls_key;
static bool g_hub_initialized = false;

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
    HLOGI("hub initialized (pool=%d, max_depth=%d, slot_size=%d)",
          ADL_HUB_STACK_POOL_SIZE, ADL_HUB_FRAME_MAX, ADL_HUB_SLOT_SIZE);
}

// ============================================================================
// Push / Pop
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
            // Recursive call detected
            if (data->flags & ADL_HUB_FLAG_ALLOW_REENTRANT) {
                // Reentrant allowed: push new frame and call proxy again
                break; // fall through to push
            }
            return data->trampoline;  // default: skip proxy
        }
    }

    // Push frame
    if (stack->count < ADL_HUB_FRAME_MAX) {
        stack->frames[stack->count].orig_addr = data->orig_addr;
        stack->frames[stack->count].flags = data->flags;
        stack->count++;
    }

    // Return first enabled proxy
    for (adl_hub_proxy_t *p = data->proxies; p != NULL; p = p->next) {
        if (p->enabled) return p->func;
    }
    return data->trampoline;
}

extern "C" void adl_hub_pop(adl_hub_data_t *data) {
    (void)data;
    adl_hub_stack_t *stack = static_cast<adl_hub_stack_t *>(
        pthread_getspecific(g_hub_tls_key));
    if (stack == NULL || stack->count <= 0) return;
    stack->count--;
}

// ============================================================================
// Proxy chain management
// ============================================================================

void *adl_hub_add_proxy(adl_hub_data_t *data, void *proxy_func) {
    adl_hub_proxy_t *proxy = new adl_hub_proxy_t();
    proxy->func = proxy_func;
    proxy->enabled = true;

    // New proxy's "orig" points to what the current head points to
    // If there's an existing head proxy, orig = head proxy's func
    // If no existing proxy, orig = trampoline
    if (data->proxies != NULL) {
        proxy->orig = data->proxies->func;  // chain to previous head
    } else {
        proxy->orig = data->trampoline;
    }

    // Insert at head
    proxy->next = data->proxies;
    data->proxies = proxy;

    HLOGI("proxy added: func=%p, orig=%p, chain_depth=%d",
          proxy_func, proxy->orig,
          ({int n=0; for(adl_hub_proxy_t*p=data->proxies;p;p=p->next)n++; n;}));

    return proxy->orig;
}

int adl_hub_remove_proxy(adl_hub_data_t *data, void *proxy_func) {
    adl_hub_proxy_t **pp = &data->proxies;
    while (*pp != NULL) {
        if ((*pp)->func == proxy_func) {
            adl_hub_proxy_t *removed = *pp;

            // If removing the head, update the next proxy's "orig"
            // to point to the removed proxy's "orig" (skip over it)
            if (removed->next != NULL && *pp == data->proxies) {
                // Next proxy becomes head; its orig should be what removed's orig was
                // Actually, next proxy already has its own orig set correctly
                // We just need to unlink
            }

            *pp = removed->next;

            // Fix chain: if there's a proxy whose orig pointed to removed->func,
            // update it to point to removed->orig
            for (adl_hub_proxy_t *p = data->proxies; p != NULL; p = p->next) {
                if (p->orig == proxy_func) {
                    p->orig = removed->orig;
                }
            }

            HLOGI("proxy removed: func=%p", proxy_func);
            delete removed;
            return 0;
        }
        pp = &(*pp)->next;
    }
    return -1;
}

// ============================================================================
// Shared hub page allocator
// ============================================================================

struct adl_hub_page {
    void *base;
    size_t used;
    adl_hub_page *next;
};

static adl_hub_page *g_hub_pages = NULL;
static pthread_mutex_t g_hub_page_mutex = PTHREAD_MUTEX_INITIALIZER;

static void *alloc_hub_slot(void) {
    pthread_mutex_lock(&g_hub_page_mutex);

    // Try to find space in existing pages
    for (adl_hub_page *page = g_hub_pages; page != NULL; page = page->next) {
        if (page->used + ADL_HUB_SLOT_SIZE <= PAGE_SIZE) {
            void *slot = static_cast<uint8_t *>(page->base) + page->used;
            page->used += ADL_HUB_SLOT_SIZE;
            pthread_mutex_unlock(&g_hub_page_mutex);
            return slot;
        }
    }

    // Need new page
    void *base = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (base == MAP_FAILED) {
        pthread_mutex_unlock(&g_hub_page_mutex);
        HLOGE("hub page mmap failed");
        return NULL;
    }

    adl_hub_page *page = new adl_hub_page();
    page->base = base;
    page->used = ADL_HUB_SLOT_SIZE;
    page->next = g_hub_pages;
    g_hub_pages = page;

    pthread_mutex_unlock(&g_hub_page_mutex);

    HLOGI("new hub page @%p (slots=%d)", base, (int)(PAGE_SIZE / ADL_HUB_SLOT_SIZE));
    return base;
}

// ============================================================================
// Hub code creation from assembly template
// ============================================================================

#if defined(__aarch64__)

extern "C" void adl_hub_template_entry(void);
extern "C" void adl_hub_template_end(void);

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

    if (tmpl_size == 0 || tmpl_size > ADL_HUB_SLOT_SIZE) {
        HLOGE("hub template size invalid: %zu (max %d)", tmpl_size, ADL_HUB_SLOT_SIZE);
        return NULL;
    }

    void *slot = alloc_hub_slot();
    if (slot == NULL) return NULL;

    memcpy(slot, reinterpret_cast<void *>(tmpl_start), tmpl_size);

    patch_placeholder(static_cast<uint8_t *>(slot), tmpl_size,
                      PLACEHOLDER_HUB_DATA, reinterpret_cast<uint64_t>(data));
    patch_placeholder(static_cast<uint8_t *>(slot), tmpl_size,
                      PLACEHOLDER_PUSH_FN, reinterpret_cast<uint64_t>(&adl_hub_push));
    patch_placeholder(static_cast<uint8_t *>(slot), tmpl_size,
                      PLACEHOLDER_POP_FN, reinterpret_cast<uint64_t>(&adl_hub_pop));

    __builtin___clear_cache(static_cast<char *>(slot),
                            static_cast<char *>(slot) + tmpl_size);

    data->hub_slot = slot;
    HLOGI("hub created: %zu bytes in shared slot @%p, data@%p",
          tmpl_size, slot, data);
    return slot;
}

#else

void *adl_hub_create(adl_hub_data_t *data) {
    adl_hub_init();
    (void)data;
    HLOGE("hub not implemented for this architecture");
    return NULL;
}

#endif

void adl_hub_destroy(void *hub_entry) {
    (void)hub_entry;
    // Slots are not freed — shared pages persist for process lifetime
    // This prevents use-after-free from other threads referencing the hub code
}
