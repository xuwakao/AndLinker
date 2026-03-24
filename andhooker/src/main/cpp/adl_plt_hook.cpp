//
// PLT/GOT hook implementation
//

#include <sys/mman.h>
#include <sys/user.h>
#include <string.h>
#include <errno.h>
#include <android/log.h>

#include "adl_hook.h"
#include "adl.h"
#include "adl_internal.h"

#define HOOKER_TAG "adl_hooker"
#ifdef ADL_HOOKER_VERBOSE
#define HLOGI(...) __android_log_print(ANDROID_LOG_INFO, HOOKER_TAG, __VA_ARGS__)
#else
#define HLOGI(...)
#endif
#define HLOGE(...) __android_log_print(ANDROID_LOG_ERROR, HOOKER_TAG, __VA_ARGS__)

// Record of a PLT hook for unhook support
struct plt_hook_record {
    const char *caller_lib;
    const char *target_func;
    void *got_addr;
    void *orig_func;
    plt_hook_record *next;
};

static plt_hook_record *g_plt_hooks = NULL;

static int adl_set_got_entry(void *got_addr, void *new_value) {
    // Make the GOT page writable
    uintptr_t page_start = reinterpret_cast<uintptr_t>(got_addr) & ~(PAGE_SIZE - 1);
    size_t page_size = PAGE_SIZE;

    if (mprotect(reinterpret_cast<void *>(page_start), page_size,
                 PROT_READ | PROT_WRITE) != 0) {
        HLOGE("mprotect failed: %s", strerror(errno));
        return -1;
    }

    // Write the new value
    *reinterpret_cast<void **>(got_addr) = new_value;

    // Flush instruction cache
    __builtin___clear_cache(reinterpret_cast<char *>(got_addr),
                            reinterpret_cast<char *>(got_addr) + sizeof(void *));

    // Restore page protection (read-only)
    mprotect(reinterpret_cast<void *>(page_start), page_size, PROT_READ);

    return 0;
}

static plt_hook_record *find_record(const char *caller_lib, const char *target_func) {
    for (plt_hook_record *r = g_plt_hooks; r != NULL; r = r->next) {
        if (strcmp(r->caller_lib, caller_lib) == 0 &&
            strcmp(r->target_func, target_func) == 0) {
            return r;
        }
    }
    return NULL;
}

int adl_plt_hook(const char *caller_lib, const char *target_func,
                 void *new_func, void **orig_func) {
    if (caller_lib == NULL || target_func == NULL || new_func == NULL) {
        HLOGE("adl_plt_hook: invalid arguments");
        return -1;
    }

    // Open the caller library to get its so_info
    void *handle = adlopen(caller_lib, 0);
    if (handle == NULL) {
        HLOGE("adl_plt_hook: adlopen(%s) failed", caller_lib);
        return -1;
    }

    adl_so_info *soInfo = reinterpret_cast<adl_so_info *>(handle);

    // Parse dynamic section to fill plt_rel/plt_rela, symtab, strtab
    if (adl_prelink_image(soInfo) < 0) {
        HLOGE("adl_plt_hook: prelink failed for %s", caller_lib);
        adlclose(handle);
        return -1;
    }

    ElfW(Addr) load_bias = soInfo->load_bias;

    // Find the target symbol index in the symbol table
    bool found = false;

#if defined(ADL_USE_RELA)
    if (soInfo->plt_rela_ != NULL) {
        for (size_t i = 0; i < soInfo->plt_rela_count_; i++) {
            const ElfW(Rela) *rela = &soInfo->plt_rela_[i];
            size_t sym_idx = ELF64_R_SYM(rela->r_info);
            if (sym_idx == 0) continue;

            const ElfW(Sym) *sym = &soInfo->symtab_[sym_idx];
            const char *sym_name = soInfo->strtab_ + sym->st_name;

            if (strcmp(sym_name, target_func) == 0) {
                void *got_addr = reinterpret_cast<void *>(load_bias + rela->r_offset);
                void *old_func = *reinterpret_cast<void **>(got_addr);

                if (orig_func != NULL) *orig_func = old_func;

                if (adl_set_got_entry(got_addr, new_func) != 0) {
                    adlclose(handle);
                    return -1;
                }

                // Save record for unhook
                plt_hook_record *record = new plt_hook_record();
                record->caller_lib = strdup(caller_lib);
                record->target_func = strdup(target_func);
                record->got_addr = got_addr;
                record->orig_func = old_func;
                record->next = g_plt_hooks;
                g_plt_hooks = record;

                HLOGI("PLT hook: %s!%s -> %p (was %p, GOT@%p)",
                      caller_lib, target_func, new_func, old_func, got_addr);
                found = true;
                break;
            }
        }
    }
#else
    if (soInfo->plt_rel_ != NULL) {
        for (size_t i = 0; i < soInfo->plt_rel_count_; i++) {
            const ElfW(Rel) *rel = &soInfo->plt_rel_[i];
            size_t sym_idx = ELF32_R_SYM(rel->r_info);
            if (sym_idx == 0) continue;

            const ElfW(Sym) *sym = &soInfo->symtab_[sym_idx];
            const char *sym_name = soInfo->strtab_ + sym->st_name;

            if (strcmp(sym_name, target_func) == 0) {
                void *got_addr = reinterpret_cast<void *>(load_bias + rel->r_offset);
                void *old_func = *reinterpret_cast<void **>(got_addr);

                if (orig_func != NULL) *orig_func = old_func;

                if (adl_set_got_entry(got_addr, new_func) != 0) {
                    adlclose(handle);
                    return -1;
                }

                plt_hook_record *record = new plt_hook_record();
                record->caller_lib = strdup(caller_lib);
                record->target_func = strdup(target_func);
                record->got_addr = got_addr;
                record->orig_func = old_func;
                record->next = g_plt_hooks;
                g_plt_hooks = record;

                HLOGI("PLT hook: %s!%s -> %p (was %p, GOT@%p)",
                      caller_lib, target_func, new_func, old_func, got_addr);
                found = true;
                break;
            }
        }
    }
#endif

    adlclose(handle);

    if (!found) {
        HLOGE("adl_plt_hook: symbol \"%s\" not found in PLT of \"%s\"",
              target_func, caller_lib);
        return -1;
    }

    return 0;
}

int adl_plt_unhook(const char *caller_lib, const char *target_func) {
    if (caller_lib == NULL || target_func == NULL) return -1;

    plt_hook_record *record = find_record(caller_lib, target_func);
    if (record == NULL) {
        HLOGE("adl_plt_unhook: no hook record for %s!%s", caller_lib, target_func);
        return -1;
    }

    if (adl_set_got_entry(record->got_addr, record->orig_func) != 0) {
        return -1;
    }

    HLOGI("PLT unhook: %s!%s restored to %p", caller_lib, target_func, record->orig_func);

    // Remove from linked list
    plt_hook_record **pp = &g_plt_hooks;
    while (*pp != NULL) {
        if (*pp == record) {
            *pp = record->next;
            free((void *) record->caller_lib);
            free((void *) record->target_func);
            delete record;
            break;
        }
        pp = &(*pp)->next;
    }

    return 0;
}
