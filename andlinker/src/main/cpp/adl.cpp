#include <jni.h>
#include "adl.h"
#include "adl_util.h"
#include "adl_linker.h"

__BEGIN_DECLS

struct {
    char *filename;
    ElfW(Addr) load_bias;
    ElfW(Addr) base;
    ElfW(Phdr) *phdr;
    ElfW(Half) phnum;
} adl_so;

/* Returns the size of the extent of all the possibly non-contiguous
 * loadable segments in an ELF program header table. This corresponds
 * to the page-aligned size in bytes that needs to be reserved in the
 * process' address space. If there are no loadable segments, 0 is
 * returned.
 *
 * If out_min_vaddr or out_max_vaddr are not null, they will be
 * set to the minimum and maximum addresses of pages to be reserved,
 * or 0 if there is nothing to load.
 */
size_t adl_phdr_table_get_load_size(const ElfW(Phdr) *phdr_table, size_t phdr_count,
                                    ElfW(Addr) *out_min_vaddr,
                                    ElfW(Addr) *out_max_vaddr) {
    ElfW(Addr) min_vaddr = UINTPTR_MAX;
    ElfW(Addr) max_vaddr = 0;

    bool found_pt_load = false;
    for (size_t i = 0; i < phdr_count; ++i) {
        const ElfW(Phdr) *phdr = &phdr_table[i];

        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        found_pt_load = true;

        if (phdr->p_vaddr < min_vaddr) {
            min_vaddr = phdr->p_vaddr;
        }

        if (phdr->p_vaddr + phdr->p_memsz > max_vaddr) {
            max_vaddr = phdr->p_vaddr + phdr->p_memsz;
        }
    }
    if (!found_pt_load) {
        min_vaddr = 0;
    }

    min_vaddr = PAGE_START(min_vaddr);
    max_vaddr = PAGE_END(max_vaddr);

    if (out_min_vaddr != nullptr) {
        *out_min_vaddr = min_vaddr;
    }
    if (out_max_vaddr != nullptr) {
        *out_max_vaddr = max_vaddr;
    }
    return max_vaddr - min_vaddr;
}


/**
 *
 * See comments in <bionic/linker/linker_soinfo.h> :
 **    //When you read a virtual address from the ELF file, add this
 **    //value to get the corresponding address in the process' address space.
 **    ElfW(Addr) load_bias;
 * base = load_bias + file_virtual_address(p_vaddr)
 *
 * dl_phdr_info.dlpi_addr == link_map.l_addr == soinfo.load_bias
 *
 * @param info
 * @param size
 * @param data
 * @return
 */
static int adl_iterate_phdr_callback(struct dl_phdr_info *info, size_t size, void *data) {
    if (NULL == info->dlpi_name || '\0' == info->dlpi_name[0]) {
        ADLOGW("adl_iterate_phdr_callback dlpi_name is invalid.");
        return 0;
    }

    if (info->dlpi_addr == NULL) {
        ADLOGW("adl_iterate_phdr_callback dlpi_addr is invalid.");
        return 0;
    }

    if (info->dlpi_phdr == NULL || 0 == info->dlpi_phnum) {
        ADLOGW("adl_iterate_phdr_callback dlpi_phdr is invalid.[%lu L %d]", info->dlpi_phdr,
               info->dlpi_phnum);
        return 0;
    }

    if ('/' != info->dlpi_name[0] && '[' != info->dlpi_name[0]) {
        ADLOGW("ELF %s is loaded without full path name ", info->dlpi_name);
    }

    uintptr_t *args = (uintptr_t *) data;
    const char *filename = reinterpret_cast<const char *>(args[0]);

    const ElfW(Phdr) *phdr_table = info->dlpi_phdr;
    ElfW(Addr) min_vaddr, max_vaddr;
    adl_phdr_table_get_load_size(phdr_table, info->dlpi_phnum, &min_vaddr,
                                 &max_vaddr);
    ElfW(Addr) load_bias = info->dlpi_addr;
    ElfW(Addr) base = load_bias + min_vaddr;

//    ADLOGI("ELF[2] %s dl_phdr_info dlpi_phdr = %lu , dlpi_phnum %d , dlpi_addr = %lu , base = %lu , bias = %lu",
//         info->dlpi_name, info->dlpi_phdr, info->dlpi_phnum, info->dlpi_addr, base, load_bias);
    return 0;
}

int adl_iterate_phdr(int (*callback)(struct dl_phdr_info *info, size_t size, void *args),
                     void *args) {
    if (callback == NULL) return 0;

    return do_adl_iterate_phdr(adl_iterate_phdr_callback, args);
}

void *adlopen(const char *filename, int flag) {
    if (filename == NULL || !adl_file_exists(filename)) {
        ADLOGW("adlopen file not exist");
        return NULL;
    }
    int level = adl_get_api_level();
    if (level >= __ANDROID_API_O_MR1__) {
        uintptr_t args[1] = {(uintptr_t) filename};
        do_adl_iterate_phdr(adl_iterate_phdr_callback, args);
    }
    return NULL;
}

__END_DECLS
