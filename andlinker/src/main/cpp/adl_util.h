//
// Created by P7XXTM1-G on 5/20/2021.
//

#ifndef ANDLINKER_ADL_UTIL_H
#define ANDLINKER_ADL_UTIL_H

#include <sys/cdefs.h>
#include <android/log.h>
#include <stdio.h>
#include <sys/user.h>
#include <android/api-level.h>
#include <sys/stat.h>
#include <string.h>
#include <link.h>
#include <inttypes.h>
#include <ctype.h>
#include <cstdlib>

//#define NO_LOG
#define TAG "adl"
#ifndef NO_LOG
#define ADLOGI(...) __android_log_print(ANDROID_LOG_INFO,TAG,__VA_ARGS__)
#define ADLOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define ADLOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define ADLOGE(...) __android_log_print(ANDROID_LOG_ERROR,TAG,__VA_ARGS__)
#else
#define ADLOGI(...)
#define ADLOGD(...)
#define ADLOGW(...)
#define ADLOGE(...)
#endif

// Returns the address of the page containing address 'x'.
#define PAGE_START(x) ((x) & PAGE_MASK)

// Returns the offset of address 'x' in its page.
#define PAGE_OFFSET(x) ((x) & ~PAGE_MASK)

// Returns the address of the next page after address 'x', unless 'x' is
// itself at the start of a page.
#define PAGE_END(x) PAGE_START((x) + (PAGE_SIZE-1))

#define ADL_FLAG_NEW_SOINFO       0x40000000 // new soinfo format

#define ADL_FLAG_GNU_HASH         0x00000040 // uses gnu hash
#define ADL_FLAG_PRELINKED        0x00000400 // prelink_image has successfully processed this soinfo

// Android uses RELA for LP64.
#if defined(__LP64__)
#define ADL_USE_RELA 1
#endif

#define SELF_MAPS_PATH "/proc/self/maps"

constexpr ElfW(Versym) ADL_kVersymNotNeeded = 0;
constexpr ElfW(Versym) ADL_kVersymGlobal = 1;

#ifndef __LP64__
#define LINKER_BASENAME "linker"
#define LINKER_PATHNAME "/system/bin/linker"
#else
#define LINKER_BASENAME "linker64"
#define LINKER_PATHNAME "/system/bin/linker64"
#endif


__BEGIN_DECLS

static int adl_get_api_level(void) {
    static int api_level = -1;
    if (api_level < 0) {
        api_level = android_get_device_api_level();
    }
    return api_level;
}

static inline bool adl_ends_with(const char *s1, const char *s2) {
    size_t s1_length = strlen(s1);
    size_t s2_length = strlen(s2);
    if (s2_length > s1_length) {
        return false;
    }
    return memcmp(s1 + (s1_length - s2_length), s2, s2_length) == 0;
}

// Checks if the file exists and not a directory.
static bool adl_file_exists(const char *path) {
    struct stat s;

    if (stat(path, &s) != 0) {
        return false;
    }

    return S_ISREG(s.st_mode);
}

constexpr off64_t kPageMask = ~static_cast<off64_t>(PAGE_SIZE - 1);
static off64_t adl_page_start(off64_t offset) {
    return offset & kPageMask;
}

static bool adl_safe_add(off64_t *out, off64_t a, size_t b) {
    if (static_cast<uint64_t>(INT64_MAX - a) < b) {
        return false;
    }

    *out = a + b;
    return true;
}

static size_t adl_page_offset(off64_t offset) {
    return static_cast<size_t>(offset & (PAGE_SIZE - 1));
}

static bool adl_realpath_fd(int fd, const char *realpath) {
    // proc_self_fd needs to be large enough to hold "/proc/self/fd/" plus an
    // integer, plus the NULL terminator.
    char proc_self_fd[32];
    // We want to statically allocate this large buffer so that we don't grow
    // the stack by too much.
    static char buf[PATH_MAX];

    snprintf(proc_self_fd, sizeof(proc_self_fd), "/proc/self/fd/%d", fd);
    auto length = readlink(proc_self_fd, buf, sizeof(buf));
    if (length == -1) {
        return false;
    }

    memcpy((void *) realpath, buf, length);
    return true;
}


static inline const void *adl_untag_address(const void *p) {
#if defined(__aarch64__)
    return reinterpret_cast<const void*>(reinterpret_cast<uintptr_t>(p) & ((1ULL << 56) - 1));
#else
    return p;
#endif
}

static char *adl_string_trim(char *start) {
    char *end;
    // Trim leading space
    while (isspace((unsigned char) *start)) start++;

    if (*start == 0)  // All spaces?
        return 0;

    // Trim trailing space
    end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char) *end)) end--;
    // Write new null terminator character
    end[1] = '\0';
    return start;
}

static bool adl_verify_elf_header(const ElfW(Ehdr) *ehdr) {
    if (ehdr == NULL) {
        return false;
    }
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        ADLOGE("bad ELF magic: %02x%02x%02x%02x",
               ehdr->e_ident[0], ehdr->e_ident[1], ehdr->e_ident[2], ehdr->e_ident[3]);
        return false;
    }

    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        ADLOGE("not little-endian: %d", ehdr->e_ident[EI_DATA]);
        return false;
    }

    if (ehdr->e_type != ET_DYN) {
        ADLOGE("has unexpected e_type: %d", ehdr->e_type);
        return false;
    }

    if (ehdr->e_version != EV_CURRENT) {
        ADLOGE("has unexpected e_version: %d", ehdr->e_version);
        return false;
    }

    if (ehdr->e_shentsize != sizeof(ElfW(Shdr))) {
        // Fail if app is targeting Android O or above
        if (adl_get_api_level() >= 26) {
            ADLOGE("has unsupported e_shentsize: 0x%x (expected 0x%zx)",
                   ehdr->e_shentsize, sizeof(ElfW(Shdr)));
            return false;
        }
        ADLOGW("invalid-elf-header_section-headers-enforced-for-api-level-26, "
               "has unsupported e_shentsize 0x%x (expected 0x%zx)",
               ehdr->e_shentsize, sizeof(ElfW(Shdr)));
        ADLOGW("has invalid ELF header");
    }

    if (ehdr->e_shstrndx == 0) {
        // Fail if app is targeting Android O or above
        if (adl_get_api_level() >= 26) {
            ADLOGE("has invalid e_shstrndx");
            return false;
        }

        ADLOGW("invalid-elf-header_section-headers-enforced-for-api-level-26, "
               "has invalid e_shstrndx");
        ADLOGW("has invalid ELF header");
    }
    return true;
}

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
static size_t adl_phdr_table_get_load_size(const ElfW(Phdr) *phdr_table,
                                           size_t phdr_count,
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

    if (out_min_vaddr != NULL) {
        *out_min_vaddr = min_vaddr;
    }
    if (out_max_vaddr != NULL) {
        *out_max_vaddr = max_vaddr;
    }
    return max_vaddr - min_vaddr;
}

static FILE *adl_maps_open_reset() {
    FILE *maps = NULL;
    if (maps == NULL) {
        maps = fopen(SELF_MAPS_PATH, "re");
        if (maps == NULL)
            return NULL;
    }
    fseeko(maps, 0, SEEK_SET);
    return maps;
}

static bool adl_read_path_by_base(uintptr_t base,
                                  char *output,
                                  int out_len) {
    FILE *maps = NULL;
    if ((maps = adl_maps_open_reset()) == NULL) {
        return false;
    }

    uintptr_t start, end;
    char line[1024]{};
    char pathname[PATH_MAX];
    while (fgets(line, 1024, maps) != NULL) {
        const char *map_line = adl_string_trim(line);
        if (2 != sscanf(map_line, "%" SCNxPTR
                                  "-%"
                                  SCNxPTR
                                  " %*s %*"
                                  SCNxPTR
                                  " %*s %*s %s",
                        &start, &end, pathname))
            continue;
        if (base < start || base >= end) continue;
        strlcpy(output, pathname, out_len);
        fclose(maps);
        return true;
    }
    fclose(maps);
    return false;
}

typedef int (*adl_iterate_phdr_cb)(struct dl_phdr_info *info,
                                   size_t size, void *args);
static int adl_iterate_library_by_maps(adl_iterate_phdr_cb callback,
                                       void *args) {
    FILE *maps = NULL;
    if ((maps = adl_maps_open_reset()) == NULL) {
        return 0;
    }
    uintptr_t start, offset;
    char line[1024]{};
    char pathname[PATH_MAX];
    int result = 0;
    while (fgets(line, 1024, maps) != NULL) {
        const char *map_line = adl_string_trim(line);
        if (2 != sscanf(map_line, "%" SCNxPTR
                                  "-%*"
                                  SCNxPTR
                                  " r-xp %"
                                  SCNxPTR
                                  " %*s %*s %s",
                        &start, &offset, pathname))
            continue;
        if (0 != offset) continue;

        const ElfW(Ehdr) *ehdr = reinterpret_cast<const ElfW(Ehdr) *>(start);
        if (!adl_verify_elf_header(ehdr))
            continue;

        struct dl_phdr_info info;
        info.dlpi_name = pathname;
        info.dlpi_phdr = (const ElfW(Phdr) *) (start + ehdr->e_phoff);
        info.dlpi_phnum = ehdr->e_phnum;

        ElfW(Addr) min_vaddr, max_vaddr;
        adl_phdr_table_get_load_size(info.dlpi_phdr,
                                     info.dlpi_phnum, &min_vaddr,
                                     &max_vaddr);
        if (min_vaddr == UINTPTR_MAX) return 0;//min address is invalid
        ElfW(Addr) load_bias = start - min_vaddr;
        info.dlpi_addr = load_bias;

        result = callback(&info, sizeof(dl_phdr_info), args);
        if (result != 0)
            break;
    }
    fclose(maps);
    return result;
}

static ElfW(Addr) adl_read_base_by_maps(const char *library) {
    FILE *maps = NULL;
    if ((maps = adl_maps_open_reset()) == NULL) {
        return 0;
    }

    uintptr_t start, offset;
    char line[1024]{};
    while (fgets(line, 1024, maps) != NULL) {
        if (!adl_ends_with(adl_string_trim(line), library))
            continue;

        if (2 != sscanf(line, "%" SCNxPTR
                              "-%*"
                              SCNxPTR
                              " r-xp %"
                              SCNxPTR
                              " ", &start, &offset))
            continue;
        if (0 != offset) continue;
        return start;
    }
    fclose(maps);
    return 0;
}

static dl_phdr_info *adl_read_linker_by_maps() {
    ElfW(Addr) start = adl_read_base_by_maps(LINKER_BASENAME);
    const ElfW(Ehdr) *ehdr = reinterpret_cast<const ElfW(Ehdr) *>(start);
    if (!adl_verify_elf_header(ehdr))
        return NULL;
    struct dl_phdr_info *info = static_cast<dl_phdr_info *>(
            calloc(1, sizeof(dl_phdr_info)));;
    info->dlpi_name = strdup(LINKER_PATHNAME);
    info->dlpi_phdr = (const ElfW(Phdr) *) (start + ehdr->e_phoff);
    info->dlpi_phnum = ehdr->e_phnum;

    ElfW(Addr) min_vaddr, max_vaddr;
    adl_phdr_table_get_load_size(info->dlpi_phdr,
                                 info->dlpi_phnum, &min_vaddr,
                                 &max_vaddr);
    if (min_vaddr == UINTPTR_MAX) return 0;//min address is invalid
    ElfW(Addr) load_bias = start - min_vaddr;
    info->dlpi_addr = load_bias;
    return info;
}

__END_DECLS

#endif //ANDLINKER_ADL_UTIL_H

