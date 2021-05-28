#include <jni.h>
#include <malloc.h>
#include <sys/param.h>

#include "adl.h"
#include "adl_util.h"
#include "adl_linker.h"
#include "adl_linker_phdr.h"

__BEGIN_DECLS

static constexpr ElfW(Versym) ADL_kVersymHiddenBit = 0x8000;

typedef struct symbol_name {
    uint32_t elf_hash();

    uint32_t gnu_hash();

    const char *name_;
    bool has_elf_hash_;
    bool has_gnu_hash_;
    uint32_t elf_hash_;
    uint32_t gnu_hash_;
} adl_symbol;

typedef struct version_info {
    constexpr version_info() : elf_hash(0), name(NULL) {}

    uint32_t elf_hash;
    const char *name;
} adl_version_info;

typedef struct tls_segment {
    size_t size = 0;
    size_t alignment = 1;
    const void *init_ptr = "";    // Field is non-null even when init_size is 0.
    size_t init_size = 0;
} adl_tls_segment;

typedef struct so_info {
    char *filename;
    ElfW(Addr) load_bias;
    ElfW(Addr) base;
    const ElfW(Phdr) *phdr;
    ElfW(Half) phnum;
    uint32_t flags_;

    ElfW(Dyn) *dynamic;

    const char *strtab_;
    size_t strtab_size_;
    ElfW(Sym) *symtab_;

    size_t nbucket_;
    size_t nchain_;
    uint32_t *bucket_;
    uint32_t *chain_;

#if defined(ADL_USE_RELA)
    ElfW(Rela)* plt_rela_;
    size_t plt_rela_count_;

    ElfW(Rela)* rela_;
    size_t rela_count_;
#else
    ElfW(Rel) *plt_rel_;
    size_t plt_rel_count_;

    ElfW(Rel) *rel_;
    size_t rel_count_;
#endif

#if !defined(__LP64__)
    bool has_text_relocations;
#endif
    bool has_DT_SYMBOLIC;

    adl_tls_segment *tls_segment;

    // version >= 2
    size_t gnu_nbucket_;
    uint32_t *gnu_bucket_;
    uint32_t *gnu_chain_;
    uint32_t gnu_maskwords_;
    uint32_t gnu_shift2_;
    ElfW(Addr) *gnu_bloom_filter_;


    uint8_t *android_relocs_;
    size_t android_relocs_size_;

    const ElfW(Versym) *versym_;

    ElfW(Addr) verdef_ptr_;
    size_t verdef_cnt_;

    ElfW(Addr) verneed_ptr_;
    size_t verneed_cnt_;

    // version >= 4
    ElfW(Relr) *relr_;
    size_t relr_count_;

    bool is_gnu_hash() const;
} adl_so_info;

bool adl_so_info::is_gnu_hash() const {
    return (flags_ & ADL_FLAG_GNU_HASH) != 0;
}

static uint32_t calculate_elf_hash(const char *name) {
    const uint8_t *name_bytes = reinterpret_cast<const uint8_t *>(name);
    uint32_t h = 0, g;

    while (*name_bytes) {
        h = (h << 4) + *name_bytes++;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
    }

    return h;
}

uint32_t adl_symbol::elf_hash() {
    if (!has_elf_hash_) {
        elf_hash_ = calculate_elf_hash(name_);
        has_elf_hash_ = true;
    }

    return elf_hash_;
}

static uint32_t calculate_gnu_hash_simple(const char *name) {
    uint32_t h = 5381;
    const uint8_t *name_bytes = reinterpret_cast<const uint8_t *>(name);
    while (*name_bytes != 0) {
        h += (h << 5) + *name_bytes++; // h*33 + c = h + h * 32 + c = h + h << 5 + c
    }
    return h;
}

uint32_t adl_symbol::gnu_hash() {
    if (!has_gnu_hash_) {
        gnu_hash_ = calculate_gnu_hash_simple(name_);
        has_gnu_hash_ = true;
    }

    return gnu_hash_;
}

static inline bool adl_is_symbol_global_and_defined(const adl_so_info *si, const ElfW(Sym) *s) {
    if (__predict_true(ELF_ST_BIND(s->st_info) == STB_GLOBAL ||
                       ELF_ST_BIND(s->st_info) == STB_WEAK)) {
        return s->st_shndx != SHN_UNDEF;
    } else if (__predict_false(ELF_ST_BIND(s->st_info) != STB_LOCAL)) {
        ADLOGW("Warning: unexpected ST_BIND value: %d for \"%s\" in \"%s\" (ignoring)",
               ELF_ST_BIND(s->st_info), si->strtab_ + s->st_name, si->filename);
    }
    return false;
}


//TODO : force ADL_kVersymNotNeeded
ElfW(Versym) adl_find_verdef_version_index(const adl_so_info *si, const version_info *vi) {
    return ADL_kVersymNotNeeded;
//    if (vi == nullptr) {
//        return ADL_kVersymNotNeeded;
//    }
//
//    ElfW(Versym) result = ADL_kVersymGlobal;
//    return result;
}

// Check whether a requested version matches the version on a symbol definition. There are a few
// special cases:
//  - If the defining DSO has no version info at all, then any version matches.
//  - If no version is requested (vi==nullptr, verneed==kVersymNotNeeded), then any non-hidden
//    version matches.
//  - If the requested version is not defined by the DSO, then verneed is kVersymGlobal, and only
//    global symbol definitions match. (This special case is handled as part of the ordinary case
//    where the version must match exactly.)
// TODO : Not checked
static inline bool check_symbol_version(const ElfW(Versym) *ver_table, uint32_t sym_idx,
                                        const ElfW(Versym) verneed) {
    return true;
//    if (ver_table == nullptr) return true;
//    const uint32_t verdef = ver_table[sym_idx];
//    return (verneed == ADL_kVersymNotNeeded) ?
//           !(verdef & ADL_kVersymHiddenBit) :
//           verneed == (verdef & ~ADL_kVersymHiddenBit);
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
static size_t adl_phdr_table_get_load_size(const ElfW(Phdr) *phdr_table, size_t phdr_count,
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

static ElfW(Addr) resolve_symbol_address(const adl_so_info *soInfo, const ElfW(Sym) *s) {
    if (ELF_ST_TYPE(s->st_info) == STT_GNU_IFUNC) {
        //TODO : ifunc handle
//        return call_ifunc_resolver(s->st_value + soInfo->load_bias);
        return 0;
    }

    return static_cast<ElfW(Addr)>(s->st_value + soInfo->load_bias);
}

// Search for a TLS segment in the given phdr table. Returns true if it has a
// TLS segment and false otherwise.
static bool adl_get_tls_segment(const ElfW(Phdr) *phdr_table, size_t phdr_count,
                                ElfW(Addr) load_bias, adl_tls_segment *out) {
    for (size_t i = 0; i < phdr_count; ++i) {
        const ElfW(Phdr) &phdr = phdr_table[i];
        if (phdr.p_type == PT_TLS) {
            *out = adl_tls_segment{
                    phdr.p_memsz,
                    phdr.p_align,
                    reinterpret_cast<void *>(load_bias + phdr.p_vaddr),
                    phdr.p_filesz,
            };
            return true;
        }
    }
    return false;
}

// Return true if the alignment of a TLS segment is a valid power-of-two. Also
// cap the alignment if it's too high.
bool adl_check_tls_alignment(size_t *alignment) {
    // N.B. The size does not need to be a multiple of the alignment. With
    // ld.bfd (or after using binutils' strip), the TLS segment's size isn't
    // rounded up.
    if (*alignment == 0 || !powerof2(*alignment)) {
        return false;
    }
    // Bionic only respects TLS alignment up to one page.
    *alignment = MIN(*alignment, PAGE_SIZE);
    return true;
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

    if (info->dlpi_addr == 0) {
        ADLOGW("adl_iterate_phdr_callback dlpi_addr is invalid.");
        return 0;
    }

    if ('/' != info->dlpi_name[0] && '[' != info->dlpi_name[0]) {
        ADLOGW("ELF %s is loaded without full path name ", info->dlpi_name);
    }

    /**
     * copy to avoid modifying original one
     */
    struct dl_phdr_info ret_info;
    info = static_cast<dl_phdr_info *>(memcpy(&ret_info, info, sizeof(dl_phdr_info)));

    if (NULL == info->dlpi_phdr || 0 == info->dlpi_phnum) {
        ADLOGW("No program header table in ELF [%s], try to fix it.", info->dlpi_name);
        ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *) info->dlpi_addr;
        info->dlpi_phdr = (ElfW(Phdr) *) (info->dlpi_addr + ehdr->e_phoff);
        info->dlpi_phnum = ehdr->e_phnum;
    }

    uintptr_t *it_args = (uintptr_t *) data;
    adl_iterate_phdr_cb callback = reinterpret_cast<adl_iterate_phdr_cb>(*it_args++);
    void *org_arg = reinterpret_cast<void *>(*it_args++);
    ADLOGI("ELF[2] %s dl_phdr_info dlpi_phdr = 0x%llx , dlpi_phnum %d , dlpi_addr = 0x%llx",
           info->dlpi_name, info->dlpi_phdr, info->dlpi_phnum, info->dlpi_addr);
    return callback(info, size, org_arg);
}

static int adl_find_library_callback(struct dl_phdr_info *info, size_t size, void *data) {
    const ElfW(Phdr) *phdr_table = info->dlpi_phdr;
    ElfW(Addr) min_vaddr, max_vaddr;
    adl_phdr_table_get_load_size(phdr_table, info->dlpi_phnum, &min_vaddr,
                                 &max_vaddr);
    if (min_vaddr == UINTPTR_MAX) return 0;//min address is invalid
    ElfW(Addr) load_bias = info->dlpi_addr;
    ElfW(Addr) base = load_bias + min_vaddr;

    uintptr_t *it_args = (uintptr_t *) data;
    adl_so_info **soInfo = reinterpret_cast<adl_so_info **>(*it_args++);
    const char *filename = (const char *) *it_args;

    if (0 == info->dlpi_addr || NULL == info->dlpi_name) return 0;
    if ('/' == filename[0] || '[' == filename[0]) {
        if (0 != strcmp(info->dlpi_name, filename)) return 0;
    } else {
        if (!adl_ends_with(info->dlpi_name, filename)) return 0;
        //confirm the char before filename is '/'
        if ('/' != *(info->dlpi_name + (strlen(info->dlpi_name) - strlen(filename)) - 1)) return 0;
    }

    *soInfo = static_cast<adl_so_info *>(calloc(1, sizeof(adl_so_info)));
    (*soInfo)->filename = strdup(info->dlpi_name);
    (*soInfo)->load_bias = load_bias;
    (*soInfo)->base = base;
    (*soInfo)->phdr = info->dlpi_phdr;
    (*soInfo)->phnum = info->dlpi_phnum;
    return 1;
}

static adl_so_info *adl_find_library(const char *filename) {
    adl_so_info *soInfo = NULL;
    uintptr_t args[2] = {reinterpret_cast<uintptr_t>(&soInfo),
                         (uintptr_t) filename};
    adl_iterate_phdr(adl_find_library_callback, args);
    return soInfo;
}


static int adl_prelink_image(adl_so_info *soInfo) {
    if (soInfo->flags_ & ADL_FLAG_PRELINKED) return 0;
    /* Extract dynamic section */
    ElfW(Word) dynamic_flags = 0;
    adl_phdr_table_get_dynamic_section(soInfo->phdr, soInfo->phnum, soInfo->load_bias,
                                       &soInfo->dynamic, &dynamic_flags);
    if (soInfo->dynamic == NULL) {
        return -1;
    }

    adl_tls_segment tls_segment;
    if (adl_get_tls_segment(soInfo->phdr, soInfo->phnum, soInfo->load_bias, &tls_segment)) {
        if (!adl_check_tls_alignment(&tls_segment.alignment)) {
            return false;
        }
        soInfo->tls_segment = &tls_segment;
    }

    // Extract useful information from dynamic section.
    // Note that: "Except for the DT_NULL element at the end of the array,
    // and the relative order of DT_NEEDED elements, entries may appear in any order."
    //
    // source: http://www.sco.com/developers/gabi/1998-04-29/ch5.dynamic.html
    uint32_t needed_count = 0;
    ElfW(Addr) load_bias = soInfo->load_bias;
    for (ElfW(Dyn) *d = soInfo->dynamic; d->d_tag != DT_NULL; ++d) {
        ADLOGD("d = %p, d[0](tag) = %p d[1](val) = %p",
               d, reinterpret_cast<void *>(d->d_tag), reinterpret_cast<void *>(d->d_un.d_val));
        switch (d->d_tag) {
            case DT_SONAME:
                // this is parsed after we have strtab initialized (see below).
                break;
            case DT_HASH:
                soInfo->nbucket_ = reinterpret_cast<uint32_t *>(load_bias + d->d_un.d_ptr)[0];
                soInfo->nchain_ = reinterpret_cast<uint32_t *>(load_bias + d->d_un.d_ptr)[1];
                soInfo->bucket_ = reinterpret_cast<uint32_t *>(load_bias + d->d_un.d_ptr + 8);
                soInfo->chain_ = reinterpret_cast<uint32_t *>(load_bias + d->d_un.d_ptr + 8 +
                                                              soInfo->nbucket_ * 4);
                break;
            case DT_GNU_HASH:
                soInfo->gnu_nbucket_ = reinterpret_cast<uint32_t *>(load_bias + d->d_un.d_ptr)[0];
                // skip symndx
                soInfo->gnu_maskwords_ = reinterpret_cast<uint32_t *>(load_bias + d->d_un.d_ptr)[2];
                soInfo->gnu_shift2_ = reinterpret_cast<uint32_t *>(load_bias + d->d_un.d_ptr)[3];

                soInfo->gnu_bloom_filter_ = reinterpret_cast<ElfW(Addr) *>(load_bias +
                                                                           d->d_un.d_ptr + 16);
                soInfo->gnu_bucket_ = reinterpret_cast<uint32_t *>(soInfo->gnu_bloom_filter_ +
                                                                   soInfo->gnu_maskwords_);
                // amend chain for symndx = header[1]
                soInfo->gnu_chain_ = soInfo->gnu_bucket_ + soInfo->gnu_nbucket_ -
                                     reinterpret_cast<uint32_t *>(load_bias + d->d_un.d_ptr)[1];

                if (!powerof2(soInfo->gnu_maskwords_)) {
                    ADLOGE("invalid maskwords for gnu_hash = 0x%x, in \"%s\" expecting power to two",
                           soInfo->gnu_maskwords_, soInfo->filename);
                    return false;
                }
                --soInfo->gnu_maskwords_;
                soInfo->flags_ |= ADL_FLAG_GNU_HASH;
                break;
            case DT_STRTAB:
                soInfo->strtab_ = reinterpret_cast<const char *>(load_bias + d->d_un.d_ptr);
                break;
            case DT_STRSZ:
                soInfo->strtab_size_ = d->d_un.d_val;
                break;
            case DT_SYMTAB:
                soInfo->symtab_ = reinterpret_cast<ElfW(Sym) *>(load_bias + d->d_un.d_ptr);
                break;
            case DT_SYMENT:
                if (d->d_un.d_val != sizeof(ElfW(Sym))) {
                    ADLOGE("invalid DT_SYMENT: %zd in \"%s\"",
                           static_cast<size_t>(d->d_un.d_val), soInfo->filename);
                    return false;
                }
                break;
            case DT_PLTREL:
                if (d->d_un.d_val != DT_RELA) {
                    ADLOGE("unsupported DT_PLTREL in \"%s\"; expected DT_RELA", soInfo->filename);
                    return false;
                }
#if defined(ADL_USE_RELA)
                if (d->d_un.d_val != DT_RELA) {
                    ADLOGE("unsupported DT_PLTREL in \"%s\"; expected DT_RELA", soInfo->filename);
                    return false;
                }
#else
                if (d->d_un.d_val != DT_REL) {
                    ADLOGE("unsupported DT_PLTREL in \"%s\"; expected DT_REL", soInfo->filename);
                    return false;
                }
#endif
                break;
            case DT_JMPREL:
#if defined(ADL_USE_RELA)
                soInfo->plt_rela_ = reinterpret_cast<ElfW(Rela)*>(load_bias + d->d_un.d_ptr);
#else
                soInfo->plt_rel_ = reinterpret_cast<ElfW(Rel) *>(load_bias + d->d_un.d_ptr);
#endif
                break;
            case DT_PLTRELSZ:
#if defined(ADL_USE_RELA)
                soInfo->plt_rela_count_ = d->d_un.d_val / sizeof(ElfW(Rela));
#else
                soInfo->plt_rel_count_ = d->d_un.d_val / sizeof(ElfW(Rel));
#endif
                break;
            case DT_PLTGOT:
                // Ignored (because RTLD_LAZY is not supported).
                break;
            case DT_DEBUG:
                break;
#if defined(ADL_USE_RELA)
                case DT_RELA:
                    soInfo->rela_ = reinterpret_cast<ElfW(Rela)*>(load_bias + d->d_un.d_ptr);
                    break;

                case DT_RELASZ:
                    soInfo->rela_count_ = d->d_un.d_val / sizeof(ElfW(Rela));
                    break;

                case DT_ANDROID_RELA:
                    soInfo->android_relocs_ = reinterpret_cast<uint8_t*>(load_bias + d->d_un.d_ptr);
                    break;

                case DT_ANDROID_RELASZ:
                    soInfo->android_relocs_size_ = d->d_un.d_val;
                    break;

                case DT_ANDROID_REL:
                    ADLOGE("unsupported DT_ANDROID_REL in \"%s\"", soInfo->filename);
                    return false;

                case DT_ANDROID_RELSZ:
                    ADLOGE("unsupported DT_ANDROID_RELSZ in \"%s\"", soInfo->filename);
                    return false;

                case DT_RELAENT:
                    if (d->d_un.d_val != sizeof(ElfW(Rela))) {
                        ADLOGE("invalid DT_RELAENT: %zd", static_cast<size_t>(d->d_un.d_val));
                        return false;
                    }
                    break;

                    // Ignored (see DT_RELCOUNT comments for details).
                case DT_RELACOUNT:
                    break;

                case DT_REL:
                    ADLOGE("unsupported DT_REL in \"%s\"", soInfo->filename);
                    return false;

                case DT_RELSZ:
                    ADLOGE("unsupported DT_RELSZ in \"%s\"", soInfo->filename);
                    return false;
#else
            case DT_REL:
                soInfo->rel_ = reinterpret_cast<ElfW(Rel) *>(load_bias + d->d_un.d_ptr);
                break;
            case DT_RELSZ:
                soInfo->rel_count_ = d->d_un.d_val / sizeof(ElfW(Rel));
                break;
            case DT_RELENT:
                if (d->d_un.d_val != sizeof(ElfW(Rel))) {
                    ADLOGE("invalid DT_RELENT: %zd", static_cast<size_t>(d->d_un.d_val));
                    return false;
                }
                break;
            case DT_ANDROID_REL:
                soInfo->android_relocs_ = reinterpret_cast<uint8_t *>(load_bias + d->d_un.d_ptr);
                break;
            case DT_ANDROID_RELSZ:
                soInfo->android_relocs_size_ = d->d_un.d_val;
                break;
            case DT_ANDROID_RELA:
                ADLOGE("unsupported DT_ANDROID_RELA in \"%s\"", soInfo->filename);
                return false;
            case DT_ANDROID_RELASZ:
                ADLOGE("unsupported DT_ANDROID_RELASZ in \"%s\"", soInfo->filename);
                return false;
                // "Indicates that all RELATIVE relocations have been concatenated together,
                // and specifies the RELATIVE relocation count."
                //
                // TODO: Spec also mentions that this can be used to optimize relocation process;
                // Not currently used by bionic linker - ignored.
            case DT_RELCOUNT:
                break;
            case DT_RELA:
                ADLOGE("unsupported DT_RELA in \"%s\"", soInfo->filename);
                return false;
            case DT_RELASZ:
                ADLOGE("unsupported DT_RELASZ in \"%s\"", soInfo->filename);
                return false;
#endif
            case DT_RELR:
                soInfo->relr_ = reinterpret_cast<ElfW(Relr) *>(load_bias + d->d_un.d_ptr);
                break;
            case DT_RELRSZ:
                soInfo->relr_count_ = d->d_un.d_val / sizeof(ElfW(Relr));
                break;
            case DT_RELRENT:
                if (d->d_un.d_val != sizeof(ElfW(Relr))) {
                    ADLOGE("invalid DT_RELRENT: %zd", static_cast<size_t>(d->d_un.d_val));
                    return false;
                }
                break;
            case DT_TEXTREL:
#if defined(__LP64__)
                ADLOGE("\"%s\" has text relocations", soInfo->filename);
                return false;
#else
                soInfo->has_text_relocations = true;
                break;
#endif
            case DT_SYMBOLIC:
                soInfo->has_DT_SYMBOLIC = true;
                break;
            case DT_NEEDED:
                ++needed_count;
                break;
            case DT_FLAGS:
                if (d->d_un.d_val & DF_TEXTREL) {
#if defined(__LP64__)
                    ADLOGE("\"%s\" has text relocations", soInfo->filename);
                    return false;
#else
                    soInfo->has_text_relocations = true;
#endif
                }
                if (d->d_un.d_val & DF_SYMBOLIC) {
                    soInfo->has_DT_SYMBOLIC = true;
                }
                break;
            case DT_VERSYM:
                soInfo->versym_ = reinterpret_cast<ElfW(Versym) *>(load_bias + d->d_un.d_ptr);
                break;

            case DT_VERDEF:
                soInfo->verdef_ptr_ = load_bias + d->d_un.d_ptr;
                break;
            case DT_VERDEFNUM:
                soInfo->verdef_cnt_ = d->d_un.d_val;
                break;

            case DT_VERNEED:
                soInfo->verneed_ptr_ = load_bias + d->d_un.d_ptr;
                break;

            case DT_VERNEEDNUM:
                soInfo->verneed_cnt_ = d->d_un.d_val;
                break;
            default:
                break;
        }
    }

    if (soInfo->nbucket_ == 0 && soInfo->gnu_nbucket_ == 0) {
        ADLOGE("empty/missing DT_HASH/DT_GNU_HASH in \"%s\" "
               "(new hash type from the future?)", soInfo->filename);
        return -1;
    }
    if (soInfo->strtab_ == NULL) {
        ADLOGE("empty/missing DT_STRTAB in \"%s\"", soInfo->filename);
        return -1;
    }
    if (soInfo->symtab_ == NULL) {
        ADLOGE("empty/missing DT_SYMTAB in \"%s\"", soInfo->filename);
        return -1;
    }

    soInfo->flags_ |= ADL_FLAG_PRELINKED;
    return 0;
}

static ElfW(Sym) *
adl_gnu_lookup(adl_so_info *soInfo, adl_symbol &symbol_name, const version_info *vi) {
    const uint32_t hash = symbol_name.gnu_hash();

    constexpr uint32_t kBloomMaskBits = sizeof(ElfW(Addr)) * 8;
    const uint32_t word_num = (hash / kBloomMaskBits) & soInfo->gnu_maskwords_;
    const ElfW(Addr) bloom_word = soInfo->gnu_bloom_filter_[word_num];
    const uint32_t h1 = hash % kBloomMaskBits;
    const uint32_t h2 = (hash >> soInfo->gnu_shift2_) % kBloomMaskBits;

    ADLOGD("SEARCH %s in %s@%p (gnu)",
           symbol_name.name_, soInfo->filename, reinterpret_cast<void *>(soInfo->base));

    // test against bloom filter
    if ((1 & (bloom_word >> h1) & (bloom_word >> h2)) == 0) {
        ADLOGW("NOT FOUND %s in %s@%p",
               symbol_name.name_, soInfo->filename, reinterpret_cast<void *>(soInfo->base));

        return NULL;
    }

    // bloom test says "probably yes"...
    uint32_t n = soInfo->gnu_bucket_[hash % soInfo->gnu_nbucket_];

    if (n == 0) {
        ADLOGW("NOT FOUND %s in %s@%p",
               symbol_name.name_, soInfo->filename, reinterpret_cast<void *>(soInfo->base));

        return NULL;
    }

    const ElfW(Versym) verneed = adl_find_verdef_version_index(soInfo, vi);
    const ElfW(Versym) *versym = soInfo->versym_;

    do {
        ElfW(Sym) *s = soInfo->symtab_ + n;
        if (((soInfo->gnu_chain_[n] ^ hash) >> 1) == 0 &&
            check_symbol_version(versym, n, verneed) &&
            strcmp(soInfo->strtab_ + s->st_name, symbol_name.name_) == 0 &&
            adl_is_symbol_global_and_defined(soInfo, s)) {
            ADLOGW("FOUND %s in %s (%p) %zd",
                   symbol_name.name_, soInfo->filename, reinterpret_cast<void *>(s->st_value),
                   static_cast<size_t>(s->st_size));
            return soInfo->symtab_ + n;
        }
    } while ((soInfo->gnu_chain_[n++] & 1) == 0);

    ADLOGW("NOT FOUND %s in %s@%p",
           symbol_name.name_, soInfo->filename, reinterpret_cast<void *>(soInfo->base));

    return NULL;
}

static ElfW(Sym) *
adl_elf_lookup(adl_so_info *soInfo, adl_symbol &symbol_name, const version_info *vi) {
    uint32_t hash = symbol_name.elf_hash();

    ADLOGW("SEARCH %s in %s@%p h=%x(elf) %zd",
           symbol_name.name_, soInfo->filename,
           reinterpret_cast<void *>(soInfo->base), hash, hash % soInfo->nbucket_);

    const ElfW(Versym) verneed = adl_find_verdef_version_index(soInfo, vi);
    const ElfW(Versym) *versym = soInfo->versym_;

    for (uint32_t n = soInfo->bucket_[hash % soInfo->nbucket_]; n != 0; n = soInfo->chain_[n]) {
        ElfW(Sym) *s = soInfo->symtab_ + n;

        if (check_symbol_version(versym, n, verneed) &&
            strcmp(soInfo->strtab_ + s->st_name, symbol_name.name_) == 0 &&
            adl_is_symbol_global_and_defined(soInfo, s)) {
            ADLOGI("FOUND %s in %s (%p) %zd",
                   symbol_name.name_, soInfo->filename,
                   reinterpret_cast<void *>(s->st_value),
                   static_cast<size_t>(s->st_size));
            return soInfo->symtab_ + n;
        }
    }

    ADLOGW("NOT FOUND %s in %s@%p %x %zd",
           symbol_name.name_, soInfo->filename,
           reinterpret_cast<void *>(soInfo->base), hash, hash % soInfo->nbucket_);

    return NULL;
}


static const ElfW(Sym) *adlsym_handle_lookup(adl_so_info *soInfo,
                                             adl_symbol &symbol_name,
                                             const adl_version_info *vi) {
    if (adl_prelink_image(soInfo) < 0)
        return NULL;

    return soInfo->is_gnu_hash() ?
           adl_gnu_lookup(soInfo, symbol_name, vi) : adl_elf_lookup(soInfo, symbol_name, vi);
}

bool adl_do_dlsym(void *handle, const char *sym_name, const char *sym_ver, void **symbol) {
    if (NULL == handle || NULL == symbol) return NULL;

    const ElfW(Sym) *sym = NULL;

    adl_so_info *soInfo = (adl_so_info *) handle;

    adl_version_info vi_instance;
    adl_version_info *vi = NULL;

    if (sym_ver != NULL) {
        vi_instance.name = sym_ver;
        vi_instance.elf_hash = calculate_elf_hash(sym_ver);
        vi = &vi_instance;
    }

    adl_symbol adlSymbol;
    adlSymbol.name_ = sym_name;
    sym = adlsym_handle_lookup(soInfo, adlSymbol, vi);
    if (sym != NULL) {
        uint32_t bind = ELF_ST_BIND(sym->st_info);
        uint32_t type = ELF_ST_TYPE(sym->st_info);

        if (/*(bind == STB_GLOBAL || bind == STB_WEAK) &&*/ sym->st_shndx != 0) {
            if (type == STT_TLS) {
                // For a TLS symbol, dlsym returns the address of the current thread's
                // copy of the symbol.
                const adl_tls_segment *tls_module = soInfo->tls_segment;
                if (tls_module == NULL) {
                    ADLOGE("TLS symbol \"%s\" in solib \"%s\" with no TLS segment",
                           sym_name, soInfo->filename);
                    return false;
                }

                //TODO : get tls block
//                void* tls_block = get_tls_block_for_this_thread(tls_module, /*should_alloc=*/true);
//                *symbol = static_cast<char*>(tls_block) + sym->st_value;
                return false;
            } else {
                *symbol = reinterpret_cast<void *>(resolve_symbol_address(soInfo, sym));
            }
            ADLOGW("... dlsym successful: sym_name=\"%s\", sym_ver=\"%s\", found in=\"%s\", address=%p",
                   sym_name, sym_ver, soInfo->filename, *symbol);
            return true;
        }
    }

    return false;
}

void *adlsym(void *handle, const char *symbol) {
    void *result;
    if (!adl_do_dlsym(handle, symbol, NULL, &result)) {
        return NULL;
    }
    return result;
}

void *adlvsym(void *handle, const char *symbol,
              const char *version) {
    void *result;
    if (!adl_do_dlsym(handle, symbol, version, &result)) {
        return NULL;
    }
    return result;
}

int adl_iterate_phdr(int (*callback)(struct dl_phdr_info *info, size_t size, void *args),
                     void *args) {
    if (callback == NULL) return 0;

    uintptr_t it_args[] = {reinterpret_cast<uintptr_t>(callback),
                           reinterpret_cast<uintptr_t>(args)};
    return adl_do_iterate_phdr(adl_iterate_phdr_callback, it_args);
}

void *adlopen(const char *filename, int flag) {
    if (filename == NULL || !adl_file_exists(filename)) {
        ADLOGW("adlopen file not exist");
        return NULL;
    }
    int level = adl_get_api_level();
    if (level >= __ANDROID_API_O_MR1__) {
        adl_so_info *soInfo = adl_find_library(filename);
        if (soInfo != NULL) {
            ADLOGI("elf [%s] is found at : [0x%llx,0x%llx,%d]", soInfo->filename,
                   soInfo->load_bias,
                   soInfo->base, soInfo->phdr->p_vaddr);
            return soInfo;
        } else {
            ADLOGW("elf [%s] NOT found.", filename);
        }
    }
    return NULL;
}

__END_DECLS
