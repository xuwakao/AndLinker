//
// Internal header shared between andlinker and andhooker
// NOT part of the public API
//

#ifndef ANDLINKER_ADL_INTERNAL_H
#define ANDLINKER_ADL_INTERNAL_H

#include <sys/cdefs.h>
#include <link.h>
#include "adl_util.h"
#include "adl_elf_reader.h"

__BEGIN_DECLS

typedef struct {
    size_t size = 0;
    size_t alignment = 1;
    const void *init_ptr = "";
    size_t init_size = 0;
} adl_tls_segment;

typedef struct so_info {
    const char *filename;
    ElfW(Addr) base;//mmap load start
    const ElfW(Phdr) *phdr;
    ElfW(Half) phnum;
    uint32_t flags_;

    struct so_info *next;
    void *dlopen_handle;
    void *elf_reader;

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

    ElfW(Addr) load_bias;

#if !defined(__LP64__)
    bool has_text_relocations;
#endif
    bool has_DT_SYMBOLIC;

    adl_tls_segment *tls_segment;
    size_t tls_module_id;

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

    bool is_gnu_hash(void) const;

    ElfW(Addr) get_verneed_ptr(void) const;
    size_t get_verneed_cnt(void) const;
    ElfW(Addr) get_verdef_ptr(void) const;
    size_t get_verdef_cnt(void) const;
    const char *get_string(ElfW(Word) index) const;
} adl_so_info;

// Internal function — exported for andhooker module
int adl_prelink_image(adl_so_info *soInfo);

__END_DECLS

#endif //ANDLINKER_ADL_INTERNAL_H
