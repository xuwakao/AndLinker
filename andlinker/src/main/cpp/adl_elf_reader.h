//
// Created by P7XXTM1-G on 6/9/2021.
//

#ifndef ANDLINKER_ADL_ELF_READER_H
#define ANDLINKER_ADL_ELF_READER_H


#include <sys/cdefs.h>
#include <unistd.h>
#include <link.h>

__BEGIN_DECLS

typedef struct map_file_fragment {
    void *map_start_;
    size_t map_size_;
    void *data_;
    size_t size_;

    bool map(int fd, size_t file_sz, off64_t base_offset,
             size_t elf_offset, size_t size);

    void unmap(void) const;
} adl_map_file_fragment;

typedef struct elf_reader {
    const char *name_;
    const char *real_path_;
    int fd_;
    off64_t file_offset_;
    off64_t file_size_;

    const ElfW(Ehdr) *header_;
    size_t phdr_num_;

    const ElfW(Dyn) *dynamic_;

    adl_map_file_fragment *phdr_fragment_;
    const ElfW(Phdr) *phdr_table_;

    adl_map_file_fragment *shdr_fragment_;
    const ElfW(Shdr) *shdr_table_;
    size_t shdr_num_;

    adl_map_file_fragment *shstrtab_fragment_;
    const char *shstrtab_;
    size_t shstrtab_size_;

    adl_map_file_fragment *symtab_fragment_;
    const ElfW(Sym) *symtab_;
    size_t symtab_num_;

    adl_map_file_fragment *strtab_fragment_;
    const char *strtab_;
    size_t strtab_size_;

    bool openFile(void);

    bool read_elf_header(bool force);

    bool verify_elf_header(void);

    bool read_program_headers(void);

    bool read_section_headers(void);

    bool read_other_section(void);

    bool check_file_range(ElfW(Addr) offset, size_t size, size_t alignment) const;

    void recycle(void);
} adl_elf_reader;

__END_DECLS


#endif //ANDLINKER_ADL_ELF_READER_H
