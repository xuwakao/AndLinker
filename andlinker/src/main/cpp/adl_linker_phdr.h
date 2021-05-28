//
// Created by P7XXTM1-G on 5/28/2021.
//

#ifndef ANDLINKER_ADL_LINKER_PHDR_H
#define ANDLINKER_ADL_LINKER_PHDR_H


#include <sys/cdefs.h>
#include <link.h>

__BEGIN_DECLS

void adl_phdr_table_get_dynamic_section(const ElfW(Phdr)* phdr_table, size_t phdr_count,
        ElfW(Addr) load_bias, ElfW(Dyn)** dynamic, ElfW(Word)* dynamic_flags);

__END_DECLS


#endif //ANDLINKER_ADL_LINKER_PHDR_H
