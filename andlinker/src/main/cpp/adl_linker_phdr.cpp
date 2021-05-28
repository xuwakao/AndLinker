//
// Created by P7XXTM1-G on 5/28/2021.
//

#include "adl_linker_phdr.h"

/* Return the address and size of the ELF file's .dynamic section in memory,
 * or null if missing.
 *
 * Input:
 *   phdr_table  -> program header table
 *   phdr_count  -> number of entries in tables
 *   load_bias   -> load bias
 * Output:
 *   dynamic       -> address of table in memory (null on failure).
 *   dynamic_flags -> protection flags for section (unset on failure)
 * Return:
 *   void
 */
void adl_phdr_table_get_dynamic_section(const ElfW(Phdr) *phdr_table, size_t phdr_count,
                                        ElfW(Addr) load_bias, ElfW(Dyn) **dynamic,
                                        ElfW(Word) *dynamic_flags) {
    *dynamic = nullptr;
    for (size_t i = 0; i < phdr_count; ++i) {
        const ElfW(Phdr) &phdr = phdr_table[i];
        if (phdr.p_type == PT_DYNAMIC) {
            *dynamic = reinterpret_cast<ElfW(Dyn) *>(load_bias + phdr.p_vaddr);
            if (dynamic_flags) {
                *dynamic_flags = phdr.p_flags;
            }
            return;
        }
    }
}