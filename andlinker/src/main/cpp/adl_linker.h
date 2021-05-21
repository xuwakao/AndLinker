//
// Created by P7XXTM1-G on 5/20/2021.
//

#ifndef ANDLINKER_ADL_LINKER_H
#define ANDLINKER_ADL_LINKER_H

#include <sys/cdefs.h>
#include <stdint.h>

__BEGIN_DECLS

int do_adl_iterate_phdr(int (*__callback)(struct dl_phdr_info*, size_t, void*), void* __data);

__END_DECLS

#endif //ANDLINKER_ADL_LINKER_H
