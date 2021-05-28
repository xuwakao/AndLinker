//
// Created by P7XXTM1-G on 5/20/2021.
//

#ifndef ANDLINKER_ADL_LINKER_H
#define ANDLINKER_ADL_LINKER_H

#include <sys/cdefs.h>
#include <stdint.h>
#include "adl.h"

__BEGIN_DECLS

int adl_do_iterate_phdr(adl_iterate_phdr_cb callback, void *__data);

__END_DECLS

#endif //ANDLINKER_ADL_LINKER_H
