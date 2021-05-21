//
// Created by P7XXTM1-G on 5/20/2021.
//

#include "adl_linker.h"

__BEGIN_DECLS

extern __attribute((weak)) int dl_iterate_phdr(int (*)(struct dl_phdr_info *, size_t, void *), void *);

int do_adl_iterate_phdr(int (*callback)(struct dl_phdr_info *info, size_t size, void *data),
                        void *data) {
    return dl_iterate_phdr(callback, data);
}

__END_DECLS
