//
// Created by P7XXTM1-G on 5/19/2021.
//

#ifndef ANDLINKER_ADL_H
#define ANDLINKER_ADL_H

#include <link.h>
#include <dlfcn.h>
#include <stdint.h>

/**
 * adl.h define exported APIs that are similar to those defined in <dlfcn.h> and <link.h>
 */
__BEGIN_DECLS

//dlfcn.h
void *adlopen(const char *__filename, int __flag);

int adlclose(void *__handle);

char *adlerror(void);

void *adlsym(void *__handle, const char *__symbol);

void *adlvsym(void *__handle,
              const char *__symbol,
              const char *__version) __INTRODUCED_IN(24);

int adladdr(const void *__addr, Dl_info *__info);

//link.h
typedef int (*adl_iterate_phdr_cb)(struct dl_phdr_info *info, size_t size, void *arg);
int adl_iterate_phdr(int (*__callback)(struct dl_phdr_info *, size_t, void *), void *__data);

__END_DECLS

#endif //ANDLINKER_ADL_H
