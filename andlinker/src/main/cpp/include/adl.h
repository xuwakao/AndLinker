//
// Created by P7XXTM1-G on 5/19/2021.
//

#ifndef ANDLINKER_ADL_H
#define ANDLINKER_ADL_H

#include <link.h>
#include <dlfcn.h>
#include <unistd.h>

/**
 * adl.h define exported APIs that are similar to those defined in <dlfcn.h> and <link.h>
 */
__BEGIN_DECLS

//dlfcn.h
void *adlopen(const char *__filename, int __flag);

int adlclose(void *__handle);

void *adlsym(void *__handle, const char *__symbol);

void *adlvsym(void *__handle,
              const char *__symbol,
              const char *__version);

int adladdr(const void *__addr, Dl_info *__info);

const char *adlerror(void);

//link.h
//https://android.googlesource.com/platform/bionic/+/master/docs/status.md
int adl_iterate_phdr(int (*__callback)(dl_phdr_info *, size_t, void *), void *__data);

// symbol enumeration
// callback returns 0 to continue, non-zero to stop
typedef int (*adl_symbol_callback)(const char *__name, void *__addr,
                                    size_t __size, int __type, void *__arg);
int adl_enum_symbols(void *__handle, adl_symbol_callback __callback, void *__arg);

// fuzzy symbol lookup: exact match first, then substring match
// callback is called for each substring match; return non-zero to select it
// if callback is NULL, returns the first substring match
void *adlsym_match(void *__handle, const char *__pattern,
                   adl_symbol_callback __callback, void *__arg);

__END_DECLS

#endif //ANDLINKER_ADL_H
