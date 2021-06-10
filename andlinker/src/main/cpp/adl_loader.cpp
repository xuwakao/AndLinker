//
// Created by P7XXTM1-G on 6/8/2021.
//

#include <cstdio>
#include <adl.h>
#include "adl_loader.h"
#include "adl_util.h"

__BEGIN_DECLS

#ifndef __LP64__
#define LINKER_PATHNAME "/system/bin/linker"
#else
#define LINKER_PATHNAME "/system/bin/linker64"
#endif

#define LINKER_DLOPEN "__loader_dlopen"

static bool adl_loader_initialized = false;
static const void *FAKE_CALLER_ADDR = (const void *) getc;

typedef void *(*adl_loader_dlopen_t)(const char *filename,
                                     int flags, const void *caller_addr);
static adl_loader_dlopen_t adl_loader_dlopen = NULL;

static void adl_loader_init(void) {
    if (adl_loader_initialized) return;
    adl_loader_initialized = true;

    int level = adl_get_api_level();
    void *handle = adlopen(LINKER_PATHNAME, 0);
    if (level >= __ANDROID_API_O_MR1__) {
        if (handle == NULL) {
            ADLOGW("Linker [%s] NOT found.", LINKER_PATHNAME);
            return;
        }
        ADLOGW("Linker handle(%p) found", handle);
        adl_loader_dlopen = (adl_loader_dlopen_t) adlsym(handle, LINKER_DLOPEN);
    }
    adlclose(handle);
}

void *adl_load(const char *filename) {
    int level = adl_get_api_level();
    if (level <= __ANDROID_API_M__) {
        return dlopen(filename, RTLD_NOW);
    } else {
        adl_loader_init();
        if (level >= __ANDROID_API_O_MR1__) {
            if (adl_loader_dlopen)
                return adl_loader_dlopen(filename, RTLD_NOW, FAKE_CALLER_ADDR);
        } else {
            //TODO should not ues dlopen
            return dlopen(filename, RTLD_NOW);
        }
    }

    return NULL;
}

__END_DECLS