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

/**
 * >= android 9.0 (P) LINKER_DLOPEN_P
 * >= android 8.0 (O) LINKER_DLOPEN_ANDROID_DLOPEN_O
 * >= android 7.0 (N) LINKER_DLOPEN_ANDROID_DLOPEN_N
 * < android 7 use dlopen directly
 */
//
#define LINKER_DLOPEN_P "__loader_dlopen"
//>= android 8.0 (O)
#define LINKER_DLOPEN_O "__dl__Z8__dlopenPKciPKv"
#define LINKER_DLOPEN_ANDROID_DLOPEN_O "__dl__Z20__android_dlopen_extPKciPK17android_dlextinfoPKv"
#define LINKER_DLOPEN_EXT_O "__dl__Z9do_dlopenPKciPK17android_dlextinfoPKv"
//>= android 7.0 (N)
#define LINKER_DLOPEN_N"__dl_dlopen"
#define LINKER_DLOPEN_ANDROID_DLOPEN_N "__dl_android_dlopen_ext"
#define LINKER_DLOPEN_EXT_N "__dl__Z9do_dlopenPKciPK17android_dlextinfoPv"


static bool adl_loader_initialized = false;
static const void *FAKE_CALLER_ADDR = (const void *) getc;

typedef void *(*adl_loader_dlopen_t)(const char *filename,
                                     int flags, const void *caller_addr);
static adl_loader_dlopen_t adl_loader_dlopen = NULL;

typedef void *(*adl_android_dlopen_ext_O_t)(const char *filename,
                                            int flags,
                                            const void *extinfo,
                                            const void *caller_addr);
static adl_android_dlopen_ext_O_t adl_android_dlopen_O_ext = NULL;

typedef void *(*adl_android_dlopen_ext_N_t)(const char *filename,
                                            int flags,
                                            const void *extinfo);
static adl_android_dlopen_ext_N_t adl_android_dlopen_N_ext = NULL;

static void *adl_dlopen_compat = NULL;

static void adl_loader_init(void) {
    if (adl_loader_initialized) return;
    adl_loader_initialized = true;

    ADLOGW("adl_loader_init.");
    void *handle = adlopen(LINKER_PATHNAME, 0);
    if (handle == NULL) {
        ADLOGW("Linker [%s] NOT found.", LINKER_PATHNAME);
        return;
    }

    int level = adl_get_api_level();
    if (level >= __ANDROID_API_P__) {
        adl_loader_dlopen = (adl_loader_dlopen_t)
                adlsym(handle, LINKER_DLOPEN_P);
        adl_dlopen_compat = reinterpret_cast<void *>(adl_loader_dlopen);
    } else if (level >= __ANDROID_API_O__) {
        adl_android_dlopen_O_ext = (adl_android_dlopen_ext_O_t)
                adlsym(handle, LINKER_DLOPEN_ANDROID_DLOPEN_O);
        adl_dlopen_compat = reinterpret_cast<void *>(adl_android_dlopen_O_ext);
    } else if (level >= __ANDROID_API_N__) {
        adl_android_dlopen_N_ext = (adl_android_dlopen_ext_N_t)
                adlsym(handle, LINKER_DLOPEN_ANDROID_DLOPEN_N);
        adl_dlopen_compat = reinterpret_cast<void *>(adl_android_dlopen_N_ext);
    } else {
        adl_dlopen_compat = reinterpret_cast<void *>(dlopen);
    }

    ADLOGI("dlopen(api=%d) handle(%p) found, dlopen(%p)",
           level, handle, adl_dlopen_compat);
    adlclose(handle);
}

void *adl_load(const char *filename) {
    int level = adl_get_api_level();
    //< android 7.0
    if (level < __ANDROID_API_N__) {
        return dlopen(filename, RTLD_NOW);
    } else {
        adl_loader_init();
        if (level >= __ANDROID_API_P__ && adl_loader_dlopen) {
            return adl_loader_dlopen(filename, RTLD_NOW, FAKE_CALLER_ADDR);
        } else if (level >= __ANDROID_API_O__ && adl_android_dlopen_O_ext) {
            return adl_android_dlopen_O_ext(filename, RTLD_NOW, NULL, FAKE_CALLER_ADDR);
        } else if (level >= __ANDROID_API_N__ && adl_android_dlopen_N_ext) {
            return adl_android_dlopen_N_ext(filename, RTLD_NOW, NULL);
        } else {
            ADLOGW("dlopen function is NULL");
        }
    }
    return NULL;
}

__END_DECLS