#include <jni.h>
#include <string>
#include <android/log.h>
#include <unistd.h>

#include "adl.h"

// log
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#define LOG(fmt, ...) __android_log_print(ANDROID_LOG_INFO, "adl_sample", fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, "adl_sample", fmt, ##__VA_ARGS__)
#pragma clang diagnostic pop

#define LOG_BEGIN(TAG) LOG("*** %s", (const char*)TAG)
#define LOG_BEGIN_FMT(fmt, ...) LOG(fmt, ##__VA_ARGS__)
#define LOG_END LOG("*** -----------------------------------------")


#define BASENAME_LIBC     "libc.so"
#define BASENAME_LIBCPP   "libc++.so"

#if defined(__LP64__)
#define BASENAME_LINKER   "linker64"
#define PATHNAME_LIBCPP   "/system/lib64/libc++.so"
#define PATHNAME_LIBCURL      "/system/lib64/libcurl.so"
#else
#define BASENAME_LINKER   "linker"
#define PATHNAME_LIBCPP   "/system/lib/libc++.so"
#define PATHNAME_LIBCURL      "/system/lib/libcurl.so"
#endif

static int callback(struct dl_phdr_info *info, size_t size, void *arg) {
    return 0;
}

static void adl_test_iterate(void) {
    LOG_BEGIN("adl_test_iterate");
    adl_iterate_phdr(callback, NULL);
    LOG_END;
    usleep(100 * 1000);
}

static void *
adl_test_dlsym(const char *filename, const char *symbol, bool open_lib) {
    if (open_lib) {
        void *handle = dlopen(filename, RTLD_NOW);
        LOG("--- dlopen(%s) : handle %p", filename, (uintptr_t) handle);
        if (NULL != handle)
            dlclose(handle);
    }

    LOG_BEGIN("adl_test_dlsym");

    // adlopen
    void *handle = adlopen(filename, 0);
    if (handle)
        LOG(">>> adlopen(%s) : handle %p", filename, (uintptr_t) handle);
    else
        LOGE("xxx adlopen(%s) failed", filename);

    // adlsym
    void *symbol_addr = adlsym(handle, symbol);
    if (symbol_addr)
        LOG(">>> adlsym(%s) : addr %p", symbol, (uintptr_t) symbol_addr);
    else
        LOGE("xxx adlsym(%s) not found", symbol);

    // adladdr
    Dl_info info;
    if (0 != adladdr(symbol_addr, &info)) {
        if (0 == info.dli_saddr) {
            LOGE("xxx adladdr(%p) not found: %p, %s", (uintptr_t) symbol_addr,
                 (uintptr_t) info.dli_fbase, info.dli_fname);
        } else {
            LOG(">>> adladdr(%p) : %p, %s, %p %s", (uintptr_t) symbol_addr,
                (uintptr_t) info.dli_fbase, info.dli_fname,
                (uintptr_t) info.dli_saddr, info.dli_sname);
        }
    } else
        LOGE("xxx adladdr(%p) failed ", (uintptr_t) symbol_addr);


    LOG_END;

    return handle;
}

static void adl_test(JNIEnv *env, jobject thiz) {
    (void) env;
    (void) thiz;

    adl_test_iterate();

    // linker
    //inner symbol
    adl_test_dlsym(BASENAME_LINKER, "__dl__Z14get_libdl_infoRK6soinfo", false);
    //export symbol
    adl_test_dlsym(BASENAME_LINKER, "__loader_android_get_LD_LIBRARY_PATH", false);

    // libc.so
    //inner symbol
    adl_test_dlsym(BASENAME_LIBC, "__openat", false);
    //export symbol
    adl_test_dlsym(BASENAME_LIBC, "gettimeofday", false);

    // libc++.so
    adl_test_dlsym(BASENAME_LIBCPP, "_ZNSt3__18valarrayImEC2Em", false);
    adl_test_dlsym(PATHNAME_LIBCPP, "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE3putEc", false);

    //load elf file
    void *handle = adl_test_dlsym(PATHNAME_LIBCURL, "Curl_open", true);
    if (handle != NULL) {
        adlclose(handle);
    }
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_owttwo_andlinker_sample_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject thiz) {
    std::string hello = "ADL C++";
    adl_test(env, thiz);
    return env->NewStringUTF(hello.c_str());
}
