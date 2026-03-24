#include <jni.h>
#include <string>
#include <android/log.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <fcntl.h>

#include "adl.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#define LOG(fmt, ...) __android_log_print(ANDROID_LOG_INFO, "adl_sample", fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, "adl_sample", fmt, ##__VA_ARGS__)
#pragma clang diagnostic pop

#define BASENAME_LIBC     "libc.so"
#define BASENAME_LIBCPP   "libc++.so"

#if defined(__LP64__)
#define BASENAME_LINKER   "linker64"
#define PATHNAME_LIBCPP   "/system/lib64/libc++.so"
#define PATHNAME_LIBCURL  "/system/lib64/libcurl.so"
#else
#define BASENAME_LINKER   "linker"
#define PATHNAME_LIBCPP   "/system/lib/libc++.so"
#define PATHNAME_LIBCURL  "/system/lib/libcurl.so"
#endif

static std::string g_result;

static void result_pass(const char *fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    LOG("[PASS] %s", buf);
    g_result += "[PASS] ";
    g_result += buf;
    g_result += "\n";
}

static void result_fail(const char *fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    LOGE("[FAIL] %s", buf);
    g_result += "[FAIL] ";
    g_result += buf;
    g_result += "\n";
}

static void result_info(const char *fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    LOG("  %s", buf);
    g_result += "  ";
    g_result += buf;
    g_result += "\n";
}

static int iterate_callback(struct dl_phdr_info *info, size_t size, void *arg) {
    (void) size;
    int *count = static_cast<int *>(arg);
    (*count)++;
    return 0;
}

// Helper: read first 4 bytes at address to verify it's readable
static void verify_readable(void *addr, const char *name) {
    uint8_t *p = static_cast<uint8_t *>(addr);
    result_info("verify: %s bytes=[%02x %02x %02x %02x]",
                name, p[0], p[1], p[2], p[3]);
}

// Open + sym + adladdr, returns symbol address (caller must adlclose handle)
static void *resolve_sym(const char *filename, const char *symbol,
                         void **out_handle, bool pre_dlopen,
                         void **out_pre_handle = NULL) {
    if (out_pre_handle) *out_pre_handle = NULL;
    if (pre_dlopen) {
        void *h = dlopen(filename, RTLD_NOW);
        if (out_pre_handle) *out_pre_handle = h;
    }

    void *handle = adlopen(filename, 0);
    if (handle == NULL) {
        result_fail("adlopen(%s)", filename);
        *out_handle = NULL;
        return NULL;
    }
    result_pass("adlopen(%s)", filename);
    *out_handle = handle;

    void *addr = adlsym(handle, symbol);
    if (addr != NULL) {
        result_pass("adlsym(%s) -> %p", symbol, addr);
    } else {
        result_fail("adlsym(%s)", symbol);
        return NULL;
    }

    Dl_info info;
    if (adladdr(addr, &info) != 0 && info.dli_saddr != NULL) {
        result_pass("adladdr(%s) -> %s in %s", symbol, info.dli_sname, info.dli_fname);
    } else {
        result_fail("adladdr(%s)", symbol);
    }

    return addr;
}

static void adl_test() {
    g_result.clear();

    int api = android_get_device_api_level();
    char header[128];
    snprintf(header, sizeof(header),
             "=== AndLinker Test (API %d, %s) ===\n\n",
             api,
#if defined(__LP64__)
             "64-bit"
#else
             "32-bit"
#endif
    );
    g_result += header;

    void *handle = NULL;
    void *addr = NULL;

    // 1. iterate test
    g_result += "--- adl_iterate_phdr ---\n";
    {
        int count = 0;
        adl_iterate_phdr(iterate_callback, &count);
        if (count > 0)
            result_pass("adl_iterate_phdr -> %d libraries", count);
        else
            result_fail("adl_iterate_phdr -> 0 libraries");
    }

    // 2. linker: __loader_android_get_LD_LIBRARY_PATH
    g_result += "\n--- linker: get_LD_LIBRARY_PATH ---\n";
    addr = resolve_sym(BASENAME_LINKER, "__loader_android_get_LD_LIBRARY_PATH", &handle, false);
    if (addr != NULL) {
        typedef void (*get_ld_path_t)(char *, size_t);
        get_ld_path_t fn = reinterpret_cast<get_ld_path_t>(addr);
        char path_buf[512] = {0};
        fn(path_buf, sizeof(path_buf));
        if (path_buf[0] != '\0')
            result_pass("call -> LD_LIBRARY_PATH=\"%s\"", path_buf);
        else
            result_pass("call -> LD_LIBRARY_PATH=(empty)");
    }
    if (handle) adlclose(handle);

    // 3. linker: internal symbol (API 30+)
    if (api >= 30) {
        g_result += "\n--- linker: get_libdl_info (API 30+) ---\n";
        addr = resolve_sym(BASENAME_LINKER, "__dl__Z14get_libdl_infoRK6soinfo", &handle, false);
        if (addr != NULL) {
            verify_readable(addr, "__dl__Z14get_libdl_infoRK6soinfo");
        }
        if (handle) adlclose(handle);
    }

    // 4. libc: __openat (internal)
    g_result += "\n--- libc: __openat ---\n";
    addr = resolve_sym(BASENAME_LIBC, "__openat", &handle, false);
    if (addr != NULL) {
        typedef int (*openat_t)(int, const char *, int, ...);
        openat_t fn = reinterpret_cast<openat_t>(addr);
        int fd = fn(AT_FDCWD, "/proc/self/maps", O_RDONLY);
        if (fd >= 0) {
            char buf[64] = {0};
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            close(fd);
            result_pass("call -> openat(/proc/self/maps) fd=%d, read %zd bytes", fd, n);
        } else {
            result_fail("call -> openat(/proc/self/maps) failed errno=%d", errno);
        }
    }
    if (handle) adlclose(handle);

    // 5. libc: gettimeofday (export)
    g_result += "\n--- libc: gettimeofday ---\n";
    addr = resolve_sym(BASENAME_LIBC, "gettimeofday", &handle, false);
    if (addr != NULL) {
        typedef int (*gettimeofday_t)(struct timeval *, struct timezone *);
        gettimeofday_t fn = reinterpret_cast<gettimeofday_t>(addr);
        struct timeval tv;
        int ret = fn(&tv, NULL);
        if (ret == 0) {
            struct tm *tm_info = localtime(reinterpret_cast<const time_t *>(&tv));
            char time_buf[64];
            strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
            result_pass("call -> gettimeofday() = %s", time_buf);
        } else {
            result_fail("call -> gettimeofday() ret=%d", ret);
        }
    }
    if (handle) adlclose(handle);

    // 6. libc++: valarray constructor
    g_result += "\n--- libc++: valarray<size_t> ctor ---\n";
    addr = resolve_sym(BASENAME_LIBCPP, "_ZNSt3__18valarrayImEC2Em", &handle, false);
    if (addr != NULL) {
        verify_readable(addr, "valarray::valarray(size_t)");
    }
    if (handle) adlclose(handle);

    // 7. libc++: ostream::put
    g_result += "\n--- libc++: ostream::put ---\n";
    addr = resolve_sym(PATHNAME_LIBCPP, "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE3putEc",
                        &handle, false);
    if (addr != NULL) {
        verify_readable(addr, "ostream::put(char)");
    }
    if (handle) adlclose(handle);

    // 8. libcurl: Curl_open (keep loaded to stabilize address across runs)
    g_result += "\n--- libcurl: Curl_open ---\n";
    {
        static void *curl_dl_handle = NULL;
        if (curl_dl_handle == NULL) {
            curl_dl_handle = dlopen(PATHNAME_LIBCURL, RTLD_NOW);
        }
        addr = resolve_sym(PATHNAME_LIBCURL, "Curl_open", &handle, false);
        if (addr != NULL) {
            verify_readable(addr, "Curl_open");
        }
        // don't adlclose — keep handle alive so address stays stable
    }

    // summary
    int pass = 0, fail = 0;
    size_t pos = 0;
    while ((pos = g_result.find("[PASS]", pos)) != std::string::npos) { pass++; pos++; }
    pos = 0;
    while ((pos = g_result.find("[FAIL]", pos)) != std::string::npos) { fail++; pos++; }
    char summary[128];
    snprintf(summary, sizeof(summary), "\n=== %d passed, %d failed ===\n", pass, fail);
    g_result += summary;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_owttwo_andlinker_sample_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject thiz) {
    (void) thiz;
    adl_test();
    return env->NewStringUTF(g_result.c_str());
}
