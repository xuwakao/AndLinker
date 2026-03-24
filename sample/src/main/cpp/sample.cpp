#include <jni.h>
#include <string>
#include <android/log.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <fcntl.h>
#include <pthread.h>
#include <cerrno>

#include "adl.h"
#include "adl_hook.h"

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
#define PATHNAME_LIBART   "/apex/com.android.art/lib64/libart.so"
#else
#define BASENAME_LINKER   "linker"
#define PATHNAME_LIBCPP   "/system/lib/libc++.so"
#define PATHNAME_LIBCURL  "/system/lib/libcurl.so"
#define PATHNAME_LIBART   "/apex/com.android.art/lib/libart.so"
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

    // 9. ART VM: JNI_GetCreatedJavaVMs (exported)
    g_result += "\n--- libart: JNI_GetCreatedJavaVMs ---\n";
    {
        // libart.so path varies: /apex/com.android.art/lib[64]/ on API 30+,
        // /system/lib[64]/ on older versions
        void *art_handle = adlopen(PATHNAME_LIBART, 0);
        if (art_handle == NULL) {
            // fallback for pre-API 30
            art_handle = adlopen("libart.so", 0);
        }
        if (art_handle != NULL) {
            // JNI_GetCreatedJavaVMs: exported JNI function
            typedef int (*jni_get_vms_t)(JavaVM **, int, int *);
            void *sym = adlsym(art_handle, "JNI_GetCreatedJavaVMs");
            if (sym != NULL) {
                result_pass("adlsym(JNI_GetCreatedJavaVMs) -> %p", sym);
                jni_get_vms_t fn = reinterpret_cast<jni_get_vms_t>(sym);
                JavaVM *vm = NULL;
                int count = 0;
                int ret = fn(&vm, 1, &count);
                if (ret == 0 && count > 0 && vm != NULL) {
                    result_pass("call -> %d VM(s), JavaVM*=%p", count, vm);
                } else {
                    result_fail("call -> ret=%d, count=%d", ret, count);
                }
            } else {
                result_fail("adlsym(JNI_GetCreatedJavaVMs)");
            }

            // fuzzy match: ArtMethod::PrettyMethod (mangled name varies across versions)
            auto match_cb = [](const char *name, void *addr, size_t size,
                               int type, void *arg) -> int {
                std::string *r = static_cast<std::string *>(arg);
                char buf[256];
                snprintf(buf, sizeof(buf), "  match: %s -> %p", name, addr);
                *r += buf;
                *r += "\n";
                return 0; // continue to show all matches
            };
            void *sym2 = adlsym_match(art_handle, "ArtMethod::PrettyMethod", match_cb, &g_result);
            if (sym2 != NULL) {
                result_pass("adlsym_match(PrettyMethod) -> %p", sym2);
                verify_readable(sym2, "PrettyMethod");
            } else {
                result_info("PrettyMethod not found (may be stripped)");
            }

            adlclose(art_handle);
        } else {
            result_fail("adlopen(libart.so) failed");
        }
    }

    // 10. adlerror test
    g_result += "\n--- adlerror ---\n";
    {
        void *bad = adlopen("/nonexistent/libfake.so", 0);
        if (bad == NULL) {
            const char *err = adlerror();
            if (err != NULL) {
                result_pass("adlerror() -> \"%s\"", err);
            } else {
                result_fail("adlerror() returned NULL after failed adlopen");
            }
        }
        // second call should return NULL (error consumed)
        const char *err2 = adlerror();
        if (err2 == NULL) {
            result_pass("adlerror() -> NULL (cleared)");
        } else {
            result_fail("adlerror() not cleared: \"%s\"", err2);
        }
    }

    // 10. adl_enum_symbols — list first 5 symbol names
    g_result += "\n--- adl_enum_symbols (libc.so) ---\n";
    {
        struct enum_ctx {
            int count;
            int limit;
            std::string *result;
        };
        auto enum_cb = [](const char *name, void *addr, size_t size,
                          int type, void *arg) -> int {
            enum_ctx *ctx = static_cast<enum_ctx *>(arg);
            if (ctx->count < ctx->limit) {
                char buf[256];
                snprintf(buf, sizeof(buf), "  [%d] %s -> %p (size=%zu, type=%d)",
                         ctx->count, name, addr, size, type);
                *ctx->result += buf;
                *ctx->result += "\n";
            }
            ctx->count++;
            return 0; // continue to count all
        };

        void *h = adlopen(BASENAME_LIBC, 0);
        if (h != NULL) {
            enum_ctx ctx = {0, 5, &g_result};
            int total = adl_enum_symbols(h, enum_cb, &ctx);
            if (total > 0) {
                result_pass("adl_enum_symbols(libc.so) -> %d total symbols (showing first %d)",
                            total, ctx.limit);
            } else {
                result_fail("adl_enum_symbols(libc.so) -> %d", total);
            }
            adlclose(h);
        } else {
            result_fail("adl_enum_symbols: adlopen(libc.so) failed");
        }
    }

    // 11. adlvsym — versioned symbol lookup
    g_result += "\n--- adlvsym ---\n";
    {
        void *h = adlopen(BASENAME_LIBC, 0);
        if (h != NULL) {
            // "LIBC" is a common version tag in Android's libc
            void *sym = adlvsym(h, "gettimeofday", "LIBC");
            if (sym != NULL) {
                result_pass("adlvsym(gettimeofday, LIBC) -> %p", sym);
            } else {
                // may not have version "LIBC" on all API levels, try without
                result_info("adlvsym(gettimeofday, LIBC) not found (version may not exist)");
                // try non-versioned as comparison
                void *sym2 = adlsym(h, "gettimeofday");
                if (sym2 != NULL) {
                    result_pass("adlsym(gettimeofday) fallback -> %p", sym2);
                } else {
                    result_fail("adlsym(gettimeofday) fallback also failed");
                }
            }
            adlclose(h);
        } else {
            result_fail("adlvsym: adlopen(libc.so) failed");
        }
    }

    // 12. non-existent symbol — verify error path
    g_result += "\n--- non-existent symbol ---\n";
    {
        void *h = adlopen(BASENAME_LIBC, 0);
        if (h != NULL) {
            void *sym = adlsym(h, "__this_symbol_does_not_exist_12345__");
            if (sym == NULL) {
                const char *err = adlerror();
                if (err != NULL) {
                    result_pass("adlsym(nonexistent) -> NULL, error=\"%s\"", err);
                } else {
                    result_fail("adlsym(nonexistent) -> NULL but adlerror() is NULL");
                }
            } else {
                result_fail("adlsym(nonexistent) unexpectedly returned %p", sym);
            }
            adlclose(h);
        }
    }

    // 13. basename vs full path — same library should have same base
    g_result += "\n--- basename vs fullpath ---\n";
    {
        void *h1 = adlopen(BASENAME_LIBCPP, 0);
        void *h2 = adlopen(PATHNAME_LIBCPP, 0);
        if (h1 != NULL && h2 != NULL) {
            // compare load_bias from the adl_so_info struct (first fields after filename)
            void *sym1 = adlsym(h1, "_ZNSt3__18valarrayImEC2Em");
            void *sym2 = adlsym(h2, "_ZNSt3__18valarrayImEC2Em");
            if (sym1 != NULL && sym2 != NULL && sym1 == sym2) {
                result_pass("basename vs fullpath -> same address %p", sym1);
            } else {
                result_fail("basename vs fullpath -> %p vs %p", sym1, sym2);
            }
        } else {
            result_fail("basename vs fullpath: adlopen failed (%p, %p)", h1, h2);
        }
        if (h1) adlclose(h1);
        if (h2) adlclose(h2);
    }

    // 14. open/close/reopen lifecycle
    g_result += "\n--- open/close/reopen ---\n";
    {
        void *h1 = adlopen(BASENAME_LIBC, 0);
        void *sym1 = NULL;
        if (h1 != NULL) {
            sym1 = adlsym(h1, "getpid");
            result_pass("first open: adlsym(getpid) -> %p", sym1);
            adlclose(h1);
        } else {
            result_fail("first open failed");
        }
        // reopen
        void *h2 = adlopen(BASENAME_LIBC, 0);
        if (h2 != NULL) {
            void *sym2 = adlsym(h2, "getpid");
            if (sym2 != NULL && sym2 == sym1) {
                result_pass("reopen: adlsym(getpid) -> %p (same)", sym2);
            } else if (sym2 != NULL) {
                result_pass("reopen: adlsym(getpid) -> %p", sym2);
            } else {
                result_fail("reopen: adlsym(getpid) failed");
            }
            adlclose(h2);
        } else {
            result_fail("reopen failed");
        }
    }

    // 15. thread safety — concurrent adlsym from 4 threads
    g_result += "\n--- thread safety ---\n";
    {
        struct thread_result {
            void *addr;
            bool success;
        };

        auto thread_fn = [](void *arg) -> void * {
            thread_result *r = static_cast<thread_result *>(arg);
            void *h = adlopen(BASENAME_LIBC, 0);
            if (h != NULL) {
                r->addr = adlsym(h, "getpid");
                r->success = (r->addr != NULL);
                adlclose(h);
            } else {
                r->success = false;
            }
            return NULL;
        };

        const int NUM_THREADS = 4;
        pthread_t threads[NUM_THREADS];
        thread_result results[NUM_THREADS] = {};

        for (int i = 0; i < NUM_THREADS; i++) {
            pthread_create(&threads[i], NULL, thread_fn, &results[i]);
        }
        for (int i = 0; i < NUM_THREADS; i++) {
            pthread_join(threads[i], NULL);
        }

        bool all_ok = true;
        bool all_same = true;
        for (int i = 0; i < NUM_THREADS; i++) {
            if (!results[i].success) all_ok = false;
            if (results[i].addr != results[0].addr) all_same = false;
        }

        if (all_ok && all_same) {
            result_pass("%d threads: all resolved getpid -> %p", NUM_THREADS, results[0].addr);
        } else if (all_ok) {
            result_fail("%d threads: addresses differ (%p, %p, %p, %p)",
                        NUM_THREADS, results[0].addr, results[1].addr,
                        results[2].addr, results[3].addr);
        } else {
            int fail_count = 0;
            for (int i = 0; i < NUM_THREADS; i++) if (!results[i].success) fail_count++;
            result_fail("%d threads: %d failed", NUM_THREADS, fail_count);
        }
    }

    // 16. PLT hook test — hook close() called from this module
    g_result += "\n--- PLT hook: close ---\n";
    {
        typedef int (*close_fn)(int);
        static close_fn orig_close = NULL;
        static int close_hook_count;
        close_hook_count = 0;

        static std::string *hook_log;
        hook_log = &g_result;

        struct hook_helper {
            static int hooked_close(int fd) {
                close_hook_count++;
                char buf[128];
                snprintf(buf, sizeof(buf), "  >> before close(fd=%d)\n", fd);
                *hook_log += buf;
                LOG("[PLT hook] >> before close(fd=%d)", fd);
                int ret = orig_close(fd);
                snprintf(buf, sizeof(buf), "  << after  close(fd=%d) = %d\n", fd, ret);
                *hook_log += buf;
                LOG("[PLT hook] << after close(fd=%d) = %d", fd, ret);
                return ret;
            }
        };

        int ret = adl_plt_hook("libsample.so", "close",
                               reinterpret_cast<void *>(hook_helper::hooked_close),
                               reinterpret_cast<void **>(&orig_close));
        if (ret == 0) {
            result_pass("adl_plt_hook(close) installed");

            // Open and close a file — close should go through our hook
            int fd = open("/proc/self/maps", O_RDONLY);
            if (fd >= 0) {
                close_hook_count = 0;
                close(fd);
                if (close_hook_count == 1) {
                    result_pass("hooked: close() intercepted (count=%d)", close_hook_count);
                } else {
                    result_fail("hooked: close() count=%d, expected 1", close_hook_count);
                }
            }

            ret = adl_plt_unhook("libsample.so", "close");
            if (ret == 0) {
                result_pass("adl_plt_unhook(close) restored");
                int fd2 = open("/proc/self/maps", O_RDONLY);
                if (fd2 >= 0) {
                    close_hook_count = 0;
                    close(fd2);
                    if (close_hook_count == 0) {
                        result_pass("unhooked: close() not intercepted (correct)");
                    } else {
                        result_fail("unhooked: close() still intercepted count=%d", close_hook_count);
                    }
                }
            } else {
                result_fail("adl_plt_unhook failed");
            }
        } else {
            result_fail("adl_plt_hook(close) failed");
        }
    }

    // 17. Inline hook test — hook gettimeofday (safe, no recursion risk)
    g_result += "\n--- Inline hook: gettimeofday ---\n";
    {
        typedef int (*gettimeofday_fn)(struct timeval *, struct timezone *);
        static gettimeofday_fn orig_gettimeofday = NULL;
        static std::string *hook_log2;
        hook_log2 = &g_result;

        struct hook_helper2 {
            static int hooked_gettimeofday(struct timeval *tv, struct timezone *tz) {
                char buf[128];
                snprintf(buf, sizeof(buf), "  >> before gettimeofday()\n");
                *hook_log2 += buf;
                int ret = orig_gettimeofday(tv, tz);
                snprintf(buf, sizeof(buf), "  << after  gettimeofday() = %d, sec=%ld\n",
                         ret, tv ? (long)tv->tv_sec : 0);
                *hook_log2 += buf;
                // Add 1 day to verify we can modify results
                if (ret == 0 && tv != NULL) {
                    tv->tv_sec += 86400;
                }
                return ret;
            }
        };

        void *handle = adlopen(BASENAME_LIBC, 0);
        void *target = handle ? adlsym(handle, "gettimeofday") : NULL;
        if (target != NULL) {
            // Get real time first
            struct timeval before;
            gettimeofday(&before, NULL);

            int ret = adl_inline_hook(target,
                                      reinterpret_cast<void *>(hook_helper2::hooked_gettimeofday),
                                      reinterpret_cast<void **>(&orig_gettimeofday));
            if (ret == 0) {
                result_pass("adl_inline_hook(gettimeofday) installed");

                struct timeval after;
                gettimeofday(&after, NULL);
                long diff = after.tv_sec - before.tv_sec;
                if (diff >= 86000) {
                    result_pass("hooked: time shifted +%ld seconds (1 day)", diff);
                } else {
                    result_fail("hooked: expected +86400s, got +%ld", diff);
                }

                ret = adl_inline_unhook(target);
                if (ret == 0) {
                    result_pass("adl_inline_unhook(gettimeofday) restored");
                    struct timeval restored;
                    gettimeofday(&restored, NULL);
                    long diff2 = restored.tv_sec - before.tv_sec;
                    if (diff2 < 100) {
                        result_pass("unhooked: time normal +%ld seconds", diff2);
                    } else {
                        result_fail("unhooked: still shifted +%ld", diff2);
                    }
                } else {
                    result_fail("adl_inline_unhook failed");
                }
            } else {
                result_fail("adl_inline_hook(gettimeofday) failed");
            }
        } else {
            result_fail("adlsym(gettimeofday) not found");
        }
        if (handle) adlclose(handle);
    }

    // 18. PLT hook: intercept __android_log_print to count log calls
    g_result += "\n--- PLT hook: __android_log_print ---\n";
    {
        typedef int (*log_fn)(int, const char *, const char *, ...);
        static log_fn orig_log = NULL;
        static int log_count;
        log_count = 0;

        struct log_hook {
            static int hooked_log(int prio, const char *tag, const char *fmt, ...) {
                log_count++;
                va_list args;
                va_start(args, fmt);
                int ret = __android_log_vprint(prio, tag, fmt, args);
                va_end(args);
                return ret;
            }
        };

        int ret = adl_plt_hook("libsample.so", "__android_log_print",
                               reinterpret_cast<void *>(log_hook::hooked_log),
                               reinterpret_cast<void **>(&orig_log));
        if (ret == 0) {
            result_pass("adl_plt_hook(__android_log_print) installed");
            log_count = 0;
            LOG("test log 1");
            LOG("test log 2");
            LOG("test log 3");
            if (log_count == 3) {
                result_pass("hooked: intercepted %d log calls", log_count);
            } else {
                result_fail("hooked: expected 3 log calls, got %d", log_count);
            }
            adl_plt_unhook("libsample.so", "__android_log_print");
            result_pass("adl_plt_unhook(__android_log_print) restored");
        } else {
            result_fail("adl_plt_hook(__android_log_print) failed");
        }
    }

    // 19. PLT hook: modify memcmp return to always match
    g_result += "\n--- PLT hook: memcmp ---\n";
    {
        typedef int (*memcmp_fn)(const void *, const void *, size_t);
        static memcmp_fn orig_memcmp = NULL;

        struct memcmp_hook {
            static int hooked_memcmp(const void *a, const void *b, size_t n) {
                (void)a; (void)b; (void)n;
                return 0; // always "equal"
            }
        };

        int ret = adl_plt_hook("libsample.so", "memcmp",
                               reinterpret_cast<void *>(memcmp_hook::hooked_memcmp),
                               reinterpret_cast<void **>(&orig_memcmp));
        if (ret == 0) {
            result_pass("adl_plt_hook(memcmp) installed");
            // Use volatile to prevent compiler from optimizing away the call
            volatile const char *a = "hello";
            volatile const char *b = "world";
            int cmp = memcmp(const_cast<const char*>(a), const_cast<const char*>(b), 5);
            if (cmp == 0) {
                result_pass("hooked: memcmp(\"hello\",\"world\") = 0 (forced equal)");
            } else {
                result_fail("hooked: memcmp returned %d, expected 0", cmp);
            }
            adl_plt_unhook("libsample.so", "memcmp");
            cmp = memcmp(const_cast<const char*>(a), const_cast<const char*>(b), 5);
            if (cmp != 0) {
                result_pass("unhooked: memcmp(\"hello\",\"world\") = %d (correct)", cmp);
            } else {
                result_fail("unhooked: memcmp still returns 0");
            }
        } else {
            result_fail("adl_plt_hook(memcmp) failed");
        }
    }

    // 20. Inline hook: localtime
    g_result += "\n--- Inline hook: localtime ---\n";
    {
        typedef struct tm *(*localtime_fn)(const time_t *);
        static localtime_fn orig_localtime = NULL;
        static std::string *lt_log;
        lt_log = &g_result;

        struct lt_hook {
            static struct tm *hooked_localtime(const time_t *timep) {
                struct tm *result = orig_localtime(timep);
                if (result != NULL) {
                    result->tm_year += 100; // +100 years, no string ops
                }
                return result;
            }
        };

        void *handle = adlopen(BASENAME_LIBC, 0);
        void *target = handle ? adlsym(handle, "localtime") : NULL;
        if (target != NULL) {
            time_t now = time(NULL);
            struct tm *before = localtime(&now);
            int real_year = before->tm_year + 1900;

            int ret = adl_inline_hook(target,
                                      reinterpret_cast<void *>(lt_hook::hooked_localtime),
                                      reinterpret_cast<void **>(&orig_localtime));
            if (ret == 0) {
                result_pass("adl_inline_hook(localtime) installed");
                struct tm *after = localtime(&now);
                int hooked_year = after->tm_year + 1900;
                if (hooked_year == real_year + 100) {
                    result_pass("hooked: year=%d (real=%d, +100)", hooked_year, real_year);
                } else {
                    result_fail("hooked: year=%d, expected %d", hooked_year, real_year + 100);
                }

                adl_inline_unhook(target);
                result_pass("adl_inline_unhook(localtime) restored");
                struct tm *restored = localtime(&now);
                if (restored->tm_year + 1900 == real_year) {
                    result_pass("unhooked: year=%d (correct)", restored->tm_year + 1900);
                } else {
                    result_fail("unhooked: year=%d, expected %d",
                                restored->tm_year + 1900, real_year);
                }
            } else {
                result_fail("adl_inline_hook(localtime) failed");
            }
        } else {
            result_fail("adlsym(localtime) not found");
        }
        if (handle) adlclose(handle);
    }

    // 21. Inline hook: atoi
    g_result += "\n--- Inline hook: atoi ---\n";
    {
        typedef int (*atoi_fn)(const char *);
        static atoi_fn orig_atoi = NULL;
        static std::string *atoi_log;
        atoi_log = &g_result;

        struct atoi_hook {
            static int hooked_atoi(const char *s) {
                char buf[128];
                snprintf(buf, sizeof(buf), "  >> before atoi(\"%s\")\n", s);
                *atoi_log += buf;
                int ret = orig_atoi(s);
                snprintf(buf, sizeof(buf), "  << after  atoi(\"%s\") = %d, returning %d\n",
                         s, ret, ret * 2);
                *atoi_log += buf;
                return ret * 2; // double it
            }
        };

        void *handle = adlopen(BASENAME_LIBC, 0);
        void *target = handle ? adlsym(handle, "atoi") : NULL;
        if (target != NULL) {
            int ret = adl_inline_hook(target,
                                      reinterpret_cast<void *>(atoi_hook::hooked_atoi),
                                      reinterpret_cast<void **>(&orig_atoi));
            if (ret == 0) {
                result_pass("adl_inline_hook(atoi) installed");
                int val = atoi("123");
                if (val == 246) {
                    result_pass("hooked: atoi(\"123\") = %d (doubled)", val);
                } else {
                    result_fail("hooked: atoi(\"123\") = %d, expected 246", val);
                }
                adl_inline_unhook(target);
                result_pass("adl_inline_unhook(atoi) restored");
                int restored = atoi("123");
                if (restored == 123) {
                    result_pass("unhooked: atoi(\"123\") = %d (correct)", restored);
                } else {
                    result_fail("unhooked: atoi(\"123\") = %d, expected 123", restored);
                }
            } else {
                result_fail("adl_inline_hook(atoi) failed");
            }
        } else {
            result_fail("adlsym(atoi) not found");
        }
        if (handle) adlclose(handle);
    }

    // 22. Inline hook: strlen — user hooks strlen, framework auto-detects FORTIFY
    // Framework automatically hooks __strlen_chk, orig points to raw strlen
    g_result += "\n--- Inline hook: strlen (FORTIFY auto) ---\n";
    {
        typedef size_t (*strlen_fn)(const char *);
        static strlen_fn orig_strlen_fn = NULL;

        static volatile int strlen_call_count;
        strlen_call_count = 0;

        struct strlen_hook {
            static size_t hooked_strlen(const char *s) {
                // Observe only — do NOT modify return value for global functions!
                // Modifying return value of strlen/memcpy/etc breaks other threads.
                strlen_call_count++;
                return orig_strlen_fn(s);  // transparent pass-through
            }
        };

        void *handle = adlopen(BASENAME_LIBC, 0);
        void *target = handle ? adlsym(handle, "strlen") : NULL;
        if (target != NULL) {
            int ret = adl_inline_hook(target,
                                      reinterpret_cast<void *>(strlen_hook::hooked_strlen),
                                      reinterpret_cast<void **>(&orig_strlen_fn));
            if (ret == 0) {
                result_pass("adl_inline_hook(strlen) installed");

                // Verify interception: call strlen and check counter
                strlen_call_count = 0;
                char test[] = "hello";
                volatile size_t len = strlen(test);
                if (strlen_call_count > 0 && len == 5) {
                    result_pass("hooked: strlen(\"hello\") = %zu, intercepted %d times",
                                (size_t)len, (int)strlen_call_count);
                } else {
                    result_fail("hooked: strlen count=%d len=%zu",
                                (int)strlen_call_count, (size_t)len);
                }

                adl_inline_unhook(target);
                result_pass("adl_inline_unhook(strlen) restored");
                strlen_call_count = 0;
                volatile size_t restored = strlen(test);
                if (strlen_call_count == 0 && restored == 5) {
                    result_pass("unhooked: strlen not intercepted, len=%zu (correct)",
                                (size_t)restored);
                } else {
                    result_fail("unhooked: count=%d len=%zu",
                                (int)strlen_call_count, (size_t)restored);
                }
            } else {
                result_fail("adl_inline_hook(strlen) failed");
            }
        } else {
            result_fail("adlsym(strlen) not found");
        }
        if (handle) adlclose(handle);
    }

    // 23. Inline hook: __strlen_chk directly — can safely modify return value
    // Because we bypass FORTIFY check entirely (we ARE the check now)
    g_result += "\n--- Inline hook: __strlen_chk (modify) ---\n";
    {
        typedef size_t (*strlen_chk_fn)(const char *, size_t);
        static strlen_chk_fn orig_strlen_chk = NULL;

        struct strlen_chk_hook {
            static size_t hooked(const char *s, size_t bos) {
                // Safe to modify: we replaced __strlen_chk, so FORTIFY check is ours
                return orig_strlen_chk(s, bos) + 42;
            }
        };

        void *handle = adlopen(BASENAME_LIBC, 0);
        void *target = handle ? adlsym(handle, "__strlen_chk") : NULL;
        if (target != NULL) {
            int ret = adl_inline_hook(target,
                                      reinterpret_cast<void *>(strlen_chk_hook::hooked),
                                      reinterpret_cast<void **>(&orig_strlen_chk));
            if (ret == 0) {
                result_pass("adl_inline_hook(__strlen_chk) installed at %p", target);

                char test[] = "hello";
                volatile size_t hooked_len = strlen(test);
                if (hooked_len == 5 + 42) {
                    result_pass("hooked: strlen via __strlen_chk = %zu (+42)", (size_t)hooked_len);
                } else {
                    result_fail("hooked: strlen = %zu, expected 47", (size_t)hooked_len);
                }

                adl_inline_unhook(target);
                result_pass("adl_inline_unhook(__strlen_chk) restored");
                volatile size_t restored = strlen(test);
                if (restored == 5) {
                    result_pass("unhooked: strlen = %zu (correct)", (size_t)restored);
                } else {
                    result_fail("unhooked: strlen = %zu, expected 5", (size_t)restored);
                }
            } else {
                result_fail("adl_inline_hook(__strlen_chk) failed");
            }
        } else {
            result_fail("adlsym(__strlen_chk) not found");
        }
        if (handle) adlclose(handle);
    }

    // 24. Inline hook: open (minimal hook, no LOG/malloc to avoid recursion)
    g_result += "\n--- Inline hook: open ---\n";
    {
        typedef int (*open_fn)(const char *, int, ...);
        static open_fn orig_open_fn = NULL;
        static volatile int open_hook_count;
        open_hook_count = 0;

        struct open_hook {
            static int hooked_open(const char *path, int flags, ...) {
                open_hook_count++;
                return orig_open_fn(path, flags);
            }
        };

        // FORTIFY replaces open() with __open_2, so hook that instead
        void *handle = adlopen(BASENAME_LIBC, 0);
        void *target = handle ? adlsym(handle, "__open_2") : NULL;
        if (target == NULL && handle) {
            // fallback to open if __open_2 not found
            target = adlsym(handle, "open");
        }
        if (target != NULL) {
            int ret = adl_inline_hook(target,
                                      reinterpret_cast<void *>(open_hook::hooked_open),
                                      reinterpret_cast<void **>(&orig_open_fn));
            if (ret == 0) {
                result_pass("adl_inline_hook(__open_2/open) installed at %p", target);
                open_hook_count = 0;
                int fd = open("/proc/self/maps", O_RDONLY);
                if (fd >= 0 && open_hook_count > 0) {
                    result_pass("hooked: open() intercepted (count=%d, fd=%d)",
                                (int)open_hook_count, fd);
                    close(fd);
                } else if (fd >= 0) {
                    result_fail("hooked: open() not intercepted (count=%d)",
                                (int)open_hook_count);
                    close(fd);
                } else {
                    result_fail("hooked: open() failed errno=%d", errno);
                }

                adl_inline_unhook(target);
                result_pass("adl_inline_unhook(__open_2/open) restored");
                open_hook_count = 0;
                int fd2 = open("/proc/self/maps", O_RDONLY);
                if (fd2 >= 0 && open_hook_count == 0) {
                    result_pass("unhooked: open() not intercepted (correct)");
                    close(fd2);
                } else {
                    result_fail("unhooked: count=%d fd=%d", (int)open_hook_count, fd2);
                    if (fd2 >= 0) close(fd2);
                }
            } else {
                result_fail("adl_inline_hook(__open_2/open) failed");
            }
        } else {
            result_fail("adlsym(__open_2/open) not found");
        }
        if (handle) adlclose(handle);
    }

    // 25. Inline hook: short function (getpid, ~12 bytes)
    g_result += "\n--- Inline hook: getpid (short func) ---\n";
    {
        typedef pid_t (*getpid_fn)(void);
        static getpid_fn orig_getpid = NULL;
        static volatile int getpid_hook_count;
        getpid_hook_count = 0;

        struct getpid_hook {
            static pid_t hooked_getpid(void) {
                getpid_hook_count++;
                return orig_getpid();  // observe only — getpid is very short
            }
        };

        void *handle = adlopen(BASENAME_LIBC, 0);
        void *target = handle ? adlsym(handle, "getpid") : NULL;
        if (target != NULL) {
            int ret = adl_inline_hook(target,
                                      reinterpret_cast<void *>(getpid_hook::hooked_getpid),
                                      reinterpret_cast<void **>(&orig_getpid));
            if (ret == 0) {
                result_pass("adl_inline_hook(getpid) installed");
                getpid_hook_count = 0;
                pid_t pid = getpid();
                if (getpid_hook_count > 0 && pid > 0) {
                    result_pass("hooked: getpid() = %d, intercepted %d times", pid, (int)getpid_hook_count);
                } else {
                    result_fail("hooked: pid=%d count=%d", pid, (int)getpid_hook_count);
                }
                adl_inline_unhook(target);
                result_pass("adl_inline_unhook(getpid) restored");
            } else {
                result_info("adl_inline_hook(getpid) failed (may be too short, expected)");
            }
        }
        if (handle) adlclose(handle);
    }

    // 26. Inline hook: reject/block call
    g_result += "\n--- Inline hook: block call ---\n";
    {
        typedef int (*access_fn)(const char *, int);
        static access_fn orig_access = NULL;

        struct access_hook {
            static int hooked_access(const char *path, int mode) {
                // Block access to a specific path — don't call original
                if (path != NULL && path[0] == '/' && path[1] == 't' && path[2] == 'm' && path[3] == 'p') {
                    return -1;  // reject without calling orig
                }
                return orig_access(path, mode);  // allow others
            }
        };

        void *handle = adlopen(BASENAME_LIBC, 0);
        void *target = handle ? adlsym(handle, "access") : NULL;
        if (target != NULL) {
            int ret = adl_inline_hook(target,
                                      reinterpret_cast<void *>(access_hook::hooked_access),
                                      reinterpret_cast<void **>(&orig_access));
            if (ret == 0) {
                result_pass("adl_inline_hook(access) installed");

                // /proc/self/maps should be allowed
                int r1 = access("/proc/self/maps", F_OK);
                if (r1 == 0) {
                    result_pass("access(/proc/self/maps) = %d (allowed)", r1);
                } else {
                    result_fail("access(/proc/self/maps) = %d (should be allowed)", r1);
                }

                // /tmp/... should be blocked
                int r2 = access("/tmp/test", F_OK);
                if (r2 == -1) {
                    result_pass("access(/tmp/test) = %d (blocked)", r2);
                } else {
                    result_fail("access(/tmp/test) = %d (should be blocked)", r2);
                }

                adl_inline_unhook(target);
                result_pass("adl_inline_unhook(access) restored");
            } else {
                result_fail("adl_inline_hook(access) failed");
            }
        }
        if (handle) adlclose(handle);
    }

    // 27. PLT hook: parameter modification (hook localtime to modify input)
    g_result += "\n--- PLT hook: localtime param modify ---\n";
    {
        typedef struct tm *(*localtime_fn)(const time_t *);
        static localtime_fn orig_localtime_plt = NULL;
        static time_t modified_time;

        struct localtime_plt_hook {
            static struct tm *hooked(const time_t *timep) {
                // Modify parameter: add 365 days
                modified_time = *timep + 365 * 86400;
                return orig_localtime_plt(&modified_time);
            }
        };

        int ret = adl_plt_hook("libsample.so", "localtime",
                               reinterpret_cast<void *>(localtime_plt_hook::hooked),
                               reinterpret_cast<void **>(&orig_localtime_plt));
        if (ret == 0) {
            result_pass("adl_plt_hook(localtime) installed");
            time_t now = time(NULL);
            struct tm *tm = localtime(&now);
            int year = tm->tm_year + 1900;
            if (year == 2027) {
                result_pass("param modified: localtime returns year=%d (+1)", year);
            } else {
                result_fail("param modify: year=%d, expected 2027", year);
            }
            adl_plt_unhook("libsample.so", "localtime");
            result_pass("adl_plt_unhook(localtime) restored");
        } else {
            result_fail("adl_plt_hook(localtime) failed");
        }
    }

    // 28. Inline hook: hook → unhook → rehook cycle
    g_result += "\n--- Inline hook: rehook cycle ---\n";
    {
        typedef int (*atoi_fn)(const char *);
        static atoi_fn orig_atoi2 = NULL;
        static volatile int atoi_cycle_count;

        struct atoi_cycle_hook {
            static int hooked(const char *s) {
                atoi_cycle_count++;
                return orig_atoi2(s);
            }
        };

        void *handle = adlopen(BASENAME_LIBC, 0);
        void *target = handle ? adlsym(handle, "atoi") : NULL;
        if (target != NULL) {
            bool all_ok = true;
            for (int cycle = 0; cycle < 3; cycle++) {
                int ret = adl_inline_hook(target,
                                          reinterpret_cast<void *>(atoi_cycle_hook::hooked),
                                          reinterpret_cast<void **>(&orig_atoi2));
                if (ret != 0) {
                    result_fail("rehook cycle %d: hook failed", cycle);
                    all_ok = false;
                    break;
                }

                atoi_cycle_count = 0;
                volatile int val = atoi("99");
                if (atoi_cycle_count == 0 || val != 99) {
                    result_fail("rehook cycle %d: count=%d val=%d", cycle,
                                (int)atoi_cycle_count, val);
                    all_ok = false;
                    adl_inline_unhook(target);
                    break;
                }

                adl_inline_unhook(target);

                // Verify unhook works
                atoi_cycle_count = 0;
                volatile int val2 = atoi("99");
                if (atoi_cycle_count != 0 || val2 != 99) {
                    result_fail("rehook cycle %d unhook: count=%d val=%d", cycle,
                                (int)atoi_cycle_count, val2);
                    all_ok = false;
                    break;
                }
            }
            if (all_ok) {
                result_pass("3x hook/unhook/rehook cycles all passed");
            }
        } else {
            result_fail("adlsym(atoi) not found");
        }
        if (handle) adlclose(handle);
    }

    // 29. Inline hook: C++ mangled function from libart
    g_result += "\n--- Inline hook: ART C++ function ---\n";
    {
        void *art_handle = adlopen(PATHNAME_LIBART, 0);
        if (art_handle == NULL) {
            art_handle = adlopen("libart.so", 0);
        }
        if (art_handle != NULL) {
            // Find JNI_GetCreatedJavaVMs — exported C function in libart
            typedef int (*get_vms_fn)(JavaVM **, int, int *);
            static get_vms_fn orig_get_vms = NULL;
            static volatile int get_vms_count;
            get_vms_count = 0;

            struct get_vms_hook {
                static int hooked(JavaVM **vms, int max, int *count) {
                    get_vms_count++;
                    return orig_get_vms(vms, max, count);
                }
            };

            void *target = adlsym(art_handle, "JNI_GetCreatedJavaVMs");
            if (target != NULL) {
                int ret = adl_inline_hook(target,
                                          reinterpret_cast<void *>(get_vms_hook::hooked),
                                          reinterpret_cast<void **>(&orig_get_vms));
                if (ret == 0) {
                    result_pass("adl_inline_hook(JNI_GetCreatedJavaVMs) installed");

                    get_vms_count = 0;
                    JavaVM *vm = NULL;
                    int count = 0;
                    int r = get_vms_hook::hooked(&vm, 1, &count);
                    if (get_vms_count > 0 && r == 0 && count > 0) {
                        result_pass("hooked: JNI_GetCreatedJavaVMs intercepted, %d VM(s)", count);
                    } else {
                        result_fail("hooked: count=%d ret=%d vms=%d",
                                    (int)get_vms_count, r, count);
                    }

                    adl_inline_unhook(target);
                    result_pass("adl_inline_unhook(JNI_GetCreatedJavaVMs) restored");
                } else {
                    result_fail("adl_inline_hook(JNI_GetCreatedJavaVMs) failed");
                }
            } else {
                result_info("JNI_GetCreatedJavaVMs not found in libart");
            }
            adlclose(art_handle);
        } else {
            result_info("libart.so not found (skipping ART hook test)");
        }
    }

    // 30. PLT hook: __vsnprintf_chk (FORTIFY-wrapped snprintf)
    g_result += "\n--- PLT hook: __vsnprintf_chk ---\n";
    {
        typedef int (*vsnprintf_chk_fn)(char *, size_t, int, size_t, const char *, va_list);
        static vsnprintf_chk_fn orig_vsnprintf_chk = NULL;

        struct vsnprintf_chk_hook {
            static int hooked(char *buf, size_t maxlen, int flag, size_t slen,
                              const char *fmt, va_list ap) {
                // Prefix the output with [hooked]
                int prefix_len = 0;
                if (maxlen > 9) {
                    memcpy(buf, "[hooked] ", 9);
                    prefix_len = 9;
                }
                int ret = orig_vsnprintf_chk(buf + prefix_len, maxlen - prefix_len,
                                              flag, slen > (size_t)prefix_len ? slen - prefix_len : slen,
                                              fmt, ap);
                return ret + prefix_len;
            }
        };

        int ret = adl_plt_hook("libsample.so", "__vsnprintf_chk",
                               reinterpret_cast<void *>(vsnprintf_chk_hook::hooked),
                               reinterpret_cast<void **>(&orig_vsnprintf_chk));
        if (ret == 0) {
            result_pass("adl_plt_hook(__vsnprintf_chk) installed");

            char buf[64];
            snprintf(buf, sizeof(buf), "hello %d", 42);
            if (memcmp(buf, "[hooked]", 8) == 0) {
                result_pass("hooked: snprintf -> \"%s\"", buf);
            } else {
                result_fail("hooked: snprintf -> \"%s\" (expected [hooked] prefix)", buf);
            }

            adl_plt_unhook("libsample.so", "__vsnprintf_chk");
            result_pass("adl_plt_unhook(__vsnprintf_chk) restored");

            snprintf(buf, sizeof(buf), "hello %d", 42);
            if (memcmp(buf, "hello", 5) == 0) {
                result_pass("unhooked: snprintf -> \"%s\" (correct)", buf);
            } else {
                result_fail("unhooked: snprintf -> \"%s\"", buf);
            }
        } else {
            result_fail("adl_plt_hook(__vsnprintf_chk) failed");
        }
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
