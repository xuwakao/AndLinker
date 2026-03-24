//
// AndHooker — PLT/GOT hook and inline hook for Android
//

#ifndef ANDHOOKER_ADL_HOOK_H
#define ANDHOOKER_ADL_HOOK_H

#include <sys/cdefs.h>

__BEGIN_DECLS

/**
 * Recursion guard for inline hook proxy functions.
 *
 * When a proxy function internally calls other functions that may re-enter
 * the hooked function (e.g., hooking strlen, and the proxy calls snprintf
 * which calls strlen again), use this macro to prevent infinite recursion.
 *
 * Usage in C++ proxy function:
 *
 *   static size_t my_strlen_hook(const char *s) {
 *       ADL_HOOK_CALL_GUARD(orig_strlen, s);  // if recursive, call orig and return
 *       // ... your logic (may call functions that use strlen internally) ...
 *       return orig_strlen(s) + 42;
 *   }
 *
 * ADL_HOOK_CALL_GUARD checks a thread-local recursion flag. If already inside
 * this proxy, it calls the original function directly and returns immediately.
 * The flag is automatically cleared when the proxy function returns normally.
 */

struct _adl_hook_guard_t {
    int &depth;
    _adl_hook_guard_t(int &d) : depth(d) { depth++; }
    ~_adl_hook_guard_t() { depth--; }
};

#define ADL_HOOK_CALL_GUARD(orig_fn, ...) \
    static __thread int _adl_guard_depth_##orig_fn = 0; \
    if (_adl_guard_depth_##orig_fn > 0) { \
        return (orig_fn)(__VA_ARGS__); \
    } \
    _adl_hook_guard_t _adl_guard_instance_##orig_fn(_adl_guard_depth_##orig_fn)

/**
 * PLT/GOT hook: replace a PLT call in caller_lib to target_func with new_func.
 *
 * @param caller_lib  Library name or path whose GOT will be patched (e.g. "libsample.so")
 * @param target_func Symbol name of the function to hook (e.g. "gettimeofday")
 * @param new_func    Pointer to the replacement function
 * @param orig_func   [out] Receives the original function pointer (can be NULL)
 * @return 0 on success, -1 on error
 */
int adl_plt_hook(const char *caller_lib, const char *target_func,
                 void *new_func, void **orig_func);

/**
 * PLT/GOT unhook: restore the original PLT call.
 *
 * @param caller_lib  Same library used in adl_plt_hook
 * @param target_func Same symbol name used in adl_plt_hook
 * @return 0 on success, -1 on error
 */
int adl_plt_unhook(const char *caller_lib, const char *target_func);

/**
 * Inline hook: patch the function entry to redirect to new_func.
 * Works on all callers, not just a specific library.
 *
 * @param target_func Pointer to the function to hook
 * @param new_func    Pointer to the replacement function
 * @param orig_func   [out] Receives a trampoline to call the original function (can be NULL)
 * @return 0 on success, -1 on error
 */
int adl_inline_hook(void *target_func, void *new_func, void **orig_func);

/**
 * Inline unhook: restore the original function entry.
 *
 * @param target_func Same pointer used in adl_inline_hook
 * @return 0 on success, -1 on error
 */
int adl_inline_unhook(void *target_func);

__END_DECLS

#endif //ANDHOOKER_ADL_HOOK_H
