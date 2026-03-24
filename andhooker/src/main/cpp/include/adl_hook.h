//
// AndHooker — PLT/GOT hook and inline hook for Android
//

#ifndef ANDHOOKER_ADL_HOOK_H
#define ANDHOOKER_ADL_HOOK_H

#include <sys/cdefs.h>

__BEGIN_DECLS

/**
 * Inline hook includes automatic recursion prevention via a "hub" mechanism.
 * When a proxy function internally calls other functions that re-enter the
 * hooked function, the hub detects the recursion and calls the original
 * function directly, preventing infinite loops.
 *
 * Example:
 *   static size_t (*orig_strlen)(const char *) = NULL;
 *   static size_t my_strlen(const char *s) {
 *       // No guard needed! Hub handles recursion automatically.
 *       // snprintf below may call strlen internally — hub will bypass proxy.
 *       char buf[64];
 *       snprintf(buf, sizeof(buf), "strlen called for %p", s);
 *       return orig_strlen(s) + 42;
 *   }
 *   adl_inline_hook(target, my_strlen, (void**)&orig_strlen);
 */

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
 * If multiple hooks are chained on the same function, removes the most recent one.
 * When the last hook is removed, the original function is fully restored.
 *
 * @param target_func Same pointer used in adl_inline_hook
 * @return 0 on success, -1 on error
 */
int adl_inline_unhook(void *target_func);

/**
 * Allow reentrant calls for an inline-hooked function.
 * By default, recursive calls to a hooked function skip the proxy (recursion guard).
 * Calling this allows recursive calls to also go through the proxy.
 * Useful for thread-pool scenarios where the same function is legitimately
 * called recursively across task boundaries.
 *
 * @param target_func Same pointer used in adl_inline_hook
 * @return 0 on success, -1 if not found
 */
int adl_inline_hook_allow_reentrant(void *target_func);

/**
 * Disallow reentrant calls (restore default recursion guard behavior).
 *
 * @param target_func Same pointer used in adl_inline_hook
 * @return 0 on success, -1 if not found
 */
int adl_inline_hook_disallow_reentrant(void *target_func);

__END_DECLS

#endif //ANDHOOKER_ADL_HOOK_H
