# AndLinker

Android linker bypass library — access private/internal symbols in system shared libraries (`.so`) by bypassing linker namespace restrictions.

## Why

Starting from Android 7.0 (Nougat), the system linker enforces **namespace-based library isolation**. Apps can no longer use `dlopen`/`dlsym` to access private symbols in system libraries like `libc.so`, `libart.so`, or `linker64`. Calling `dlsym` on these symbols returns `NULL`, even though the symbols exist in the library's ELF binary.

This restriction blocks legitimate use cases such as:

- **Performance profiling** — accessing ART internals to inspect method execution
- **Security research** — analyzing system behavior at the native level
- **Compatibility workarounds** — calling private APIs that have no public alternatives
- **Reverse engineering** — understanding system library behavior for debugging

AndLinker restores access to **all** symbols in any loaded `.so` file, regardless of linker namespace restrictions.

## How It Works

### Library Loading (Bypass `dlopen`)

On Android 7.0+, the standard `dlopen` checks the caller's namespace and rejects libraries outside the app's allowed list. AndLinker bypasses this by:

1. **Locating the linker's internal `dlopen` function** — uses `adlsym` to find symbols like `__loader_dlopen` (API 28+), `__dl__Z9do_dlopenPKciPK17android_dlextinfoPv` (API 24-27), or `__dl__Z20__android_dlopen_ext...` (API 26-27) inside the linker binary itself
2. **Calling it with a fake caller address** — the linker determines namespace membership based on the caller's address; by passing an address from `libc` (which belongs to the system namespace), the restriction is bypassed
3. **Falling back to standard `dlopen`** — if the bypass fails (e.g., on future Android versions), it gracefully falls back

### Symbol Resolution (Bypass `dlsym`)

Standard `dlsym` only searches `.dynsym` (dynamic symbol table) and respects namespace visibility. AndLinker implements its own symbol lookup with three levels:

1. **Hash table lookup** — parses `DT_GNU_HASH` or `DT_HASH` from the library's dynamic section for O(1) symbol lookup in `.dynsym` (same algorithm as the system linker, but without namespace filtering)
2. **`.dynsym` linear scan** — falls back to iterating the dynamic symbol table if hash lookup fails
3. **`.symtab` file-based scan** — reads the full symbol table from the ELF file on disk via `mmap`, which includes static/local symbols not in `.dynsym` (these are the "private" symbols that are completely invisible to standard `dlsym`)

### Fuzzy Symbol Matching

C++ mangled names (e.g., `_ZN3art9ArtMethod12PrettyMethodEb`) vary across Android versions due to different compiler versions, overloads, or parameter types. `adlsym_match` solves this by:

1. Trying exact match first
2. Demangling each symbol using `__cxa_demangle` (e.g., → `art::ArtMethod::PrettyMethod(bool)`), then substring matching against the demangled name
3. Falling back to raw mangled name substring matching

This allows searching with readable patterns like `"ArtMethod::PrettyMethod"` instead of exact mangled names.

### Thread Safety

All public APIs are protected by a recursive mutex, ensuring safe concurrent access from multiple threads.

## Features

- `adlopen` / `adlclose` — Open and close shared libraries, bypassing linker restrictions on Android 7.0+
- `adlsym` — Resolve symbols (including private/internal ones) from loaded libraries
- `adlvsym` — Resolve versioned symbols (Android 7.0+)
- `adlsym_match` — Fuzzy symbol lookup with `__cxa_demangle` support (search by C++ readable name)
- `adladdr` — Get symbol information for a given address (like `dladdr`)
- `adlerror` — Get last error message (like `dlerror`)
- `adl_iterate_phdr` — Iterate over program headers of all loaded libraries
- `adl_enum_symbols` — Enumerate all symbols in a library (.dynsym + .symtab)

## Compatibility

- **Minimum SDK**: API 21 (Android 5.0)
- **Target SDK**: API 34 (Android 14)
- **Architectures**: armeabi-v7a, arm64-v8a, x86, x86_64
- **Tested on**: Android 6.0 — 16 (API 23 — 36)

## Usage

### Integration

Add the `andlinker` module to your project and declare a dependency:

```gradle
dependencies {
    implementation project(':andlinker')
}
```

### API

```cpp
#include <adl.h>

// Open a library (supports both full path and basename)
void *handle = adlopen("libc.so", 0);

// Resolve a private symbol
void *sym = adlsym(handle, "__openat");

// Fuzzy match by demangled C++ name
void *sym2 = adlsym_match(handle, "ArtMethod::PrettyMethod", NULL, NULL);

// Resolve a versioned symbol
void *sym_v = adlvsym(handle, "symbol_name", "LIBC");

// Enumerate all symbols
adl_enum_symbols(handle, [](const char *name, void *addr, size_t size,
                             int type, void *arg) -> int {
    // process each symbol
    return 0; // 0 = continue, non-zero = stop
}, NULL);

// Get symbol info by address
Dl_info info;
adladdr(some_addr, &info);

// Check errors
if (sym == NULL) {
    const char *err = adlerror(); // returns error message, clears it
}

// Iterate loaded libraries
adl_iterate_phdr(callback, user_data);

// Close handle
adlclose(handle);
```

---

# AndHooker

`andhooker` is a companion module that provides **PLT/GOT hook** and **inline hook** capabilities, built on top of AndLinker's symbol resolution.

## Hook Types

### PLT/GOT Hook

PLT hook intercepts function calls **from a specific library** by modifying its GOT (Global Offset Table) entries.

```
app calls strlen()
  → PLT stub in libsample.so
    → GOT entry (originally points to libc strlen)
      → [HOOKED] GOT entry now points to your proxy function
        → proxy calls original via saved pointer
```

**Characteristics:**
- Only affects calls from the specified library (other libraries still call the original)
- Safe for high-frequency functions (strlen, memcpy, etc.) — only one module affected
- Can modify parameters, return values, or block calls
- No instruction relocation needed — just a pointer swap

### Inline Hook

Inline hook patches the **function entry** directly, affecting **all callers** across the entire process.

```
Any code calls gettimeofday()
  → function entry (first 16 bytes replaced with jump)
    → Hub assembly trampoline
      → Check TLS recursion state
        → First call: jump to proxy function
        → Recursive call: jump to original (via trampoline)
    → proxy executes, calls orig via trampoline
    → Hub epilogue: pop recursion state, return to caller
```

**Characteristics:**
- Affects ALL callers in the process (global interception)
- Instruction relocation engine handles PC-relative instructions in trampoline
- Hub mechanism provides automatic recursion prevention (no user code needed)
- FORTIFY auto-detection: framework detects `__xxx_chk` wrappers and adjusts target

## How It Works

### PLT Hook Implementation

1. `adlopen(caller_lib)` → parse dynamic section via `adl_prelink_image`
2. Iterate `.rela.plt` / `.rel.plt` entries to find target symbol
3. Calculate GOT entry address: `load_bias + relocation.r_offset`
4. `mprotect` GOT page to writable → write new function pointer → restore protection
5. Save original pointer for unhook and `orig_func` callback

### Inline Hook Implementation

#### 1. FORTIFY Auto-Detection

When user hooks `strlen`, the framework:
1. Reverse-lookups symbol name via `adladdr`
2. Checks if `__strlen_chk` exists in the same library (pattern: `__<name>_chk` or `__<name>_2`)
3. If found, hooks the FORTIFY wrapper instead; `orig_func` points to the raw function

This prevents FORTIFY abort: `__strlen_chk` validates strlen's return value, so hooking raw strlen with a modified return triggers a security check. Hooking `__strlen_chk` directly bypasses this.

#### 2. BTI (Branch Target Identification) Handling

ARM64 security feature: CPU verifies branch targets have BTI instructions. If a function starts with `HINT #34` (BTI), the hook patches **after** the BTI instruction, and the trampoline includes BTI at its entry.

#### 3. Instruction Relocation

The first 16 bytes of the target function are overwritten with a jump. The original instructions are moved to a trampoline with PC-relative fixups:

| ARM64 Instruction | Relocation Method |
|-------------------|-------------------|
| B / BL | → Absolute jump (LDR X17 + BR X17) |
| B.cond | → Invert condition skip + absolute jump |
| CBZ / CBNZ | → Same pattern |
| TBZ / TBNZ | → Same pattern |
| ADRP | → LDR Xd from literal pool |
| ADR | → LDR Xd from literal pool |
| LDR literal (all variants) | → Load address + indirect load |
| Other instructions | Direct copy (no relocation needed) |

ARM32 (ARM + Thumb) and x86/x86_64 relocators are also included.

#### 4. Hub Mechanism (Automatic Recursion Prevention)

Inspired by [ShadowHook](https://github.com/bytedance/android-inline-hook), the hub prevents infinite recursion when a proxy function indirectly re-enters the hooked function.

**Architecture (ARM64):**

The hub is an assembly template (`adl_hub_arm64.S`) compiled by the assembler for correct instruction encoding, then copied to `mmap`'d executable memory at runtime:

1. **Hub entry**: Saves all parameter registers (x0-x8, q0-q7, LR), calls `adl_hub_push()` in C
2. **Push logic**: Checks per-thread TLS frame stack — if `orig_addr` already present, it's recursive → return trampoline address; otherwise push frame → return proxy address
3. **Hub entry (cont)**: Restores all registers, sets LR to hub return address, jumps to decision result
4. **Proxy executes**: User code runs normally, any re-entrant calls go through hub again (detected as recursive)
5. **Hub return**: Proxy returns here, saves return values, calls `adl_hub_pop()`, restores return values, returns to original caller

**TLS Stack:**
- Pre-allocated pool of 128 thread stacks (lock-free atomic allocation)
- Each thread stack holds up to 16 recursion frames
- `pthread_key_t` for automatic cleanup on thread exit

#### 5. Thread-Safe Ordered Writes

Hook installation uses ordered writes with memory barriers to prevent crashes from concurrent execution:

1. Write target address (bytes 8-15) first
2. Memory barrier (`dmb ish` on ARM, `mfence` on x86)
3. Write jump instruction (bytes 0-7) — atomically activates the hook

Result: concurrent threads either execute complete old code or complete new hook, never partial/corrupted instructions.

## AndHooker API

```cpp
#include <adl_hook.h>

// --- PLT Hook ---
// Hook close() calls from libsample.so only
static int (*orig_close)(int) = NULL;
int my_close(int fd) {
    log("closing fd=%d", fd);
    return orig_close(fd);
}
adl_plt_hook("libsample.so", "close", my_close, &orig_close);
adl_plt_unhook("libsample.so", "close");

// --- Inline Hook ---
// Hook gettimeofday() globally (all callers affected)
static int (*orig_gettimeofday)(struct timeval*, struct timezone*) = NULL;
int my_gettimeofday(struct timeval *tv, struct timezone *tz) {
    int ret = orig_gettimeofday(tv, tz);  // call original
    if (ret == 0) tv->tv_sec += 86400;    // add 1 day
    return ret;
}
void *target = adlsym(adlopen("libc.so", 0), "gettimeofday");
adl_inline_hook(target, my_gettimeofday, (void**)&orig_gettimeofday);
adl_inline_unhook(target);
```

## Limitations and Best Practices

### Inline Hook: Return Value Modification

**Safe to modify return values for:**
- Low-frequency functions: `gettimeofday`, `localtime`, `atoi`, `access`, etc.
- Functions not called by system infrastructure (JIT, GC, malloc)

**Unsafe to modify return values for:**
- `strlen`, `memcpy`, `memset`, `malloc`, `free` — these are called by every thread including JIT/GC; modified return values corrupt heap
- Any IFUNC function with FORTIFY wrapper — `__strlen_chk` validates strlen's return

**For high-frequency global functions:**
- Use **PLT hook** (only affects one module) to safely modify return values
- Use **inline hook in observe-only mode** (transparent pass-through) for global interception
- Or hook the `__xxx_chk` FORTIFY wrapper directly (bypasses FORTIFY validation)

### FORTIFY Functions

Android's `_FORTIFY_SOURCE` replaces many libc functions with checked versions at compile time:

| Function | FORTIFY Wrapper | PLT Hook Target |
|----------|----------------|-----------------|
| `strlen` | `__strlen_chk` | `__strlen_chk` |
| `strcpy` | `__strcpy_chk` | `__strcpy_chk` |
| `memcpy` | `__memcpy_chk` | `__memcpy_chk` |
| `sprintf` | `__sprintf_chk` | `__sprintf_chk` |
| `snprintf` | `__vsnprintf_chk` | `__vsnprintf_chk` |
| `open` | `__open_2` | `__open_2` |

`adl_inline_hook` auto-detects FORTIFY wrappers at runtime. When you pass `strlen`'s address, the framework automatically hooks `__strlen_chk` instead, and `orig_func` returns the raw `strlen` pointer (matching the original signature).

### Short Functions

Functions shorter than 16 bytes (ARM64 hook size) cannot be safely inline hooked — the patch would overwrite adjacent functions. The framework detects this at runtime via `st_size` from the symbol table and **rejects the hook with an error** (`adl_inline_hook` returns -1). Examples: `atol` (12 bytes), `strptime` (8 bytes), `getopt_long_only` (8 bytes).

For short functions, use **PLT hook** instead (no size restriction since it only modifies a GOT pointer).

## Build

Requires Android NDK and CMake 3.10.2+.

```bash
# Build all modules
./gradlew assembleRelease

# Build individually
./gradlew :andlinker:assembleRelease
./gradlew :andhooker:assembleRelease
./gradlew :sample:assembleDebug
```
