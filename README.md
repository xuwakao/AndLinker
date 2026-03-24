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

## Build

Requires Android NDK and CMake 3.10.2+.

```bash
./gradlew :andlinker:assembleRelease
```
