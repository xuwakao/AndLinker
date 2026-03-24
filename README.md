# AndLinker

Android linker bypass library — access private/internal symbols in system shared libraries (`.so`) by bypassing linker namespace restrictions.

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

// Resolve a versioned symbol
void *sym_v = adlvsym(handle, "symbol_name", "LIBC");

// Get symbol info by address
Dl_info info;
adladdr(some_addr, &info);

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

## How It Works

AndLinker parses ELF binary structures directly from memory and files to resolve symbols that the standard `dlsym` cannot access due to Android's linker namespace restrictions (introduced in Android 7.0). It supports both ELF hash and GNU hash tables for symbol lookup, and falls back to `.symtab` section scanning for symbols not in `.dynsym`.

For `dlopen` on restricted Android versions (7.0+), it locates the linker's internal `dlopen` implementation and calls it directly with a fake caller address to bypass the namespace checks.
