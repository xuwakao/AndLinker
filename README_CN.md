*其他语言: [English](README.md), [中文](README_CN.md)*

# AndLinker

Android linker 绕过库 —— 突破 linker namespace 限制，访问系统共享库（`.so`）中的私有/内部符号。

## 为什么需要

从 Android 7.0 (Nougat) 开始，系统 linker 实施了**基于命名空间的库隔离**。应用无法再通过 `dlopen`/`dlsym` 访问 `libc.so`、`libart.so`、`linker64` 等系统库中的私有符号。即使符号存在于 ELF 二进制中，`dlsym` 也返回 `NULL`。

这限制了以下合法场景：

- **性能分析** —— 访问 ART 内部结构以检查方法执行
- **安全研究** —— 在 native 层分析系统行为
- **兼容性适配** —— 调用没有公开替代方案的私有 API
- **逆向工程** —— 理解系统库行为用于调试

AndLinker 恢复对任意已加载 `.so` 文件中**所有**符号的访问，不受 linker namespace 限制。

## 实现原理

### 库加载（绕过 `dlopen`）

Android 7.0+ 的标准 `dlopen` 会检查调用者的命名空间，拒绝加载不在允许列表中的库。AndLinker 通过以下方式绕过：

1. **定位 linker 内部的 `dlopen` 函数** —— 使用 `adlsym` 在 linker 二进制中查找 `__loader_dlopen`（API 28+）、`__dl__Z9do_dlopenPKciPK17android_dlextinfoPv`（API 24-27）等符号
2. **使用伪造的调用者地址调用** —— linker 根据调用者地址判断其所属命名空间；传入 `libc` 中的地址（属于系统命名空间），即可绕过限制
3. **回退到标准 `dlopen`** —— 如果绕过失败（如未来 Android 版本变更），优雅降级

### 符号解析（绕过 `dlsym`）

标准 `dlsym` 仅搜索 `.dynsym`（动态符号表）且遵循命名空间可见性。AndLinker 实现了三级符号查找：

1. **哈希表查找** —— 解析动态段中的 `DT_GNU_HASH` 或 `DT_HASH`，在 `.dynsym` 中进行 O(1) 查找（与系统 linker 相同的算法，但不做命名空间过滤）
2. **`.dynsym` 线性扫描** —— 哈希查找失败时，遍历动态符号表
3. **`.symtab` 文件扫描** —— 通过 `mmap` 读取 ELF 文件中的完整符号表，包含不在 `.dynsym` 中的静态/局部符号（这些就是标准 `dlsym` 完全不可见的"私有"符号）

### 模糊符号匹配

C++ mangled 名称（如 `_ZN3art9ArtMethod12PrettyMethodEb`）在不同 Android 版本间可能变化（编译器版本、重载、参数类型不同）。`adlsym_match` 通过以下方式解决：

1. 先尝试精确匹配
2. 使用 `__cxa_demangle` 还原每个符号（如 → `art::ArtMethod::PrettyMethod(bool)`），然后对还原后的名称做子串匹配
3. 回退到原始 mangled 名称子串匹配

这允许使用可读的模式搜索，如 `"ArtMethod::PrettyMethod"` 而非精确的 mangled 名称。

### 线程安全

所有公开 API 由递归互斥锁保护，确保多线程安全并发访问。

## 功能

- `adlopen` / `adlclose` —— 打开和关闭共享库，绕过 Android 7.0+ 的 linker 限制
- `adlsym` —— 解析符号（包括私有/内部符号）
- `adlvsym` —— 解析带版本的符号（Android 7.0+）
- `adlsym_match` —— 模糊符号查找，支持 `__cxa_demangle`（按 C++ 可读名称搜索）
- `adladdr` —— 根据地址获取符号信息（类似 `dladdr`）
- `adlerror` —— 获取最后一次错误信息（类似 `dlerror`）
- `adl_iterate_phdr` —— 遍历所有已加载库的程序头
- `adl_enum_symbols` —— 枚举库中的所有符号（.dynsym + .symtab）

## 兼容性

- **最低 SDK**: API 21 (Android 5.0)
- **目标 SDK**: API 34 (Android 14)
- **架构**: armeabi-v7a, arm64-v8a, x86, x86_64
- **已测试**: Android 6.0 — 16 (API 23 — 36)

## 使用方法

### 集成

将模块添加到项目并声明依赖：

```gradle
dependencies {
    implementation project(':andlinker')   // 符号解析、linker 绕过
    implementation project(':andhooker')   // PLT hook + inline hook（依赖 andlinker）
}
```

### API

```cpp
#include <adl.h>

// 打开库（支持全路径和 basename）
void *handle = adlopen("libc.so", 0);

// 解析私有符号
void *sym = adlsym(handle, "__openat");

// 模糊匹配 demangle 后的 C++ 名称
void *sym2 = adlsym_match(handle, "ArtMethod::PrettyMethod", NULL, NULL);

// 解析带版本的符号
void *sym_v = adlvsym(handle, "symbol_name", "LIBC");

// 枚举所有符号
adl_enum_symbols(handle, [](const char *name, void *addr, size_t size,
                             int type, void *arg) -> int {
    // 处理每个符号
    return 0; // 0 = 继续，非零 = 停止
}, NULL);

// 根据地址获取符号信息
Dl_info info;
adladdr(some_addr, &info);

// 检查错误
if (sym == NULL) {
    const char *err = adlerror(); // 返回错误信息并清除
}

// 遍历已加载的库
adl_iterate_phdr(callback, user_data);

// 关闭句柄
adlclose(handle);
```

---

# AndHooker

`andhooker` 是配套模块，基于 AndLinker 的符号解析能力提供 **PLT/GOT hook** 和 **inline hook** 功能。

## Hook 类型

### PLT/GOT Hook

PLT hook 通过修改 GOT（全局偏移表）条目，拦截**特定库**中的函数调用。

```
应用调用 strlen()
  → libsample.so 中的 PLT 桩
    → GOT 条目（原本指向 libc strlen）
      → [已 HOOK] GOT 条目现在指向你的代理函数
        → 代理函数通过保存的指针调用原始函数
```

**特点：**
- 仅影响指定库的调用（其他库仍调用原始函数）
- 对高频函数安全（strlen、memcpy 等）—— 仅影响一个模块
- 可修改参数、返回值或阻断调用
- 无需指令重定位 —— 只是指针替换

### Inline Hook

Inline hook 直接修改**函数入口**，影响整个进程中的**所有调用者**。

```
任何代码调用 gettimeofday()
  → 函数入口（前 16 字节被替换为跳转）
    → Hub 汇编跳板
      → 检查 TLS 递归状态
        → 首次调用：跳转到代理函数
        → 递归调用：跳转到原始函数（通过 trampoline）
    → 代理函数执行，通过 trampoline 调用原始函数
    → Hub 尾声：弹出递归状态，返回给调用者
```

**特点：**
- 影响进程中的所有调用者（全局拦截）
- 指令重定位引擎处理 trampoline 中的 PC 相对指令
- Hub 机制提供自动递归防护（无需用户代码）
- FORTIFY 自动检测：框架检测 `__xxx_chk` 包装函数并自动调整目标

## 实现原理

### PLT Hook 实现

1. `adlopen(caller_lib)` → 通过 `adl_prelink_image` 解析动态段
2. 遍历 `.rela.plt` / `.rel.plt` 条目查找目标符号
3. 计算 GOT 条目地址：`load_bias + relocation.r_offset`
4. `mprotect` 修改 GOT 页为可写 → 写入新函数指针 → 恢复页保护
5. 保存原始指针用于 unhook 和 `orig_func` 回调

### Inline Hook 实现

#### 1. FORTIFY 自动检测

当用户 hook `strlen` 时，框架会：
1. 通过 `adladdr` 反查符号名
2. 检查同一库中是否存在 `__strlen_chk`（模式：`__<name>_chk` 或 `__<name>_2`）
3. 如果找到，hook FORTIFY 包装函数；`orig_func` 指向原始函数

这防止了 FORTIFY 中止：`__strlen_chk` 会验证 strlen 的返回值，直接 hook 原始 strlen 并修改返回值会触发安全检查。hook `__strlen_chk` 则绕过了这个检查。

#### 2. BTI（分支目标识别）处理

ARM64 安全特性：CPU 验证跳转目标是否有 BTI 指令。如果函数以 `HINT #34`（BTI）开头，hook 在 BTI 指令**之后**打补丁，trampoline 入口也包含 BTI。

#### 3. 指令重定位

目标函数的前 16 字节被跳转指令覆盖。原始指令被移到 trampoline 中并修复 PC 相对寻址：

| ARM64 指令 | 重定位方式 |
|-----------|-----------|
| B / BL | → 绝对跳转 (LDR X17 + BR X17) |
| B.cond | → 反转条件跳过 + 绝对跳转 |
| CBZ / CBNZ | → 同上 |
| TBZ / TBNZ | → 同上 |
| ADRP | → 从字面量池 LDR Xd |
| ADR | → 从字面量池 LDR Xd |
| LDR literal（所有变体） | → 加载地址 + 间接加载 |
| 其他指令 | 直接拷贝（无需重定位） |

同时包含 ARM32（ARM + Thumb）和 x86/x86_64 的重定位器。

#### 4. Hub 机制（自动递归防护）

Hub 防止代理函数间接重入被 hook 的函数时产生无限递归。

**架构（ARM64）：**

Hub 是一个汇编模板（`adl_hub_arm64.S`），由汇编器编译以确保指令编码正确，运行时拷贝到 `mmap` 分配的可执行内存中：

1. **Hub 入口**：保存所有参数寄存器（x0-x8, q0-q7, LR），调用 C 函数 `adl_hub_push()`
2. **Push 逻辑**：检查线程局部 TLS frame 栈 —— 如果 `orig_addr` 已存在则为递归 → 返回 trampoline 地址；否则 push frame → 返回代理地址
3. **Hub 入口（续）**：恢复所有寄存器，设置 LR 为 hub return 地址，跳转到决策结果
4. **代理执行**：用户代码正常运行，任何重入调用再次经过 hub（被检测为递归）
5. **Hub 返回**：代理返回到此处，保存返回值，调用 `adl_hub_pop()`，恢复返回值，返回给原始调用者

**TLS 栈：**
- 预分配 128 个线程栈池（无锁原子分配）
- 每个线程栈最多 16 层递归帧
- `pthread_key_t` 用于线程退出时自动清理

**共享 Hub 页：**
- 多个 hub slot 共享一个 4KB mmap 页（每个 slot 256 字节，每页 16 个 slot）
- 内存从每 hook 4KB 降低到约 256 字节

> **注意：** Hub 目前仅支持 ARM64。在 ARM32/x86/x86_64 上，inline hook 回退到直接跳转代理函数，无自动递归防护。

#### 6. 多 Hook 支持

同一函数可以被多次 hook，每次 hook 添加一个 proxy 到链中：

```
函数入口 → hub → proxy_C（最新）
                   ↓ orig_C 调用
                 proxy_B
                   ↓ orig_B 调用
                 proxy_A（最早）
                   ↓ orig_A 调用
                 trampoline → 原始函数
```

对已 hook 的函数再次调用 `adl_inline_hook` 会将新 proxy 插入链表头部。返回给每个调用者的 `orig_func` 指向链中的下一个 proxy（或第一个 hook 的 trampoline）。

#### 7. 重入控制

默认情况下，hub 阻止递归调用以防止无限循环。对于需要合法递归的场景（如线程池、递归算法），可以按 hook 点启用重入模式：

```cpp
adl_inline_hook(target, my_proxy, &orig);
adl_inline_hook_allow_reentrant(target);   // 递归调用也走 proxy
adl_inline_hook_disallow_reentrant(target); // 恢复默认（阻止递归）
```

#### 5. 线程安全的有序写入

Hook 安装使用有序写入配合内存屏障，防止并发执行导致崩溃：

1. 先写入目标地址（字节 8-15）
2. 内存屏障（ARM 上 `dmb ish`，x86 上 `mfence`）
3. 写入跳转指令（字节 0-7）—— 原子激活 hook

效果：并发线程要么执行完整的旧代码，要么执行完整的新 hook，不会执行部分/损坏的指令。

## AndHooker API

```cpp
#include <adl_hook.h>

// --- PLT Hook ---
// 仅 hook libsample.so 中的 close() 调用
static int (*orig_close)(int) = NULL;
int my_close(int fd) {
    log("closing fd=%d", fd);
    return orig_close(fd);
}
adl_plt_hook("libsample.so", "close", my_close, &orig_close);
adl_plt_unhook("libsample.so", "close");

// --- Inline Hook ---
// 全局 hook gettimeofday()（所有调用者受影响）
static int (*orig_gettimeofday)(struct timeval*, struct timezone*) = NULL;
int my_gettimeofday(struct timeval *tv, struct timezone *tz) {
    int ret = orig_gettimeofday(tv, tz);  // 调用原始函数
    if (ret == 0) tv->tv_sec += 86400;    // 加 1 天
    return ret;
}
void *target = adlsym(adlopen("libc.so", 0), "gettimeofday");
adl_inline_hook(target, my_gettimeofday, (void**)&orig_gettimeofday);
adl_inline_unhook(target);
```

## 限制与最佳实践

### Inline Hook：返回值修改

**可以安全修改返回值的：**
- 低频函数：`gettimeofday`、`localtime`、`atoi`、`access` 等
- 不被系统基础设施（JIT、GC、malloc）调用的函数

**不安全的（通过原始函数 inline hook）：**
- `strlen`、`memcpy`、`memset`、`malloc`、`free` —— 被所有线程（包括 JIT/GC）调用；修改返回值会在整个进程中导致堆损坏
- 注意：直接 hook `__strlen_chk` **是安全的**，因为你替换了 FORTIFY 检查本身

**对于高频全局函数：**
- 使用 **PLT hook**（仅影响一个模块）安全地修改返回值
- 使用 **inline hook 观察模式**（透明传递）进行全局拦截
- 或直接 hook `__xxx_chk` FORTIFY 包装函数（绕过 FORTIFY 校验）

### FORTIFY 函数

Android 的 `_FORTIFY_SOURCE` 在编译时将许多 libc 函数替换为带检查的版本：

| 函数 | FORTIFY 包装 | PLT Hook 目标 |
|------|-------------|--------------|
| `strlen` | `__strlen_chk` | `__strlen_chk` |
| `strcpy` | `__strcpy_chk` | `__strcpy_chk` |
| `memcpy` | `__memcpy_chk` | `__memcpy_chk` |
| `sprintf` | `__sprintf_chk` | `__sprintf_chk` |
| `snprintf` | `__vsnprintf_chk` | `__vsnprintf_chk` |
| `open` | `__open_2` | `__open_2` |

`adl_inline_hook` 运行时自动检测 FORTIFY 包装函数。当传入 `strlen` 的地址时，框架自动 hook `__strlen_chk`，`orig_func` 返回原始 `strlen` 指针（匹配原始签名）。

### 短函数

ARM64 inline hook 在函数入口覆盖 16 字节。短于 16 字节的函数（如 `atol` 12 字节、`strptime` 8 字节、`getopt_long_only` 8 字节）有覆盖相邻函数的风险。

**实际上**，ARM64 编译器将函数入口对齐到 16 字节边界，因此短函数后面跟着填充字节（`udf #0` 或 `nop`）。这使得溢出落在填充上而非真实代码。测试确认 `atol`（12 字节 + 4 字节填充）可以成功 hook。

**但是**，框架保守地**拒绝**短函数的 inline hook（`adl_inline_hook` 返回 -1），因为：
- 自定义 `.so` 文件或非标准链接脚本可能没有 16 字节对齐
- 不同编译器或优化级别可能消除填充
- 安全优先于依赖对齐假设

对于短函数，使用 **PLT hook**（无大小限制 —— 只修改 GOT 指针）。

## 许可证

MIT 许可证。详见 [LICENSE](LICENSE)。

## 构建

需要 Android NDK 和 CMake 3.10.2+。

```bash
# 构建所有模块
./gradlew assembleRelease

# 单独构建
./gradlew :andlinker:assembleRelease
./gradlew :andhooker:assembleRelease
./gradlew :sample:assembleDebug
```
