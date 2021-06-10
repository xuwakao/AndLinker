//
// Created by P7XXTM1-G on 5/20/2021.
//

#ifndef ANDLINKER_ADL_UTIL_H
#define ANDLINKER_ADL_UTIL_H

#include <sys/cdefs.h>
#include <android/log.h>
#include <stdio.h>
#include <sys/user.h>
#include <android/api-level.h>
#include <sys/stat.h>
#include <string.h>
#include <link.h>

//#define NO_LOG
#define TAG "adl"
#ifndef NO_LOG
#define ADLOGI(...) __android_log_print(ANDROID_LOG_INFO,TAG,__VA_ARGS__)
#define ADLOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define ADLOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define ADLOGE(...) __android_log_print(ANDROID_LOG_ERROR,TAG,__VA_ARGS__)
#else
#define ADLOGI(...)
#define ADLOGD(...)
#define ADLOGW(...)
#define ADLOGE(...)
#endif

// Returns the address of the page containing address 'x'.
#define PAGE_START(x) ((x) & PAGE_MASK)

// Returns the offset of address 'x' in its page.
#define PAGE_OFFSET(x) ((x) & ~PAGE_MASK)

// Returns the address of the next page after address 'x', unless 'x' is
// itself at the start of a page.
#define PAGE_END(x) PAGE_START((x) + (PAGE_SIZE-1))

#define ADL_FLAG_NEW_SOINFO       0x40000000 // new soinfo format

#define ADL_FLAG_GNU_HASH         0x00000040 // uses gnu hash
#define ADL_FLAG_PRELINKED        0x00000400 // prelink_image has successfully processed this soinfo

// Android uses RELA for LP64.
#if defined(__LP64__)
#define ADL_USE_RELA 1
#endif


constexpr ElfW(Versym) ADL_kVersymNotNeeded = 0;
constexpr ElfW(Versym) ADL_kVersymGlobal = 1;


__BEGIN_DECLS

static int adl_get_api_level(void) {
    static int api_level = -1;
    if (api_level < 0) {
        api_level = android_get_device_api_level();
    }
    return api_level;
}

static inline bool adl_ends_with(const char *s1, const char *s2) {
    size_t s1_length = strlen(s1);
    size_t s2_length = strlen(s2);
    if (s2_length > s1_length) {
        return false;
    }
    return memcmp(s1 + (s1_length - s2_length), s2, s2_length) == 0;
}

// Checks if the file exists and not a directory.
static bool adl_file_exists(const char *path) {
    struct stat s;

    if (stat(path, &s) != 0) {
        return false;
    }

    return S_ISREG(s.st_mode);
}

constexpr off64_t kPageMask = ~static_cast<off64_t>(PAGE_SIZE - 1);
static off64_t adl_page_start(off64_t offset) {
    return offset & kPageMask;
}

static bool adl_safe_add(off64_t *out, off64_t a, size_t b) {
    if (static_cast<uint64_t>(INT64_MAX - a) < b) {
        return false;
    }

    *out = a + b;
    return true;
}

static size_t adl_page_offset(off64_t offset) {
    return static_cast<size_t>(offset & (PAGE_SIZE - 1));
}

static bool adl_realpath_fd(int fd, const char *realpath) {
    // proc_self_fd needs to be large enough to hold "/proc/self/fd/" plus an
    // integer, plus the NULL terminator.
    char proc_self_fd[32];
    // We want to statically allocate this large buffer so that we don't grow
    // the stack by too much.
    static char buf[PATH_MAX];

    snprintf(proc_self_fd, sizeof(proc_self_fd), "/proc/self/fd/%d", fd);
    auto length = readlink(proc_self_fd, buf, sizeof(buf));
    if (length == -1) {
        return false;
    }

    memcpy((void *) realpath, buf, length);
    return true;
}

__END_DECLS

#endif //ANDLINKER_ADL_UTIL_H

