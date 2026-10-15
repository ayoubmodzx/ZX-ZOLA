/*
 * stealth_ext7.cpp — ZX Anti-Detection Layers 54-57
 *
 * Layer 54 — getdents64 /proc/self/task thread hider
 *            AnoSDK calls opendir("/proc/self/task") + readdir64 (→ getdents64)
 *            to enumerate all threads in the process and inspect their stacks /
 *            comm names for injected .so paths. We hook getdents64 and strip
 *            any entry whose d_name is a pure decimal TID that matches one of
 *            our registered payload threads. No fd-tracking needed: if d_name
 *            is a number and it's ours, it's gone.
 *
 * Layer 55 — AnoSDKDelReportData / AnoSDKDelReportData2 nullifiers
 *            These exports acknowledge a successful report upload. Silencing them
 *            closes the fallback scan trigger path they contain and prevents any
 *            retry logic that might slip through Layer 3.
 *
 * Layer 56 — __system_property_get spoof
 *            AnoSDK reads ro.debuggable and ro.build.type to assess if the
 *            device is a debug build / rooted test device. We return clean
 *            production values so every environment looks like stock retail.
 *
 * Layer 57 — /proc/self/fd openat filter extension
 *            Extends the existing openat hook to cover /proc/self/fd/<n> paths:
 *            any fd whose readlink resolves to our payload name is quietly
 *            redirected to /dev/null, hiding the open handle from AnoSDK's
 *            fd-enumeration pass.
 */

#include "stealth_ext7.hpp"
#include "dobby_stub.hpp"
#include "anti_detect.hpp"

#include <android/log.h>
#include <dlfcn.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <pthread.h>
#include <atomic>

#ifndef ZX_RELEASE
#define LI(...) __android_log_print(ANDROID_LOG_INFO,  "ZX-ADET", __VA_ARGS__)
#define LE(...) __android_log_print(ANDROID_LOG_ERROR, "ZX-ADET", __VA_ARGS__)
#else
#define LI(...) ((void)0)
#define LE(...) ((void)0)
#endif

// ─────────────────────────────────────────────────────────────────────────────
// Layer 54 — TID registry + getdents64 thread hider
// ─────────────────────────────────────────────────────────────────────────────

static constexpr int MAX_OUR_TIDS = 64;
static pid_t         g_our_tids[MAX_OUR_TIDS];
static int           g_our_tid_count = 0;
static pthread_mutex_t g_tid_mu = PTHREAD_MUTEX_INITIALIZER;

void zx_register_tid(pid_t tid) {
    pthread_mutex_lock(&g_tid_mu);
    if (g_our_tid_count < MAX_OUR_TIDS)
        g_our_tids[g_our_tid_count++] = tid;
    pthread_mutex_unlock(&g_tid_mu);
}

static bool is_our_tid(pid_t tid) {
    if (tid <= 0) return false;
    pthread_mutex_lock(&g_tid_mu);
    bool found = false;
    for (int i = 0; i < g_our_tid_count && !found; i++)
        found = (g_our_tids[i] == tid);
    pthread_mutex_unlock(&g_tid_mu);
    return found;
}

// Portable dirent64 layout (matches kernel ABI on arm64)
struct zx_dirent64 {
    uint64_t d_ino;
    int64_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[1];
};

static bool name_is_decimal(const char *s) {
    if (!s || !*s) return false;
    for (; *s; s++)
        if (*s < '0' || *s > '9') return false;
    return true;
}

typedef long (*getdents64_fn)(unsigned int, void*, unsigned int);
static getdents64_fn orig_getdents64 = nullptr;

static long hook_getdents64(unsigned int fd, void *dirp, unsigned int count) {
    long ret = orig_getdents64 ? orig_getdents64(fd, dirp, count)
                               : (long)syscall(__NR_getdents64, fd, dirp, count);
    if (ret <= 0 || !dirp) return ret;

    char *buf  = (char*)dirp;
    char *end  = buf + ret;
    char *out  = buf;
    char *cur  = buf;

    while (cur < end) {
        auto *d = (zx_dirent64*)cur;
        if (!d->d_reclen) break;

        bool hide = false;
        if (name_is_decimal(d->d_name)) {
            pid_t tid = (pid_t)strtoull(d->d_name, nullptr, 10);
            hide = is_our_tid(tid);
        }

        if (!hide) {
            if (out != cur) memmove(out, cur, d->d_reclen);
            out += d->d_reclen;
        }
        cur += d->d_reclen;
    }
    return (long)(out - buf);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 55 — AnoSDKDelReportData / AnoSDKDelReportData2 nullifiers
// ─────────────────────────────────────────────────────────────────────────────

static int (*orig_DelData)(int)    = nullptr;
static int (*orig_DelData2)(int)   = nullptr;

static int hook_DelData(int id)    { (void)id; return 0; }
static int hook_DelData2(int id)   { (void)id; return 0; }

// ─────────────────────────────────────────────────────────────────────────────
// Layer 56 — __system_property_get spoof
// ─────────────────────────────────────────────────────────────────────────────

typedef int (*prop_get_fn)(const char*, char*);
static prop_get_fn orig_prop_get = nullptr;

static int hook_prop_get(const char *name, char *value) {
    if (!name || !value) return orig_prop_get ? orig_prop_get(name, value) : 0;

    if (strcmp(name, "ro.debuggable") == 0)       { strcpy(value, "0"); return 1; }
    if (strcmp(name, "ro.build.type") == 0)        { strcpy(value, "user"); return 4; }
    if (strcmp(name, "ro.secure") == 0)            { strcpy(value, "1"); return 1; }
    if (strcmp(name, "service.adb.root") == 0)     { strcpy(value, "0"); return 1; }
    if (strcmp(name, "ro.build.tags") == 0)        { strcpy(value, "release-keys"); return 12; }
    if (strcmp(name, "sys.usap_pool_enabled") == 0){ strcpy(value, "false"); return 5; }

    return orig_prop_get ? orig_prop_get(name, value) : 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 57 — /proc/self/fd openat filter
// ─────────────────────────────────────────────────────────────────────────────

static const uint8_t k_pay_xor7[] = {
    0x36, 0x33, 0x38, 0x20, 0x22, 0x05, 0x2A, 0x3B, 0x23, 0x36,
    0x35, 0x3B, 0x3E, 0x74, 0x29, 0x35, 0x00
};
static char s_pay7[32] = {};
static const uint8_t k_inj_xor7[] = {
    0x20, 0x22, 0x05, 0x33, 0x34, 0x30, 0x3F, 0x39, 0x2E, 0x35, 0x28, 0x00
};
static char s_inj7[32] = {};

static void decode7() {
    for (int i = 0; k_pay_xor7[i]; i++) s_pay7[i] = (char)(k_pay_xor7[i] ^ 0x5A);
    for (int i = 0; k_inj_xor7[i]; i++) s_inj7[i] = (char)(k_inj_xor7[i] ^ 0x5A);
}

typedef int (*openat_fn)(int, const char*, int, ...);
static openat_fn orig_openat7 = nullptr;

static int hook_openat7(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        __builtin_va_list ap;
        __builtin_va_start(ap, flags);
        mode = __builtin_va_arg(ap, mode_t);
        __builtin_va_end(ap);
    }

    if (path && strncmp(path, "/proc/self/fd/", 14) == 0) {
        char link[256];
        ssize_t r = readlink(path, link, sizeof(link) - 1);
        if (r > 0) {
            link[r] = '\0';
            if ((s_pay7[0] && strstr(link, s_pay7)) ||
                (s_inj7[0] && strstr(link, s_inj7))) {
                errno = ENOENT;
                return -1;
            }
        }
    }

    if (!orig_openat7) { errno = ENOSYS; return -1; }
    if (flags & O_CREAT) return orig_openat7(dirfd, path, flags, mode);
    return orig_openat7(dirfd, path, flags);
}

// ─────────────────────────────────────────────────────────────────────────────
// Public install
// ─────────────────────────────────────────────────────────────────────────────

void install_stealth_ext7() {
    decode7();
    // Pre-register our own main-thread TID
    zx_register_tid(gettid());

    // Layer 54 — getdents64 thread hider
    {
        void *fn = DobbySymbolResolver("libc.so", "getdents64");
        if (fn) {
            DobbyHook(fn, (void*)hook_getdents64, (void**)&orig_getdents64);
            LI("L54 getdents64 thread hider active");
        } else {
            LE("L54 getdents64 not found");
        }
    }

    // Layer 55 — DelReportData nullifiers
    {
        void *h = dlopen("libanogs.so", RTLD_LAZY | RTLD_NOLOAD);
        if (h) {
            auto hk = [&](const char *sym, void *rep, void **orig) {
                void *a = dlsym(h, sym);
                if (!a) {
                    char buf[128]; snprintf(buf, sizeof(buf), "%s@@ANO", sym);
                    a = dlsym(h, buf);
                }
                if (!a) a = DobbySymbolResolver("libanogs.so", sym);
                if (a) DobbyHook(a, rep, orig);
            };
            hk("AnoSDKDelReportData",  (void*)hook_DelData,  (void**)&orig_DelData);
            hk("AnoSDKDelReportData2", (void*)hook_DelData2, (void**)&orig_DelData2);
            LI("L55 DelReportData nullifiers installed");
        }
    }

    // Layer 56 — __system_property_get spoof
    {
        void *fn = DobbySymbolResolver("libc.so", "__system_property_get");
        if (!fn) fn = dlsym(RTLD_DEFAULT, "__system_property_get");
        if (fn) {
            DobbyHook(fn, (void*)hook_prop_get, (void**)&orig_prop_get);
            LI("L56 __system_property_get spoof active");
        } else {
            LE("L56 __system_property_get not found");
        }
    }

    // Layer 57 — /proc/self/fd openat filter (chained second hook)
    {
        void *fn = DobbySymbolResolver("libc.so", "openat");
        if (!fn) fn = dlsym(RTLD_DEFAULT, "openat");
        if (fn) {
            DobbyHook(fn, (void*)hook_openat7, (void**)&orig_openat7);
            LI("L57 /proc/self/fd openat filter active");
        } else {
            LE("L57 openat not found for fd filter");
        }
    }

    LI("Layers 54-57 installed OK");
}
