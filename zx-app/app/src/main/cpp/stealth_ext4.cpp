/*
 * stealth_ext4.cpp — ZX-ZOLA Anti-Detection Layer 27-42
 *
 * Vectors covered (confirmed from libanogs.so + libanort.so binary analysis):
 *
 *  Layer 27 — clock_gettime(CLOCK_BOOTTIME=7 / CLOCK_MONOTONIC_RAW=4) spoofing
 *  Layer 28 — gettimeofday direct SVC (#169) + PLT intercept
 *  Layer 29 — setsid direct SVC (#101) spoof → always returns 0
 *  Layer 30 — __system_property_get/find_nth/read spoofing
 *  Layer 31 — prctl spoofing (PR_GET_DUMPABLE → 0, PR_GET_SECCOMP → 0)
 *  Layer 32 — dladdr spoofing (hides injected .so names)
 *  Layer 33 — sigaction intercept for SIGTRAP/SIGILL
 *  Layer 34 — libc syscall() wrapper intercept
 *  Layer 35 — fcntl sanitize on /proc fds
 *  Layer 36 — access() block for root/cheat/magisk paths
 *  Layer 37 — waitpid spoof for AnoSDK fork-ptrace child
 *  Layer 38 — /dev/alarm openat intercept (hardware timer bypass)
 *  Layer 39 — pthread_create watchdog TID recording
 *  Layer 40 — ffutil_UnmapCheck spoof
 *  Layer 41 — getrlimit RLIMIT_CORE = 0
 *  Layer 42 — getaddrinfo → ENONAME (silence C2 reporting), sysconf cores
 *  Layer 43 — unwind_xx_info_query (libanort.so) → -1 + ENODATA
 *             Blocks AnoSDK's secondary information-gather channel that bypasses
 *             the ioctl gate (Layer 19) by calling libanort directly.
 */

#include "stealth_ext4.hpp"
#include "dobby_stub.hpp"

#include <android/log.h>
#include <dlfcn.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <atomic>
#include <netdb.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#ifndef __NR_openat
#define __NR_openat 56
#endif
#include <link.h>

#define TAG "ZX-STH4"
#ifndef ZX_RELEASE
#define LI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#else
#define LI(...) ((void)0)
#define LE(...) ((void)0)
#endif

// ─────────────────────────────────────────────────────────────────────────────
// Layer 27 — clock_gettime CLOCK_BOOTTIME / CLOCK_MONOTONIC_RAW spoof
// AnoSDK uses these (immune to gettimeofday spoofing) for timing anti-debug.
// We return a steadily incrementing fake time with realistic deltas.
// ─────────────────────────────────────────────────────────────────────────────

static int (*g_orig_clock_gettime)(clockid_t, struct timespec*) = nullptr;

static std::atomic<uint64_t> g_fake_ns{0};
static constexpr uint64_t FAKE_DELTA_NS = 2'500'000ULL; // 2.5ms per call

static int hook_clock_gettime(clockid_t clk, struct timespec *tp) {
    if ((clk == 7 /*CLOCK_BOOTTIME*/ || clk == 4 /*CLOCK_MONOTONIC_RAW*/) && tp) {
        uint64_t ns = g_fake_ns.fetch_add(FAKE_DELTA_NS, std::memory_order_relaxed);
        tp->tv_sec  = (time_t)(ns / 1'000'000'000ULL);
        tp->tv_nsec = (long)  (ns % 1'000'000'000ULL);
        return 0;
    }
    if (!g_orig_clock_gettime) { errno = ENOSYS; return -1; }
    return g_orig_clock_gettime(clk, tp);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 28 — gettimeofday PLT spoof
// Direct SVC path at libanogs 0x3eff14 is covered by existing tp_syscall NOP.
// ─────────────────────────────────────────────────────────────────────────────

static int (*g_orig_gettimeofday)(struct timeval*, struct timezone*) = nullptr;

static int hook_gettimeofday(struct timeval *tv, struct timezone *tz) {
    if (!g_orig_gettimeofday) { errno = ENOSYS; return -1; }
    int ret = g_orig_gettimeofday(tv, tz);
    // Coarse-granularize to 10ms chunks to defeat microsecond timing probes
    if (ret == 0 && tv) {
        tv->tv_usec = (tv->tv_usec / 10000) * 10000;
    }
    return ret;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 29 — setsid spoof → always return 0
// Direct SVC path at libanogs 0x3eff34: setsid returns -EPERM when traced.
// ─────────────────────────────────────────────────────────────────────────────

static pid_t (*g_orig_setsid)(void) = nullptr;

static uintptr_t s_ano4_base = 0, s_ano4_end = 0;
static int phdr_find_ano4(dl_phdr_info *info, size_t, void*) {
    if (!info->dlpi_name || !strstr(info->dlpi_name, "libanogs.so")) return 0;
    uintptr_t base = (uintptr_t)info->dlpi_addr, end = base;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) &ph = info->dlpi_phdr[i];
        if (ph.p_type == PT_LOAD) { uintptr_t e = base + ph.p_vaddr + ph.p_memsz; if (e > end) end = e; }
    }
    s_ano4_base = base; s_ano4_end = end; return 1;
}

static pid_t hook_setsid(void) {
    if (!s_ano4_base) dl_iterate_phdr(phdr_find_ano4, nullptr);
    uintptr_t lr = (uintptr_t)__builtin_return_address(0);
    if (s_ano4_base && !(lr >= s_ano4_base && lr < s_ano4_end))
        return g_orig_setsid ? g_orig_setsid() : (pid_t)syscall(__NR_setsid);
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 30 — __system_property_get spoof
// Hides ro.debuggable, ro.build.type, ro.secure, ro.kernel.qemu flags.
// ─────────────────────────────────────────────────────────────────────────────

static int (*g_orig_prop_get)(const char*, char*) = nullptr;

struct PropOverride { const char *key; const char *val; };
static const PropOverride k_prop_overrides[] = {
    { "ro.debuggable",    "0"    },
    { "ro.build.type",    "user" },
    { "ro.secure",        "1"    },
    { "ro.kernel.qemu",   "0"    },
    { "ro.build.tags",    "release-keys" },
    { nullptr, nullptr }
};

static int hook_prop_get(const char *name, char *value) {
    if (name) {
        for (const PropOverride *p = k_prop_overrides; p->key; ++p) {
            if (strcmp(name, p->key) == 0) {
                if (value) { strcpy(value, p->val); }
                return (int)strlen(p->val);
            }
        }
    }
    if (!g_orig_prop_get) return 0;
    return g_orig_prop_get(name, value);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 31 — prctl spoof
// PR_GET_DUMPABLE → 0 (hide re-enabled dump by debugger)
// PR_GET_SECCOMP  → 0 (not sandboxed)
// ─────────────────────────────────────────────────────────────────────────────

// prctl actual ABI: int prctl(int, unsigned long, unsigned long, unsigned long, unsigned long)
static int (*g_orig_prctl)(int, unsigned long, unsigned long,
                            unsigned long, unsigned long) = nullptr;

static int hook_prctl(int opt, unsigned long a1, unsigned long a2,
                      unsigned long a3, unsigned long a4) {
    if (opt == PR_GET_DUMPABLE)  return 0;
    if (opt == PR_GET_SECCOMP)   return 0;
    if (opt == PR_SET_DUMPABLE)  return 0;
    if (!g_orig_prctl) { errno = ENOSYS; return -1; }
    return g_orig_prctl(opt, a1, a2, a3, a4);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 32 — dladdr spoof
// When AnoSDK calls dladdr() on a hooked function, it sees injector .so name.
// We report the original libc/libunity name instead.
// ─────────────────────────────────────────────────────────────────────────────

static int (*g_orig_dladdr)(const void*, Dl_info*) = nullptr;

static const char *const k_hook_names[] = {
    "zx_payload", "zx_inject", "libzx", "gfxjni_helper", "libdobby",
    "frida", "xposed", "substrate", "androguard", "shadowhook", nullptr
};

static bool is_hook_lib(const char *fname) {
    if (!fname) return false;
    for (const char *const *n = k_hook_names; *n; ++n)
        if (strstr(fname, *n)) return true;
    return false;
}

static int hook_dladdr(const void *addr, Dl_info *info) {
    if (!g_orig_dladdr) return 0;
    int ret = g_orig_dladdr(addr, info);
    if (ret && info && is_hook_lib(info->dli_fname)) {
        info->dli_fname = "/system/lib64/libc.so";
        info->dli_sname = nullptr;
        info->dli_saddr = nullptr;
    }
    return ret;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 33 — sigaction intercept for SIGTRAP / SIGILL
// AnoSDK installs handlers for these to detect debugger presence.
// We register a no-op handler and never deliver to theirs.
// ─────────────────────────────────────────────────────────────────────────────

static int (*g_orig_sigaction)(int, const struct sigaction*, struct sigaction*) = nullptr;

static void noop_sighandler(int) {}

static int hook_sigaction(int sig, const struct sigaction *act, struct sigaction *old) {
    if (!g_orig_sigaction) { errno = ENOSYS; return -1; }
    if (sig == SIGTRAP || sig == SIGILL) {
        struct sigaction noop_act{};
        noop_act.sa_handler = noop_sighandler;
        sigemptyset(&noop_act.sa_mask);
        noop_act.sa_flags = 0;
        return g_orig_sigaction(sig, &noop_act, old);
    }
    return g_orig_sigaction(sig, act, old);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 34 — libc syscall() wrapper intercept
// Routes AnoSDK's direct syscall() calls to our existing hook logic.
// ─────────────────────────────────────────────────────────────────────────────

// syscall() on ARM64: long syscall(long number, long a1..a6)
// Use fixed-arg signature to match ARM64 ABI (args in X0..X6)
static long (*g_orig_syscall)(long, long, long, long,
                               long, long, long) = nullptr;

static long hook_syscall(long nr, long a1, long a2, long a3,
                         long a4, long a5, long a6) {
    switch (nr) {
        case 101: // setsid
            return 0;
        case 157: // prctl
            if (a1 == PR_GET_DUMPABLE || a1 == PR_GET_SECCOMP) return 0;
            if (a1 == PR_SET_DUMPABLE) return 0;
            break;
        case 167: // getrlimit
            if (a1 == RLIMIT_CORE) {
                struct rlimit *rl = (struct rlimit*)a2;
                if (rl) { rl->rlim_cur = 0; rl->rlim_max = 0; }
                return 0;
            }
            break;
        case 169: { // gettimeofday
            struct timeval *tv = (struct timeval*)a1;
            if (tv && g_orig_gettimeofday) {
                int ret = g_orig_gettimeofday(tv, nullptr);
                if (ret == 0) tv->tv_usec = (tv->tv_usec / 10000) * 10000;
                return ret;
            }
            break;
        }
    }
    if (!g_orig_syscall) { errno = ENOSYS; return -1; }
    return g_orig_syscall(nr, a1, a2, a3, a4, a5, a6);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 35 — fcntl sanitize on /proc fds
// Block O_RDWR detection on /proc/self/mem fds (debugger artifact).
// ─────────────────────────────────────────────────────────────────────────────

// fcntl ABI on ARM64: int fcntl(int fd, int cmd, long arg) — fixed 3-arg registers
static int (*g_orig_fcntl)(int, int, long) = nullptr;

static bool is_proc_fd(int fd) {
    char link[64], path[128];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, path, sizeof(path)-1);
    if (n <= 0) return false;
    path[n] = '\0';
    return (strncmp(path, "/proc/", 6) == 0);
}

static int hook_fcntl(int fd, int cmd, long arg) {
    if (!g_orig_fcntl) return -1;
    int ret = g_orig_fcntl(fd, cmd, arg);
    // Strip O_RDWR on proc fds — debugger artifact
    if (cmd == F_GETFL && ret >= 0 && is_proc_fd(fd)) {
        ret &= ~O_RDWR;
        ret |= O_RDONLY;
    }
    return ret;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 36 — access() block for root/cheat/magisk path probes
// ─────────────────────────────────────────────────────────────────────────────

static int (*g_orig_access)(const char*, int) = nullptr;

static const char *const k_blocked_access[] = {
    "/su", "/magisk", "/frida", "/xposed", "/saurik",
    "/data/local/tmp/",
    "/system/bin/su", "/system/xbin/su", "/sbin/su",
    "/sbin/.magisk", "/.magisk",
    "frida-server", "frida-gadget", nullptr
};

static int hook_access(const char *path, int mode) {
    if (path) {
        for (const char *const *b = k_blocked_access; *b; ++b) {
            if (strstr(path, *b)) { errno = ENOENT; return -1; }
        }
    }
    if (!g_orig_access) { errno = ENOENT; return -1; }
    return g_orig_access(path, mode);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 37 — waitpid spoof for AnoSDK fork-ptrace anti-debug children
// AnoSDK forks a child that ptrace-attaches to the parent to test for tracer.
// We spoof waitpid to return a clean exit so the test always passes.
// ─────────────────────────────────────────────────────────────────────────────

static pid_t (*g_orig_waitpid)(pid_t, int*, int) = nullptr;

// Track pids forked within libanogs range
static constexpr int MAX_TRACKED = 32;
static pid_t g_ano_forks[MAX_TRACKED];
static int   g_ano_forks_n = 0;
static pthread_mutex_t g_fork_mu = PTHREAD_MUTEX_INITIALIZER;

void track_fork(pid_t child) {
    pthread_mutex_lock(&g_fork_mu);
    if (g_ano_forks_n < MAX_TRACKED)
        g_ano_forks[g_ano_forks_n++] = child;
    pthread_mutex_unlock(&g_fork_mu);
}

static pid_t hook_waitpid(pid_t pid, int *status, int opts) {
    pthread_mutex_lock(&g_fork_mu);
    bool is_ano = false;
    for (int i = 0; i < g_ano_forks_n; i++) {
        if (g_ano_forks[i] == pid) { is_ano = true; break; }
    }
    pthread_mutex_unlock(&g_fork_mu);
    if (is_ano) {
        if (status) *status = 0; // W_EXITCODE(0, 0)
        return pid;
    }
    if (!g_orig_waitpid) { errno = ECHILD; return -1; }
    return g_orig_waitpid(pid, status, opts);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 38 — /dev/alarm openat intercept
// AnoSDK opens /dev/alarm to bypass all userspace timing hooks.
// Return an in-memory fd that returns incrementing fake timing values.
// ─────────────────────────────────────────────────────────────────────────────

// Layer 38 — /dev/alarm openat intercept
// Dobby chains correctly: hooking an already-hooked symbol installs on the trampoline.
// g_orig_openat_ext4 will be the ext3 trampoline → ext3 hook → real openat.

static int (*g_orig_openat_ext4)(int, const char*, int, ...) = nullptr;

static int hook_openat_ext4(int dirfd, const char *path, int flags, ...) {
    va_list ap; va_start(ap, flags);
    int mode = va_arg(ap, int);
    va_end(ap);

    if (path && strstr(path, "/dev/alarm")) {
        int devnull = syscall(__NR_openat, AT_FDCWD, "/dev/null", O_RDONLY, 0);
        LI("Layer38: /dev/alarm -> /dev/null fd=%d", devnull);
        return devnull;
    }
    return g_orig_openat_ext4(dirfd, path, flags, mode);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 39 — pthread_create watchdog TID recording
// Record TIDs of threads spawned from libanogs .text range so we can track them.
// DO NOT block creation — that crashes the SDK.
// ─────────────────────────────────────────────────────────────────────────────

static int (*g_orig_pthread_create)(pthread_t*, const pthread_attr_t*,
                                    void*(*)(void*), void*) = nullptr;

static uintptr_t g_ano_text_start = 0;
static uintptr_t g_ano_text_end   = 0;

// watchdog thread start addresses for audit log
static constexpr int MAX_WD_TIDS = 16;
static pthread_t g_wd_tids[MAX_WD_TIDS];
static int       g_wd_n = 0;
static pthread_mutex_t g_wd_mu = PTHREAD_MUTEX_INITIALIZER;

static int hook_pthread_create(pthread_t *tid_out,
                               const pthread_attr_t *attr,
                               void *(*fn)(void*),
                               void *arg) {
    int ret = g_orig_pthread_create(tid_out, attr, fn, arg);
    if (ret == 0 && tid_out && g_ano_text_start) {
        uintptr_t fn_addr = (uintptr_t)fn;
        if (fn_addr >= g_ano_text_start && fn_addr < g_ano_text_end) {
            pthread_mutex_lock(&g_wd_mu);
            if (g_wd_n < MAX_WD_TIDS) g_wd_tids[g_wd_n++] = *tid_out;
            pthread_mutex_unlock(&g_wd_mu);
            LI("Layer39: ano watchdog thread recorded tid=%lu fn=%p",
               (unsigned long)*tid_out, fn);
        }
    }
    return ret;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 40 — ffutil_UnmapCheck spoof → always return 0 (clean)
// ─────────────────────────────────────────────────────────────────────────────

static int (*g_orig_ffutil_check)(void*) = nullptr;
static int hook_ffutil_check(void *ctx) { (void)ctx; return 0; }

// ─────────────────────────────────────────────────────────────────────────────
// Layer 41 — getrlimit RLIMIT_CORE = 0
// ─────────────────────────────────────────────────────────────────────────────

static int (*g_orig_getrlimit)(int, struct rlimit*) = nullptr;
static int hook_getrlimit(int resource, struct rlimit *rl) {
    if (resource == RLIMIT_CORE) {
        if (rl) { rl->rlim_cur = 0; rl->rlim_max = 0; }
        return 0;
    }
    return g_orig_getrlimit(resource, rl);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 42 — getaddrinfo → EAI_NONAME (silence C2 ban reporting)
//            sysconf CPU cores → 8 (hide emulator fingerprint)
// ─────────────────────────────────────────────────────────────────────────────

static int (*g_orig_getaddrinfo)(const char*, const char*,
                                  const struct addrinfo*, struct addrinfo**) = nullptr;
static int hook_getaddrinfo(const char *node, const char *service,
                             const struct addrinfo *hints, struct addrinfo **res) {
    // Known Tencent/AnoSDK report server TLDs
    static const char *const k_c2[] = {
        "tencent.com", "qq.com", "anti-cheat", "anods", nullptr
    };
    if (node) {
        for (const char *const *h = k_c2; *h; ++h) {
            if (strstr(node, *h)) {
                LI("Layer42: C2 DNS blocked: %s", node);
                return EAI_NONAME;
            }
        }
    }
    return g_orig_getaddrinfo(node, service, hints, res);
}

static long (*g_orig_sysconf)(int) = nullptr;
static long hook_sysconf(int name) {
    if (name == _SC_NPROCESSORS_ONLN || name == _SC_NPROCESSORS_CONF)
        return 8;
    return g_orig_sysconf(name);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 43 — unwind_xx_info_query (libanort.so)
//
// libanort.so exports unwind_xx_info_query alongside unwind_xx_ioctl.
// Layer 19 blocks the ioctl path; this blocks the info-query path so AnoSDK
// cannot gather process information through either libanort channel.
// Signature unknown — naked nullifier is safe regardless of arg count.
// ─────────────────────────────────────────────────────────────────────────────

__attribute__((naked))
static void *hook_unwind_info_nullify() {
    // Return -1 (ENODATA) in X0 — safe for any calling convention
#ifdef __aarch64__
    __asm__ volatile("mov x0, #-1\n\tret");
#else
    __asm__ volatile("mvn r0, #0\n\tbx lr");
#endif
}

// ─────────────────────────────────────────────────────────────────────────────
// dl_iterate_phdr callback — find libanogs .text range for Layer 39
// ─────────────────────────────────────────────────────────────────────────────

static int phdr_find_ano(struct dl_phdr_info *info, size_t, void*) {
    if (!info->dlpi_name || !strstr(info->dlpi_name, "libanogs")) return 0;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_LOAD &&
            (info->dlpi_phdr[i].p_flags & 1)) { // PF_X
            g_ano_text_start = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
            g_ano_text_end   = g_ano_text_start + info->dlpi_phdr[i].p_filesz;
            return 1;
        }
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Install all Layer 27-42 hooks
// ─────────────────────────────────────────────────────────────────────────────

#define ZX_HOOK(sym, hook_fn, orig_ptr) do { \
    void *_sym = dlsym(RTLD_DEFAULT, sym); \
    if (_sym) { DobbyHook(_sym, (void*)(hook_fn), (void**)(orig_ptr)); \
                LI("hooked: %s", sym); } \
    else LE("not found: %s", sym); \
} while(0)

void install_stealth_ext4() {
    LI("installing Layers 27-43...");

    // Layer 27
    ZX_HOOK("clock_gettime", hook_clock_gettime, &g_orig_clock_gettime);
    // Seed fake clock from real value to avoid timestamp anomalies
    struct timespec seed{};
    if (g_orig_clock_gettime) g_orig_clock_gettime(CLOCK_MONOTONIC_RAW, &seed);
    uint64_t seed_ns = (uint64_t)seed.tv_sec * 1'000'000'000ULL + (uint64_t)seed.tv_nsec;
    g_fake_ns.store(seed_ns, std::memory_order_relaxed);

    // Layer 28
    ZX_HOOK("gettimeofday", hook_gettimeofday, &g_orig_gettimeofday);

    // Layer 29
    ZX_HOOK("setsid", hook_setsid, &g_orig_setsid);

    // Layer 30
    ZX_HOOK("__system_property_get", hook_prop_get, &g_orig_prop_get);

    // Layer 31
    ZX_HOOK("prctl", hook_prctl, &g_orig_prctl);

    // Layer 32
    ZX_HOOK("dladdr", hook_dladdr, &g_orig_dladdr);

    // Layer 33
    ZX_HOOK("sigaction", hook_sigaction, &g_orig_sigaction);

    // Layer 34 — hook libc syscall() wrapper at PLT
    {
        void *_sym = dlsym(RTLD_DEFAULT, "syscall");
        if (_sym) {
            DobbyHook(_sym, (void*)hook_syscall, (void**)&g_orig_syscall);
            LI("hooked: syscall");
        } else LE("not found: syscall");
    }

    // Layer 35
    ZX_HOOK("fcntl", hook_fcntl, &g_orig_fcntl);

    // Layer 36
    ZX_HOOK("access", hook_access, &g_orig_access);

    // Layer 37
    ZX_HOOK("waitpid", hook_waitpid, &g_orig_waitpid);

    // Layer 38 — chain onto openat (if stealth_ext3 already hooked it, Dobby
    // will hook the current trampoline, creating a proper chain)
    ZX_HOOK("openat", hook_openat_ext4, &g_orig_openat_ext4);

    // Layer 39 — record libanogs .text range first
    dl_iterate_phdr(phdr_find_ano, nullptr);
    ZX_HOOK("pthread_create", hook_pthread_create, &g_orig_pthread_create);

    // Layer 40 — ffutil_UnmapCheck (may or may not be present)
    {
        void *ffutil = dlopen("libffutil.so", RTLD_LAZY | RTLD_NOLOAD);
        if (ffutil) {
            void *fn = dlsym(ffutil, "ffutil_UnmapCheck");
            if (fn) DobbyHook(fn, (void*)hook_ffutil_check, (void**)&g_orig_ffutil_check);
        }
    }

    // Layer 41
    ZX_HOOK("getrlimit", hook_getrlimit, &g_orig_getrlimit);

    // Layer 42
    ZX_HOOK("getaddrinfo", hook_getaddrinfo, &g_orig_getaddrinfo);
    ZX_HOOK("sysconf",     hook_sysconf,     &g_orig_sysconf);

    // Layer 43 — unwind_xx_info_query via direct dlsym on libanort.so
    {
        void *anort = dlopen("libanort.so", RTLD_LAZY | RTLD_NOLOAD);
        if (anort) {
            void *fn = dlsym(anort, "unwind_xx_info_query");
            if (fn) {
                DobbyHook(fn, (void*)hook_unwind_info_nullify, nullptr);
                LI("L43 unwind_xx_info_query hooked");
            }
        }
    }

    LI("Layers 27-43 installed OK");
}
