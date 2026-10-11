/*
 * anti_detect.cpp — Ultra-hardened 6-layer anti-detection for ZX-ZOLA
 *
 * Layer 1  libffutil.so page-hiding bypass
 * Layer 2  /proc sanitisation
 *            /proc/self/maps    — strip our .so names + our RWX trampoline pages
 *            /proc/self/smaps   — same, block-aware (header + detail lines)
 *            /proc/self/status  — zero TracerPid field
 *            /proc/<pid>/*      — same for numeric PID paths
 * Layer 3  AnoSDK full neutralisation
 *            AnoSDKInit         — prevent scanner thread from spawning
 *            AnoSDKIoctl        — block ALL commands (was partial before)
 *            GetReportData/2/3/4 — empty
 *            DelReportData/2    — empty
 *            OnPause/Resume     — suppressed (no scan restart)
 *            SetUserInfo        — suppressed
 *            inline_hook_opcode_dismatch + 8 internal scanner symbols
 * Layer 4  Dobby trampoline signature scrub (LDR X17 → LDR X16)
 * Layer 5  Anonymous RWX page tracker
 *            Trampoline pages filtered from maps/smaps output
 * Layer 6  Compile-time XOR string obfuscation
 *            Our library names never appear as plain ASCII in .rodata
 */

#include "anti_detect.hpp"
#include "stealth_ext.hpp"
#include "stealth_ext2.hpp"
#include "stealth_ext3.hpp"
#include "stealth_ext4.hpp"
#include "stealth_ext5.hpp"
#include "stealth_ext6.hpp"
#include "stealth_ext7.hpp"
#include "dobby_stub.hpp"
#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstdarg>
#include <atomic>
#include <pthread.h>

// arm64 syscall numbers
#ifndef __NR_memfd_create
#define __NR_memfd_create 279
#endif
#ifndef __NR_openat
#define __NR_openat 56
#endif
#ifndef __NR_close
#define __NR_close 57
#endif

#define TAG "ZX-ADET"
#ifndef ZX_RELEASE
#define LI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#else
#define LI(...) ((void)0)
#define LE(...) ((void)0)
#endif

// ═════════════════════════════════════════════════════════════════════════════
// Layer 6 — Compile-time XOR string obfuscation
// Library names are never stored as plain ASCII in .rodata.
// The XOR key 0x5A is applied at compile time; decode happens in a
// thread-local buffer at runtime, so the plaintext is never a global.
// ═════════════════════════════════════════════════════════════════════════════

static constexpr uint8_t XK = 0x5Au;

template<size_t N>
struct Obf {
    char data[N]{};
    constexpr explicit Obf(const char (&s)[N]) {
        for (size_t i = 0; i < N; i++) data[i] = (char)(s[i] ^ XK);
    }
    void decode(char (&out)[N]) const {
        for (size_t i = 0; i < N; i++) out[i] = (char)(data[i] ^ XK);
    }
};

// Decode into a function-local static buffer — NOT a global plaintext.
#define OBF_DECODE(var, lit)                                \
    char var[sizeof(lit)];                                  \
    do {                                                    \
        static constexpr Obf<sizeof(lit)> _o(lit);         \
        _o.decode(var);                                     \
    } while(0)

// ═════════════════════════════════════════════════════════════════════════════
// Layer 5 — Anonymous RWX page tracker
// dobby_impl.cpp calls zx_track_rwx_page() after every trampoline mmap.
// The hider in Layer 2 consults this list to filter those pages from output.
// ═════════════════════════════════════════════════════════════════════════════

struct RwxPage { uintptr_t start; uintptr_t end; };
static constexpr int      MAX_RWX = 128;
static RwxPage            g_rwx[MAX_RWX];
static int                g_rwx_n = 0;
static pthread_mutex_t    g_rwx_mu = PTHREAD_MUTEX_INITIALIZER;

void zx_track_rwx_page(void *p, size_t sz) {
    if (!p || sz == 0) return;
    pthread_mutex_lock(&g_rwx_mu);
    if (g_rwx_n < MAX_RWX)
        g_rwx[g_rwx_n++] = { (uintptr_t)p, (uintptr_t)p + sz };
    pthread_mutex_unlock(&g_rwx_mu);
}

static bool addr_is_ours(uintptr_t a) {
    pthread_mutex_lock(&g_rwx_mu);
    bool found = false;
    for (int i = 0; i < g_rwx_n && !found; i++)
        found = (a >= g_rwx[i].start && a < g_rwx[i].end);
    pthread_mutex_unlock(&g_rwx_mu);
    return found;
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 1 — libffutil.so bypass
// ═════════════════════════════════════════════════════════════════════════════

static int (*orig_ffutil_UnmapAddr)(uintptr_t, size_t) = nullptr;
static int (*orig_ffutil_UnmapSize)(size_t)             = nullptr;
static int (*orig_ffutil_Unmap)(void*)                  = nullptr;
static int (*orig_ffutil_SetUnmapTarget)(void*, int)    = nullptr;

static int hook_ffutil_UnmapAddr(uintptr_t a, size_t l) {
    if (addr_is_ours(a)) return 0;
    return orig_ffutil_UnmapAddr ? orig_ffutil_UnmapAddr(a, l) : 0;
}
static int hook_ffutil_UnmapSize(size_t l) {
    return orig_ffutil_UnmapSize ? orig_ffutil_UnmapSize(l) : 0;
}
static int hook_ffutil_Unmap(void *c) {
    if (c && addr_is_ours((uintptr_t)c)) return 0;
    return orig_ffutil_Unmap ? orig_ffutil_Unmap(c) : 0;
}
static int hook_ffutil_SetUnmapTarget(void *c, int f) {
    return orig_ffutil_SetUnmapTarget ? orig_ffutil_SetUnmapTarget(c, f) : 0;
}

static void install_ffutil_bypass() {
    OBF_DECODE(libname, "libffutil.so");
    void *h = dlopen(libname, RTLD_LAZY | RTLD_NOLOAD);
    if (!h) h = dlopen(libname, RTLD_LAZY);
    if (!h) { LI("ffutil: not loaded"); return; }

    auto hk = [&](const char *sym, void *rep, void **orig) {
        void *a = dlsym(h, sym);
        if (!a) a = DobbySymbolResolver(libname, sym);
        if (a) DobbyHook(a, rep, orig);
    };
    hk("ffutil_UnmapAddr",      (void*)hook_ffutil_UnmapAddr,      (void**)&orig_ffutil_UnmapAddr);
    hk("ffutil_UnmapSize",      (void*)hook_ffutil_UnmapSize,      (void**)&orig_ffutil_UnmapSize);
    hk("ffutil_Unmap",          (void*)hook_ffutil_Unmap,          (void**)&orig_ffutil_Unmap);
    hk("ffutil_SetUnmapTarget", (void*)hook_ffutil_SetUnmapTarget, (void**)&orig_ffutil_SetUnmapTarget);
    LI("L1 libffutil bypass OK");
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 2 — /proc filesystem sanitisation
// ═════════════════════════════════════════════════════════════════════════════

static constexpr int   MAX_FAKE_FDS = 32;
static std::atomic<int> g_fds[MAX_FAKE_FDS];

enum PType { P_NONE, P_MAPS, P_SMAPS, P_STATUS };
static PType fd_ptype[MAX_FAKE_FDS];

static void fd_add(int fd) {
    for (int i = 0; i < MAX_FAKE_FDS; i++) {
        int exp = -1;
        if (g_fds[i].compare_exchange_strong(exp, fd)) return;
    }
}
static void fd_del(int fd) {
    for (int i = 0; i < MAX_FAKE_FDS; i++) {
        int exp = fd;
        if (g_fds[i].compare_exchange_strong(exp, -1))
            fd_ptype[i] = P_NONE;
    }
}

static PType classify(const char *path) {
    if (!path || strncmp(path, "/proc/", 6) != 0) return P_NONE;
    // Accept both /proc/self/X and /proc/<number>/X
    const char *tail = path + 6;
    if (strncmp(tail, "self/", 5) == 0) tail += 5;
    else {
        // skip numeric pid
        while (*tail >= '0' && *tail <= '9') tail++;
        if (*tail != '/') return P_NONE;
        tail++;
    }
    if (strcmp(tail, "maps")   == 0) return P_MAPS;
    if (strcmp(tail, "smaps")  == 0 ||
        strcmp(tail, "smaps_rollup") == 0) return P_SMAPS;
    if (strcmp(tail, "status") == 0) return P_STATUS;
    return P_NONE;
}

// Returns true if a maps/smaps header line should be completely hidden.
// Criteria: contains our lib name, or is an anonymous rwxp page we own.
static bool hide_maps_line(const char *line) {
    OBF_DECODE(pay,  "libzx_payload.so");
    OBF_DECODE(inj,  "zx_injector");
    OBF_DECODE(pfx,  "zx_payload");
    OBF_DECODE(mfd,  "memfd:zx");
    OBF_DECODE(tmp,  "zxpl_");
    if (strstr(line, pay) || strstr(line, inj) || strstr(line, pfx) ||
        strstr(line, mfd) || strstr(line, tmp))
        return true;
    // Anonymous rwxp pages that belong to our trampoline pool
    if (strstr(line, "rwxp") && !strchr(line, '/')) {
        uintptr_t start = (uintptr_t)strtoull(line, nullptr, 16);
        if (start && addr_is_ours(start)) return true;
    }
    return false;
}

// Zero out TracerPid in a /proc/status line (in-place).
static void zero_tracer(char *line) {
    if (strncmp(line, "TracerPid:", 10) != 0) return;
    char *p = line + 10;
    while (*p == '\t' || *p == ' ') p++;
    // Overwrite the numeric value with '0'
    char *q = p;
    while (*q >= '0' && *q <= '9') *q++ = '0';
    // Collapse to single '0'
    if (q > p + 1) {
        p[0] = '0'; p[1] = '\n'; p[2] = '\0';
    } else {
        p[0] = '0';
    }
}

static int build_fake_maps(int real_fd) {
    int mfd = (int)syscall(__NR_memfd_create, "zxm", 0);
    if (mfd < 0) return -1;
    FILE *f = fdopen(dup(real_fd), "r");
    close(real_fd);
    if (!f) { close(mfd); return -1; }

    char line[1024];
    while (fgets(line, sizeof(line), f))
        if (!hide_maps_line(line))
            write(mfd, line, strlen(line));
    fclose(f);
    lseek(mfd, 0, SEEK_SET);
    return mfd;
}

static int build_fake_smaps(int real_fd) {
    int mfd = (int)syscall(__NR_memfd_create, "zxs", 0);
    if (mfd < 0) return -1;
    FILE *f = fdopen(dup(real_fd), "r");
    close(real_fd);
    if (!f) { close(mfd); return -1; }

    char line[1024];
    bool skip = false;
    while (fgets(line, sizeof(line), f)) {
        // A smaps header line: "aaaa-bbbb perms offset dev ino [path]"
        // Identified by 'p' or '-' permission char after the address range
        bool is_hdr = (line[0] >= '0' && line[0] <= '9') ||
                      (line[0] >= 'a' && line[0] <= 'f');
        if (is_hdr) skip = hide_maps_line(line);
        if (!skip)  write(mfd, line, strlen(line));
    }
    fclose(f);
    lseek(mfd, 0, SEEK_SET);
    return mfd;
}

static int build_fake_status(int real_fd) {
    int mfd = (int)syscall(__NR_memfd_create, "zxt", 0);
    if (mfd < 0) return -1;
    FILE *f = fdopen(dup(real_fd), "r");
    close(real_fd);
    if (!f) { close(mfd); return -1; }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        zero_tracer(line);
        write(mfd, line, strlen(line));
    }
    fclose(f);
    lseek(mfd, 0, SEEK_SET);
    return mfd;
}

static int  (*orig_openat)(int, const char*, int, ...) = nullptr;
static int  (*orig_open)(const char*, int, ...)        = nullptr;
static FILE*(*orig_fopen)(const char*, const char*)    = nullptr;
static int  (*orig_close)(int)                         = nullptr;

static int open_proc_path(const char *path, int flags) {
    if (orig_openat)
        return orig_openat(AT_FDCWD, path, flags);
    return (int)syscall(__NR_openat, AT_FDCWD, path, flags);
}

static int dispatch_proc_fd(int rfd, PType pt) {
    int mfd = -1;
    switch (pt) {
        case P_MAPS:   mfd = build_fake_maps(rfd);   break;
        case P_SMAPS:  mfd = build_fake_smaps(rfd);  break;
        case P_STATUS: mfd = build_fake_status(rfd); break;
        default: return rfd;
    }
    if (mfd < 0) return -1;
    fd_add(mfd);
    return mfd;
}

static int hook_openat(int dirfd, const char *path, int flags, ...) {
    int rfd;
    if (orig_openat) {
        if (flags & O_CREAT) {
            va_list ap; va_start(ap, flags);
            mode_t m = va_arg(ap, mode_t); va_end(ap);
            rfd = orig_openat(dirfd, path, flags, m);
        } else {
            rfd = orig_openat(dirfd, path, flags);
        }
    } else {
        rfd = (int)syscall(__NR_openat, dirfd, path, flags);
    }
    if (rfd < 0) return rfd;
    PType pt = classify(path);
    return dispatch_proc_fd(rfd, pt);
}

static int hook_open(const char *path, int flags, ...) {
    int rfd;
    if (orig_open) {
        if (flags & O_CREAT) {
            va_list ap; va_start(ap, flags);
            mode_t m = va_arg(ap, mode_t); va_end(ap);
            rfd = orig_open(path, flags, m);
        } else {
            rfd = orig_open(path, flags);
        }
    } else {
        rfd = open_proc_path(path, flags);
    }
    if (rfd < 0) return rfd;
    PType pt = classify(path);
    return dispatch_proc_fd(rfd, pt);
}

static FILE *hook_fopen(const char *path, const char *mode) {
    PType pt = classify(path);
    if (pt == P_NONE) {
        return orig_fopen ? orig_fopen(path, mode) : nullptr;
    }
    // open the real fd, build a sanitised memfd, wrap it in FILE*
    int rfd = open_proc_path(path, O_RDONLY);
    if (rfd < 0) return orig_fopen ? orig_fopen(path, mode) : nullptr;
    int mfd = dispatch_proc_fd(rfd, pt);
    if (mfd < 0) return nullptr;
    FILE *fp = fdopen(mfd, "r");
    if (!fp) { close(mfd); return nullptr; }
    return fp;
}

static int hook_close(int fd) {
    fd_del(fd);
    return orig_close ? orig_close(fd) : (int)syscall(__NR_close, fd);
}

// ── dl_iterate_phdr hook: hide our injected payload from module scanner ───────
#include <link.h>
static int (*orig_dl_iterate_phdr)(int(*)(struct dl_phdr_info*, size_t, void*), void*) = nullptr;

struct DlIterCtx {
    int  (*cb)(struct dl_phdr_info*, size_t, void*);
    void *data;
};

static int dl_iter_filter(struct dl_phdr_info *info, size_t sz, void *arg) {
    auto *ctx = reinterpret_cast<DlIterCtx*>(arg);
    const char *name = info->dlpi_name ? info->dlpi_name : "";

    // Hide our payload by name patterns
    OBF_DECODE(pay,  "libzx_payload.so");
    OBF_DECODE(pfx,  "zx_payload");
    OBF_DECODE(mfd1, "memfd:zx");
    OBF_DECODE(tmp1, "zxpl_");
    if (strstr(name, pay)  || strstr(name, pfx) ||
        strstr(name, mfd1) || strstr(name, tmp1))
        return 0;  // skip — invisible to caller

    // Also hide anonymous maps that belong to our RWX trampoline pool
    if (name[0] == '\0' && info->dlpi_phdr) {
        uintptr_t load_addr = info->dlpi_addr;
        if (addr_is_ours(load_addr)) return 0;
    }

    return ctx->cb(info, sz, ctx->data);
}

static int hook_dl_iterate_phdr(int (*cb)(struct dl_phdr_info*, size_t, void*), void *data) {
    DlIterCtx ctx = { cb, data };
    if (orig_dl_iterate_phdr)
        return orig_dl_iterate_phdr(dl_iter_filter, &ctx);
    return dl_iterate_phdr(dl_iter_filter, &ctx);
}

// ── tp_syscall_imp hook (libanort Tencent syscall shim) ───────────────────────
// Signature: long tp_syscall_imp(long nr, long a0, long a1, long a2, long a3, long a4, long a5)
static long (*orig_tp_syscall)(long,long,long,long,long,long,long) = nullptr;

static long hook_tp_syscall(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
    // Intercept openat(__NR_openat=56) calls targeting /proc paths
    if (nr == 56) {
        const char *path = reinterpret_cast<const char*>(a1);
        PType pt = (path && path[0] == '/') ? classify(path) : P_NONE;
        if (pt != P_NONE) {
            long rfd = orig_tp_syscall ? orig_tp_syscall(nr,a0,a1,a2,a3,a4,a5)
                                       : syscall(nr,a0,a1,a2,a3,a4,a5);
            if (rfd < 0) return rfd;
            int mfd = dispatch_proc_fd((int)rfd, pt);
            return mfd >= 0 ? mfd : -1;
        }
    }
    return orig_tp_syscall ? orig_tp_syscall(nr,a0,a1,a2,a3,a4,a5)
                           : syscall(nr,a0,a1,a2,a3,a4,a5);
}

static void install_proc_hider() {
    for (int i = 0; i < MAX_FAKE_FDS; i++) { g_fds[i].store(-1); fd_ptype[i] = P_NONE; }

    OBF_DECODE(libc, "libc.so");
    void *h = dlopen(libc, RTLD_LAZY | RTLD_NOLOAD);
    if (!h) h = dlopen(libc, RTLD_LAZY);
    if (!h) { LE("L2: libc not found"); return; }

    auto hk = [&](const char *sym, void *rep, void **orig_out) {
        void *a = dlsym(h, sym);
        if (a) DobbyHook(a, rep, orig_out);
    };

    hk("openat",  (void*)hook_openat, (void**)&orig_openat);
    hk("open",    (void*)hook_open,   (void**)&orig_open);
    hk("fopen",   (void*)hook_fopen,  (void**)&orig_fopen);
    hk("close",   (void*)hook_close,  (void**)&orig_close);
    // Also hook the hardened libc variants that ACE imports
    hk("__openat_2", (void*)hook_openat, nullptr);
    hk("__open_2",   (void*)hook_open,   nullptr);
    // dl_iterate_phdr — module scanner bypass
    void *fn_phdr = dlsym(RTLD_DEFAULT, "dl_iterate_phdr");
    if (fn_phdr) DobbyHook(fn_phdr, (void*)hook_dl_iterate_phdr, (void**)&orig_dl_iterate_phdr);

    // tp_syscall_imp in libanort.so — Tencent's direct syscall shim
    OBF_DECODE(anort, "libanort.so");
    void *hrt = dlopen(anort, RTLD_LAZY | RTLD_NOLOAD);
    if (hrt) {
        void *tpsysc = dlsym(hrt, "tp_syscall_imp");
        if (tpsysc) DobbyHook(tpsysc, (void*)hook_tp_syscall, (void**)&orig_tp_syscall);
    }

    LI("L2 /proc hider OK (maps+smaps+status, dl_iterate_phdr, tp_syscall, TracerPid=0)");
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 3 — AnoSDK full neutralisation
//
// NOTE: anosdk_bypass.cpp installs early hooks via __attribute__((constructor)).
// This layer adds what's missing there:
//   • AnoSDKInit  — blocks scanner thread from ever spawning
//   • AnoSDKOnPause/Resume — suppressed so scan can never restart
//   • AnoSDKSetUserInfo — suppressed (no real binding)
//   • Ioctl re-hook to block ALL commands (overrides partial hook)
//   • 8 internal scanner symbols via DobbySymbolResolver
// ═════════════════════════════════════════════════════════════════════════════

static int  (*orig_AnoInit)(int, void*, int)       = nullptr;
static void (*orig_AnoOnPause)()                   = nullptr;
static void (*orig_AnoOnResume)()                  = nullptr;
static int  (*orig_AnoSetUser)(int,const char*,int)= nullptr;
static int  (*orig_AnoIoctl)(int,void*,int)        = nullptr;
static int  (*orig_SetPeriod)(int)                 = nullptr;

// Prevent scanner thread from ever starting
static int hook_AnoInit(int id, void *d, int l) {
    (void)id; (void)d; (void)l;
    return 0;
}
// Block ALL Ioctl commands — no heartbeat, no init, no scan
static int hook_AnoIoctl(int cmd, void *d, int l) {
    (void)cmd; (void)d; (void)l;
    return 0;
}
// Prevent scan from resuming after app comes back from background
static void hook_AnoOnPause()  {}
static void hook_AnoOnResume() {}
// Prevent user binding
static int hook_AnoSetUser(int t, const char *u, int l) {
    (void)t; (void)u; (void)l; return 0;
}
// Push scan interval to max int — effectively never fires
static int hook_SetPeriod(int ms) {
    (void)ms;
    return orig_SetPeriod ? orig_SetPeriod(0x7FFFFFFF) : 0;
}
// Generic nullifier for internal scanner/detector functions
// Naked asm: safe regardless of callee arg count — just zero X0 and return
__attribute__((naked))
static void *hook_ScanNullify() {
#ifdef __aarch64__
    __asm__ volatile("mov x0, #0\n\tret");
#else
    __asm__ volatile("mov r0, #0\n\tbx lr");
#endif
}

static void install_anosdk_extended(void *h) {
    if (!h) return;
    OBF_DECODE(lib, "libanogs.so");

    auto try_hk = [&](const char *sym, void *rep, void **orig) -> bool {
        void *a = dlsym(h, sym);
        if (!a) {
            char buf[128]; snprintf(buf, sizeof(buf), "%s@@ANO", sym);
            a = dlsym(h, buf);
        }
        if (!a) a = DobbySymbolResolver(lib, sym);
        if (a) { DobbyHook(a, rep, orig); return true; }
        return false;
    };

    // Exported symbols missing from anosdk_bypass.cpp
    try_hk("AnoSDKInit",       (void*)hook_AnoInit,     (void**)&orig_AnoInit);
    try_hk("AnoSDKOnPause",    (void*)hook_AnoOnPause,  (void**)&orig_AnoOnPause);
    try_hk("AnoSDKOnResume",   (void*)hook_AnoOnResume, (void**)&orig_AnoOnResume);
    try_hk("AnoSDKSetUserInfo",(void*)hook_AnoSetUser,  (void**)&orig_AnoSetUser);

    // Re-hook Ioctl to block ALL commands (overrides the cmd<0x10 pass-through
    // left by anosdk_bypass.cpp's constructor hook)
    try_hk("AnoSDKIoctl", (void*)hook_AnoIoctl, (void**)&orig_AnoIoctl);

    // Check-period hooks
    try_hk("set_check_period",     (void*)hook_SetPeriod, (void**)&orig_SetPeriod);
    try_hk("ano_set_check_period", (void*)hook_SetPeriod, nullptr);

    // Internal scanner / hook-detector symbols (best-effort via ELF scan)
    static const char *k_internal[] = {
        "inline_hook_opcode_dismatch",
        "set_inline_hook_error",
        "ms_scan_start",
        "scan_memory_region",
        "check_module_integrity",
        "scan_for_hooks",
        "verify_code_section",
        "ptimer_start",
        "ptimer_create",
        nullptr
    };
    int found = 0;
    for (int i = 0; k_internal[i]; i++) {
        void *a = DobbySymbolResolver(lib, k_internal[i]);
        if (a) {
            DobbyHook(a, (void*)hook_ScanNullify, nullptr);
            found++;
            LI("L3 internal hook: %s", k_internal[i]);
        }
    }

    // Block libanort unwind/stack-inspect exports used for call-chain hooking detection
    OBF_DECODE(anort_s, "libanort.so");
    void *hrt2 = dlopen(anort_s, RTLD_LAZY | RTLD_NOLOAD);
    if (hrt2) {
        static const char *k_rt[] = { "unwind_xx_ioctl", "unwind_xx_info_query", nullptr };
        for (int i = 0; k_rt[i]; i++) {
            void *a = dlsym(hrt2, k_rt[i]);
            if (a) { DobbyHook(a, (void*)hook_ScanNullify, nullptr); found++; }
        }
    }

    LI("L3 AnoSDK extended OK (%d internal hooks)", found);
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 4 — Dobby trampoline signature scrub
// dobby_impl.cpp writes LDR X17, #8 (0x58000051) + BR X17 (0xD61F0220).
// AnoSDK byte-pattern scans for that exact 8-byte sequence.
// We overwrite it with the X16 variant — same semantics, different encoding.
// ═════════════════════════════════════════════════════════════════════════════

static const uint8_t k_clean_hdr[8] = {
    0x50, 0x00, 0x00, 0x58,   // LDR X16, #8
    0x00, 0x02, 0x1F, 0xD6,   // BR  X16
};

static void *k_scrub[128];
static int   k_scrub_n = 0;

void zx_register_scrub_target(void *addr) {
    if (k_scrub_n < 128) k_scrub[k_scrub_n++] = addr;
}

void zx_scrub_trampolines() {
    size_t ps = (size_t)getpagesize();
    for (int i = 0; i < k_scrub_n; i++) {
        void *p = k_scrub[i];
        if (!p) continue;
        uintptr_t pg = (uintptr_t)p & ~(ps - 1);
        mprotect((void*)pg, ps, PROT_READ | PROT_WRITE | PROT_EXEC);
        memcpy(p, k_clean_hdr, 8);
        __builtin___clear_cache((char*)p, (char*)p + 8);
    }
    LI("L4 scrubbed %d trampoline headers", k_scrub_n);
}

// ═════════════════════════════════════════════════════════════════════════════
// Public install
// ═════════════════════════════════════════════════════════════════════════════

void AntiDetect::install() {
    OBF_DECODE(anolib, "libanogs.so");
    void *ano = dlopen(anolib, RTLD_LAZY | RTLD_NOLOAD);

    install_ffutil_bypass();    // Layer 1
    install_proc_hider();       // Layer 2
    install_anosdk_extended(ano); // Layer 3
    // Layer 5 (RWX tracker) is passive — populated by dobby_impl.cpp
    // Layer 6 (string obfuscation) is passive — compile-time only
    install_stealth_ext();      // Layers 7-12
    install_stealth_ext2();     // Layers 13-17
    install_stealth_ext3();     // Layers 18-26
    install_stealth_ext4();     // Layers 27-43
    install_stealth_ext5();     // Layers 44-48
    install_stealth_ext6();     // Layers 49-53
    install_stealth_ext7();     // Layers 54-61
    zx_scrub_trampolines();     // Layer 4 — scrub ALL 61 layers' trampolines at once

    LI("AntiDetect: all 61 layers active");
}
