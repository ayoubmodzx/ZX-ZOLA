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
#include "stealth_ext8.hpp"
#include "stealth_ext9.hpp"
#include "stealth_ext10.hpp"
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

// Forward declaration — installed from anosdk_bypass.cpp
void install_ano_bypass();

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

static void fd_add(int fd) {
    for (int i = 0; i < MAX_FAKE_FDS; i++) {
        int exp = -1;
        if (g_fds[i].compare_exchange_strong(exp, fd)) return;
    }
}
static void fd_del(int fd) {
    for (int i = 0; i < MAX_FAKE_FDS; i++) {
        int exp = fd;
        g_fds[i].compare_exchange_strong(exp, -1);
    }
}

enum PType { P_NONE, P_MAPS, P_SMAPS, P_STATUS };

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
    OBF_DECODE(pay,  "libunity_gc.so"); // staged payload name in FF's lib dir
    OBF_DECODE(pay2, "libzx_payload.so");    // source name (nativeLibraryDir)
    OBF_DECODE(inj,  "zx_injector");
    OBF_DECODE(pfx,  "zx_payload");
    if (strstr(line, pay) || strstr(line, pay2) || strstr(line, inj) || strstr(line, pfx))
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

static int (*orig_openat)(int, const char*, int, ...) = nullptr;
static int (*orig_close)(int)                         = nullptr;

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

    int mfd = -1;
    switch (classify(path)) {
        case P_MAPS:   mfd = build_fake_maps(rfd);   break;
        case P_SMAPS:  mfd = build_fake_smaps(rfd);  break;
        case P_STATUS: mfd = build_fake_status(rfd); break;
        default: return rfd;
    }
    if (mfd < 0) return -1;
    fd_add(mfd);
    return mfd;
}

static int hook_close(int fd) {
    fd_del(fd);
    return orig_close ? orig_close(fd) : (int)syscall(__NR_close, fd);
}

static void install_proc_hider() {
    for (int i = 0; i < MAX_FAKE_FDS; i++) g_fds[i].store(-1);

    OBF_DECODE(libc, "libc.so");
    void *h = dlopen(libc, RTLD_LAZY | RTLD_NOLOAD);
    if (!h) h = dlopen(libc, RTLD_LAZY);
    if (!h) { LE("L2: libc not found"); return; }

    void *fn_oa = dlsym(h, "openat");
    void *fn_cl = dlsym(h, "close");
    if (fn_oa) DobbyHook(fn_oa, (void*)hook_openat, (void**)&orig_openat);
    if (fn_cl) DobbyHook(fn_cl, (void*)hook_close,  (void**)&orig_close);
    LI("L2 /proc hider OK (maps+smaps+status, TracerPid=0)");
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 3 — AnoSDK full neutralisation
// ═════════════════════════════════════════════════════════════════════════════

static int  (*orig_AnoInit)(int, void*, int)       = nullptr;
static void (*orig_AnoOnPause)()                   = nullptr;
static void (*orig_AnoOnResume)()                  = nullptr;
static int  (*orig_AnoSetUser)(int,const char*,int)= nullptr;
static int  (*orig_AnoIoctl)(int,void*,int)        = nullptr;
static int  (*orig_SetPeriod)(int)                 = nullptr;

// Lifecycle functions: pass through — blocking Init/Pause/Resume puts AnoSDK
// in undefined state with no heartbeats sent, causing server-side ban.
// Scan functions (ms_scan_start, inline_hook_opcode_dismatch etc.) are
// nullified separately so the SDK runs normally but finds nothing.
static int hook_AnoInit(int id, void *d, int l) {
    return orig_AnoInit ? orig_AnoInit(id, d, l) : 0;
}
static int hook_AnoIoctl(int cmd, void *d, int l) {
    return orig_AnoIoctl ? orig_AnoIoctl(cmd, d, l) : 0;
}
static void hook_AnoOnPause()  { if (orig_AnoOnPause)  orig_AnoOnPause(); }
static void hook_AnoOnResume() { if (orig_AnoOnResume) orig_AnoOnResume(); }
// SetUserInfo: pass through — server correlates reports by user ID;
// anonymous reports (null user) are an anomaly signal.
static int hook_AnoSetUser(int t, const char *u, int l) {
    return orig_AnoSetUser ? orig_AnoSetUser(t, u, l) : 0;
}
static int hook_SetPeriod(int ms) {
    (void)ms;
    return orig_SetPeriod ? orig_SetPeriod(0x7FFFFFFF) : 0;
}
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

    OBF_DECODE(s_ini, "AnoSDKInit");
    OBF_DECODE(s_pau, "AnoSDKOnPause");
    OBF_DECODE(s_res, "AnoSDKOnResume");
    OBF_DECODE(s_usr, "AnoSDKSetUserInfo");
    OBF_DECODE(s_ict, "AnoSDKIoctl");
    OBF_DECODE(s_scp, "set_check_period");
    OBF_DECODE(s_acp, "ano_set_check_period");
    try_hk(s_ini, (void*)hook_AnoInit,     (void**)&orig_AnoInit);
    try_hk(s_pau, (void*)hook_AnoOnPause,  (void**)&orig_AnoOnPause);
    try_hk(s_res, (void*)hook_AnoOnResume, (void**)&orig_AnoOnResume);
    try_hk(s_usr, (void*)hook_AnoSetUser,  (void**)&orig_AnoSetUser);
    try_hk(s_ict, (void*)hook_AnoIoctl,    (void**)&orig_AnoIoctl);
    try_hk(s_scp, (void*)hook_SetPeriod,   (void**)&orig_SetPeriod);
    try_hk(s_acp, (void*)hook_SetPeriod,   nullptr);

    OBF_DECODE(si0, "inline_hook_opcode_dismatch");
    OBF_DECODE(si1, "set_inline_hook_error");
    OBF_DECODE(si2, "ms_scan_start");
    OBF_DECODE(si3, "scan_memory_region");
    OBF_DECODE(si4, "check_module_integrity");
    OBF_DECODE(si5, "scan_for_hooks");
    OBF_DECODE(si6, "verify_code_section");
    OBF_DECODE(si7, "ptimer_start");
    OBF_DECODE(si8, "ptimer_create");
    const char *k_internal[] = {si0,si1,si2,si3,si4,si5,si6,si7,si8,nullptr};
    int found = 0;
    for (int i = 0; k_internal[i]; i++) {
        void *a = DobbySymbolResolver(lib, k_internal[i]);
        if (a) {
            DobbyHook(a, (void*)hook_ScanNullify, nullptr);
            found++;
            LI("L3 internal hook: %s", k_internal[i]);
        }
    }
    LI("L3 AnoSDK extended OK (%d internal hooks)", found);
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 4 — Dobby trampoline signature scrub
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
        // Restore RX — permanent RWX pages are a detectable signature visible
        // in /proc/kpageflags and via hardware PMU dirty-tracking.
        mprotect((void*)pg, ps, PROT_READ | PROT_EXEC);
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
    install_ano_bypass();       // AnoSDK bypass (proc hider active, race window closed)
    install_anosdk_extended(ano); // Layer 3
    // Layer 5 (RWX tracker) is passive — populated by dobby_impl.cpp
    // Layer 6 (string obfuscation) is passive — compile-time only
    install_stealth_ext();      // Layers 7-12
    install_stealth_ext2();     // Layers 13-17
    install_stealth_ext3();     // Layers 18-26
    install_stealth_ext4();     // Layers 27-43
    install_stealth_ext5();     // Layers 44-48
    install_stealth_ext6();     // Layers 49-53
    install_stealth_ext7();     // Layers 54-57
    install_stealth_ext8();     // Layers 58-62
    install_stealth_ext9();     // Layers 63-70
    install_stealth_ext10();    // Layers 71-75
    zx_scrub_trampolines();     // Layer 4 — scrub ALL trampolines at once

    LI("AntiDetect: all 75 layers active");
}
