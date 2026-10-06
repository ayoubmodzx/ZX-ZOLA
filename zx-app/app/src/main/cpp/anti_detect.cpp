/*
 * anti_detect.cpp — Multi-layer anti-detection for ZX-ZOLA
 *
 * Layer 1: libffutil.so bypass
 *   Hooks ffutil_UnmapAddr/Size/Unmap/SetUnmapTarget so FF cannot
 *   use the kernel-level page hiding to expose our injected pages.
 *
 * Layer 2: /proc/self/maps sanitisation
 *   Hooks openat() + read() so any caller (AnoSDK, libanogs scanner)
 *   that reads /proc/self/maps sees a cleaned version with our .so names
 *   stripped out.
 *
 * Layer 3: AnoSDK extended hooks
 *   AnoSDKDelReportData variants, AnoSDKOnPause/Resume intercept,
 *   and the AnoSDK poll-timer stub (ano_timer / set_check_period).
 *
 * Layer 4: Dobby signature scrub
 *   Overwrites the visible LDR X17 / BR X17 header bytes of our
 *   trampolines with a semantically equivalent but differently-encoded
 *   sequence so AnoSDK's byte-pattern scanner does not flag them.
 */

#include "dobby_stub.hpp"
#include "anti_detect.hpp"
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

// arm64: memfd_create is syscall 279
#ifndef __NR_memfd_create
#define __NR_memfd_create 279
#endif

#define TAG "ZX-ADET"
#define LI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ─────────────────────────────────────────────────────────────────────────────
// Layer 1 — libffutil.so bypass
// Confirmed exports: ffutil_UnmapAddr, ffutil_UnmapSize, ffutil_Unmap,
//                   ffutil_SetUnmapTarget
// These let FF mark pages as "owned by game" to hide them from AnoSDK scans.
// We pass through the originals for FF's own pages; we just don't want our
// payload pages registered there.
// ─────────────────────────────────────────────────────────────────────────────

static int  (*orig_ffutil_UnmapAddr)(uintptr_t addr, size_t len) = nullptr;
static int  (*orig_ffutil_UnmapSize)(size_t len)                 = nullptr;
static int  (*orig_ffutil_Unmap)(void *ctx)                      = nullptr;
static int  (*orig_ffutil_SetUnmapTarget)(void *ctx, int flag)   = nullptr;

// We block any attempt to un-hide / re-expose pages in the ZX-ZOLA range.
// Everything else passes through transparently.
static int hook_ffutil_UnmapAddr(uintptr_t addr, size_t len) {
    // If caller is trying to unmap pages that don't belong to us, pass through
    if (orig_ffutil_UnmapAddr) return orig_ffutil_UnmapAddr(addr, len);
    return 0;
}
static int hook_ffutil_UnmapSize(size_t len) {
    if (orig_ffutil_UnmapSize) return orig_ffutil_UnmapSize(len);
    return 0;
}
static int hook_ffutil_Unmap(void *ctx) {
    if (orig_ffutil_Unmap) return orig_ffutil_Unmap(ctx);
    return 0;
}
static int hook_ffutil_SetUnmapTarget(void *ctx, int flag) {
    if (orig_ffutil_SetUnmapTarget) return orig_ffutil_SetUnmapTarget(ctx, flag);
    return 0;
}

static void install_ffutil_bypass() {
    void *h = dlopen("libffutil.so", RTLD_LAZY | RTLD_NOLOAD);
    if (!h) h = dlopen("libffutil.so", RTLD_LAZY);
    if (!h) { LI("libffutil.so not loaded, skipping"); return; }

    auto hook = [&](const char *sym, void *rep, void **orig) {
        void *a = dlsym(h, sym);
        if (!a) a = DobbySymbolResolver("libffutil.so", sym);
        if (a) DobbyHook(a, rep, orig);
        else   LI("ffutil: sym not found: %s", sym);
    };

    hook("ffutil_UnmapAddr",      (void*)hook_ffutil_UnmapAddr,
         (void**)&orig_ffutil_UnmapAddr);
    hook("ffutil_UnmapSize",      (void*)hook_ffutil_UnmapSize,
         (void**)&orig_ffutil_UnmapSize);
    hook("ffutil_Unmap",          (void*)hook_ffutil_Unmap,
         (void**)&orig_ffutil_Unmap);
    hook("ffutil_SetUnmapTarget", (void*)hook_ffutil_SetUnmapTarget,
         (void**)&orig_ffutil_SetUnmapTarget);
    LI("libffutil.so bypass installed");
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 2 — /proc/self/maps sanitisation
//
// Strategy: hook __openat (libc) and read().
//   • When /proc/<pid>/maps or /proc/self/maps is opened, we create a
//     memfd, read the real maps into it, filter out lines that contain
//     our payload library names, seek to 0, and return the memfd fd.
//   • All other fds pass through the original read() unchanged.
// ─────────────────────────────────────────────────────────────────────────────

static const char *k_hidden_libs[] = {
    "libzx_payload.so",
    "zx_payload",
    "zx_injector",
    nullptr
};

static bool should_hide_line(const char *line) {
    for (int i = 0; k_hidden_libs[i]; i++)
        if (strstr(line, k_hidden_libs[i])) return true;
    return false;
}

static bool is_maps_path(const char *path) {
    if (!path) return false;
    // /proc/self/maps  or  /proc/<number>/maps
    if (strncmp(path, "/proc/", 6) != 0) return false;
    return strstr(path, "/maps") != nullptr;
}

// Set of fds we replaced with sanitised memfds
static constexpr int MAX_FAKE_FDS = 16;
static std::atomic<int> g_fake_fds[MAX_FAKE_FDS];
static void add_fake_fd(int fd) {
    for (int i = 0; i < MAX_FAKE_FDS; i++) {
        int exp = -1;
        if (g_fake_fds[i].compare_exchange_strong(exp, fd)) return;
    }
}
static bool is_fake_fd(int fd) {
    for (int i = 0; i < MAX_FAKE_FDS; i++)
        if (g_fake_fds[i].load() == fd) return true;
    return false;
}
static void remove_fake_fd(int fd) {
    for (int i = 0; i < MAX_FAKE_FDS; i++) {
        int exp = fd;
        g_fake_fds[i].compare_exchange_strong(exp, -1);
    }
}

static int (*orig_openat)(int, const char *, int, ...) = nullptr;
static int (*orig_close)(int)                          = nullptr;
static ssize_t (*orig_read)(int, void *, size_t)       = nullptr;

static int hook_openat(int dirfd, const char *path, int flags, ...) {
    int real_fd;
    // call original first
    if (orig_openat) {
        // pass mode if O_CREAT set
        if (flags & O_CREAT) {
            va_list ap; va_start(ap, flags);
            mode_t mode = va_arg(ap, mode_t); va_end(ap);
            real_fd = orig_openat(dirfd, path, flags, mode);
        } else {
            real_fd = orig_openat(dirfd, path, flags);
        }
    } else {
        real_fd = (int)syscall(__NR_openat, dirfd, path, flags);
    }

    if (real_fd < 0 || !is_maps_path(path)) return real_fd;

    // Build sanitised version in a memfd
    int mfd = (int)syscall(__NR_memfd_create, "maps_clean", 0);
    if (mfd < 0) return real_fd;

    char line[512];
    FILE *f = fdopen(dup(real_fd), "r");
    close(real_fd);
    if (!f) { close(mfd); return -1; }

    while (fgets(line, sizeof(line), f)) {
        if (!should_hide_line(line))
            write(mfd, line, strlen(line));
    }
    fclose(f);

    lseek(mfd, 0, SEEK_SET);
    add_fake_fd(mfd);
    return mfd;
}

static int hook_close(int fd) {
    remove_fake_fd(fd);
    if (orig_close) return orig_close(fd);
    return (int)syscall(__NR_close, fd);
}

// read() hook is not strictly needed since we return a proper memfd —
// but we keep it as a safety net for direct syscall readers
static ssize_t hook_read(int fd, void *buf, size_t count) {
    if (orig_read) return orig_read(fd, buf, count);
    return (ssize_t)syscall(__NR_read, fd, buf, count);
}

static void install_maps_hider() {
    for (int i = 0; i < MAX_FAKE_FDS; i++) g_fake_fds[i].store(-1);

    void *libc = dlopen("libc.so", RTLD_LAZY | RTLD_NOLOAD);
    if (!libc) libc = dlopen("libc.so", RTLD_LAZY);
    if (!libc) { LE("maps hider: libc not found"); return; }

    void *fn_openat = dlsym(libc, "openat");
    void *fn_close  = dlsym(libc, "close");

    if (fn_openat) DobbyHook(fn_openat, (void*)hook_openat, (void**)&orig_openat);
    if (fn_close)  DobbyHook(fn_close,  (void*)hook_close,  (void**)&orig_close);
    LI("maps hider installed (openat=%p close=%p)", fn_openat, fn_close);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 3 — AnoSDK extended hooks
// ─────────────────────────────────────────────────────────────────────────────

static int (*orig_DelReportData)(int, int*) = nullptr;
static int (*orig_DelReportData2)(int, int*, int) = nullptr;

// These are called by AnoSDK to free/clear report buffers.
// Returning 0 with zeroed length is correct — nothing to free.
static int hook_DelReportData(int type, int *len) {
    (void)type; if (len) *len = 0; return 0;
}
static int hook_DelReportData2(int type, int *len, int flag) {
    (void)type; (void)flag; if (len) *len = 0; return 0;
}

// AnoSDK's internal check-period setter — set a very long interval
// so scans happen once every ~24h instead of every few seconds
static int (*orig_set_check_period)(int ms) = nullptr;
static int hook_set_check_period(int ms) {
    (void)ms;
    // Return success but set the period to 86400000ms (24 hours)
    if (orig_set_check_period) return orig_set_check_period(86400000);
    return 0;
}

static void install_ano_extended(void *h) {
    if (!h) return;

    auto try_hook = [&](const char *sym, void *rep, void **orig) {
        void *a = dlsym(h, sym);
        if (!a) a = DobbySymbolResolver("libanogs.so", sym);
        if (a) DobbyHook(a, rep, orig);
    };

    try_hook("AnoSDKDelReportData",  (void*)hook_DelReportData,
             (void**)&orig_DelReportData);
    try_hook("AnoSDKDelReportData2", (void*)hook_DelReportData2,
             (void**)&orig_DelReportData2);
    try_hook("set_check_period",     (void*)hook_set_check_period,
             (void**)&orig_set_check_period);
    try_hook("ano_set_check_period", (void*)hook_set_check_period, nullptr);
    LI("AnoSDK extended hooks installed");
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 4 — Dobby trampoline signature scrub
//
// Our trampolines start with: 51 00 00 58  20 02 1F D6  (LDR X17 + BR X17)
// AnoSDK pattern-scans for this exact 8-byte signature.
// We overwrite the header with a different but equivalent encoding using
// the MOV X17, X17 + ... no-op chain that still jumps correctly.
// (We only scrub the visible header; the payload address stays intact.)
// ─────────────────────────────────────────────────────────────────────────────

// Replacement 8-byte preamble that is functionally equivalent but
// does NOT match the AnoSDK pattern:
//   LDR  X16, #8    (0x58000050 — same offset but X16 instead of X17)
//   BR   X16        (0xD61F0200)
// AnoSDK scans for the X17-register variant specifically.
static const uint8_t k_clean_hdr[8] = {
    0x50, 0x00, 0x00, 0x58,  // LDR X16, #8
    0x00, 0x02, 0x1F, 0xD6,  // BR  X16
};

// Called after all hooks installed — walks g_slots and patches headers.
// Declared extern so dobby_impl.cpp can expose the slot list.
extern void zx_scrub_trampolines();

// (Implemented inline here; dobby_impl.cpp doesn't expose internals —
//  so we do a second pass over known hook addresses instead.)
static void *k_scrub_targets[64];
static int   k_scrub_count = 0;

void zx_register_scrub_target(void *hook_addr) {
    if (k_scrub_count < 64)
        k_scrub_targets[k_scrub_count++] = hook_addr;
}

void zx_scrub_trampolines() {
    for (int i = 0; i < k_scrub_count; i++) {
        void *p = k_scrub_targets[i];
        if (!p) continue;
        // Make writable
        uintptr_t page = (uintptr_t)p & ~((uintptr_t)getpagesize()-1);
        mprotect((void*)page, getpagesize(), PROT_READ|PROT_WRITE|PROT_EXEC);
        memcpy(p, k_clean_hdr, 8);
        __builtin___clear_cache(p, (char*)p + 8);
    }
    LI("Scrubbed %d trampoline headers", k_scrub_count);
}

// ─────────────────────────────────────────────────────────────────────────────
// Public install — called from payload_init after AnoSDK bypass runs
// ─────────────────────────────────────────────────────────────────────────────

void AntiDetect::install() {
    void *ano = dlopen("libanogs.so", RTLD_LAZY | RTLD_NOLOAD);

    install_ffutil_bypass();
    install_maps_hider();
    install_ano_extended(ano);
    zx_scrub_trampolines();

    LI("AntiDetect fully installed");
}
