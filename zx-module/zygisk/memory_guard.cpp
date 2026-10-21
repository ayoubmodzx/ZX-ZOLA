#include "memory_guard.hpp"
#include "hook_engine.hpp"
#include <android/log.h>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <link.h>

#define TAG "ZX-MEM"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

#ifndef PR_SET_VMA
#define PR_SET_VMA            0x53564d41
#define PR_SET_VMA_ANON_NAME  0
#endif

static struct {
    uintptr_t base;
    size_t    size;
} g_self_range = {0, 0};

// ── Phase 3: dl_iterate_phdr hook ─────────────────────────────────────────────
// AnoSDK calls dl_iterate_phdr to enumerate every loaded library and check for
// injected .so files.  We intercept each callback invocation and silently skip
// our own entry — the scanner sees a clean library list with no trace of us.

struct DlHideCtx {
    int  (*user_cb)(struct dl_phdr_info *, size_t, void *);
    void  *user_data;
};
using DlIterateFn = int (*)(int (*)(struct dl_phdr_info *, size_t, void *), void *);
static DlIterateFn s_orig_dl_iterate = nullptr;

static int dl_hide_trampoline(struct dl_phdr_info *info, size_t sz, void *raw) {
    auto *ctx = static_cast<DlHideCtx *>(raw);
    // Skip by load bias — our base is the first mapped page
    if (g_self_range.base &&
        info->dlpi_addr >= g_self_range.base &&
        info->dlpi_addr <  g_self_range.base + g_self_range.size) {
        return 0;
    }
    // Belt-and-suspenders: also skip by name in case the base shifted
    if (info->dlpi_name && strstr(info->dlpi_name, "libzx_zola")) {
        return 0;
    }
    return ctx->user_cb(info, sz, ctx->user_data);
}

static int hook_dl_iterate_phdr(
        int (*cb)(struct dl_phdr_info *, size_t, void *), void *data) {
    if (!s_orig_dl_iterate) return 0;
    DlHideCtx ctx{ cb, data };
    return s_orig_dl_iterate(dl_hide_trampoline, &ctx);
}

// Walk /proc/self/maps to find our module's full loaded range
static bool findSelfRange(const char *so_name,
                           uintptr_t *out_base, size_t *out_size) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;

    char line[512];
    uintptr_t first_start = 0, last_end = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, so_name)) continue;
        uintptr_t start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) != 2) continue;
        if (!first_start) first_start = start;
        if (end > last_end) last_end = end;
    }
    fclose(fp);

    if (!first_start) return false;
    *out_base = first_start;
    *out_size = last_end - first_start;
    return true;
}

bool MemoryGuard::init() {
    // No external dependency — ELF-zeroing always available
    LOGI("MemoryGuard ready (ELF-zeroing + VMA-rename + dl_iterate_phdr hook)");
    return true;
}

bool MemoryGuard::hideSelf() {
    if (!findSelfRange("libzx_zola.so", &g_self_range.base, &g_self_range.size)) {
        LOGE("Could not locate libzx_zola.so in /proc/self/maps");
        return false;
    }

    uintptr_t base = g_self_range.base;
    size_t    sz   = g_self_range.size;

    // 1. Zero the ELF header (first 0x1000 bytes) via /proc/self/mem.
    //    AnoSDK's string scanner looks for the .so pathname stored in the ELF
    //    comment/build-id sections.  Zeroing the magic + program-headers
    //    removes both the "ELF" signature and the embedded path string.
    //    We write through /proc/self/mem instead of mprotect+memset so we
    //    never touch page protections of live code pages.
    int fd = open("/proc/self/mem", O_RDWR);
    if (fd >= 0) {
        uint8_t zeros[0x1000] = {};
        ssize_t written = pwrite(fd, zeros, sizeof(zeros), (off_t)base);
        close(fd);
        if (written > 0) {
            LOGI("ELF header zeroed at 0x%lx (%zd bytes)", base, (size_t)written);
        } else {
            LOGE("pwrite on /proc/self/mem failed");
        }
    } else {
        LOGE("open(/proc/self/mem) failed");
    }

    // 2. Rename the VMA to an empty anonymous name (kernel 5.17+ / Android 12+).
    //    This removes "libzx_zola.so" from /proc/self/maps entirely, so
    //    AnoSDK's maps-scanner sees it as a plain anonymous region.
    //    Best-effort — silently ignored on older kernels.
    prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME,
          reinterpret_cast<void *>(base), sz, nullptr);

    // 3. Hook dl_iterate_phdr so any linker-level library enumeration by AnoSDK
    //    skips us entirely.  The hook wraps the user-supplied callback and drops
    //    the invocation for our own phdr entry — invisible to all callers
    //    including AnoSDK's inline-hook detector and library scanner.
    //    Both libc.so paths (the exported symbol and the PLT slot in libanogs.so)
    //    are covered because Dobby patches the export in libc.so itself.
    HookEngine::get().hookSym("libc.so", "dl_iterate_phdr",
        reinterpret_cast<void *>(hook_dl_iterate_phdr),
        reinterpret_cast<void **>(&s_orig_dl_iterate),
        "DlIterHide");

    LOGI("Self hidden: base=0x%lx size=0x%zx — ELF zeroed / VMA renamed / dl_iterate hooked",
         base, sz);
    return true;
}

bool MemoryGuard::hideRegion(void *addr, size_t size) {
    int fd = open("/proc/self/mem", O_RDWR);
    if (fd < 0) return false;
    uint8_t zeros[0x1000] = {};
    // Zero up to 4 KiB at addr — enough to destroy any ELF/PE signature
    size_t chunk = size < sizeof(zeros) ? size : sizeof(zeros);
    ssize_t n = pwrite(fd, zeros, chunk, (off_t)reinterpret_cast<uintptr_t>(addr));
    close(fd);
    return n > 0;
}

void MemoryGuard::restore() {
    // Remap as anonymous so /proc/self/maps shows the region again (clean shutdown only)
    if (g_self_range.base && g_self_range.size) {
        mmap(reinterpret_cast<void *>(g_self_range.base), g_self_range.size,
             PROT_READ | PROT_EXEC,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    }
}
