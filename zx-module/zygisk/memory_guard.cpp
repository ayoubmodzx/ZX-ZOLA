#include "memory_guard.hpp"
#include <dlfcn.h>
#include <link.h>
#include <sys/mman.h>
#include <android/log.h>
#include <cstdio>
#include <cstring>
#include <vector>

#define TAG "ZX-MEM"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// libffutil.so exports — FF's own memory hiding utility
static void (*ffutil_UnmapAddr)(uintptr_t addr)           = nullptr;
static void (*ffutil_UnmapSize)(uintptr_t addr, size_t sz) = nullptr;

static struct {
    uintptr_t base;
    size_t    size;
} g_self_range = {0, 0};

// Walk /proc/self/maps to find our module's loaded range
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
    void *handle = dlopen("libffutil.so", RTLD_LAZY | RTLD_NOLOAD);
    if (!handle) {
        // libffutil may not be loaded yet — try loading it
        handle = dlopen("libffutil.so", RTLD_LAZY | RTLD_GLOBAL);
    }
    if (!handle) {
        LOGE("libffutil.so not found: %s", dlerror());
        return false;
    }

    ffutil_UnmapAddr = reinterpret_cast<void(*)(uintptr_t)>(
                            dlsym(handle, "ffutil_UnmapAddr"));
    ffutil_UnmapSize = reinterpret_cast<void(*)(uintptr_t, size_t)>(
                            dlsym(handle, "ffutil_UnmapSize"));

    if (!ffutil_UnmapAddr || !ffutil_UnmapSize) {
        LOGE("ffutil symbols missing");
        return false;
    }

    LOGI("MemoryGuard ready");
    return true;
}

bool MemoryGuard::hideSelf() {
    // Find our own .so in /proc/maps
    if (!findSelfRange("libzx_zola.so", &g_self_range.base, &g_self_range.size)) {
        LOGE("Could not locate self in /proc/maps");
        return false;
    }

    if (ffutil_UnmapSize) {
        ffutil_UnmapSize(g_self_range.base, g_self_range.size);
        LOGI("Self hidden: base=0x%lx size=0x%zx",
             g_self_range.base, g_self_range.size);
        return true;
    }
    return false;
}

bool MemoryGuard::hideRegion(void *addr, size_t size) {
    if (!ffutil_UnmapSize) return false;
    ffutil_UnmapSize(reinterpret_cast<uintptr_t>(addr), size);
    return true;
}

void MemoryGuard::restore() {
    // mmap the range back as anonymous so /proc/maps shows it again
    // (called on clean shutdown only)
    if (g_self_range.base && g_self_range.size) {
        mmap(reinterpret_cast<void *>(g_self_range.base),
             g_self_range.size,
             PROT_READ | PROT_EXEC,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
             -1, 0);
    }
}
