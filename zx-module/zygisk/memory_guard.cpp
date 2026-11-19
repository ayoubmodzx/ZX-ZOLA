#include "memory_guard.hpp"
#include <android/log.h>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#define TAG "GC"
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

// Walk /proc/self/maps to find our module's full loaded range.
// MUST use raw syscalls — our openat hook filters out the so_name lines,
// so fopen("/proc/self/maps") would return a filtered view that hides us.
static bool findSelfRange(const char *so_name,
                           uintptr_t *out_base, size_t *out_size) {
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY, 0);
    if (fd < 0) return false;

    char buf[4096];
    char line[512];
    int llen = 0;
    uintptr_t first_start = 0, last_end = 0;

    for (;;) {
        ssize_t n = (ssize_t)syscall(SYS_read, fd, buf, sizeof(buf));
        if (n <= 0) break;
        for (ssize_t i = 0; i < n; i++) {
            char c = buf[i];
            if (llen < (int)sizeof(line) - 1) line[llen++] = c;
            if (c == '\n' || llen >= (int)sizeof(line) - 1) {
                line[llen] = '\0';
                if (strstr(line, so_name)) {
                    uintptr_t start, end;
                    if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                        if (!first_start) first_start = start;
                        if (end > last_end) last_end = end;
                    }
                }
                llen = 0;
            }
        }
    }
    syscall(SYS_close, fd);

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
    Dl_info dli;
    if (!dladdr((void *)&MemoryGuard::hideSelf, &dli) || !dli.dli_fbase) {
        LOGE("dladdr failed — cannot locate module base");
        return false;
    }

    uintptr_t base = (uintptr_t)dli.dli_fbase;
    LOGI("dladdr: base=0x%lx fname=%s", base, dli.dli_fname ? dli.dli_fname : "(null)");

    // Calculate loaded size from ELF program headers.
    // hideModuleMaps() already converted file-backed regions to anonymous,
    // but content (including ELF headers) is still intact in memory.
    size_t total_size = 0;
    auto *ehdr = reinterpret_cast<Elf64_Ehdr *>(base);
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0 && ehdr->e_phoff != 0) {
        auto *phdr = reinterpret_cast<Elf64_Phdr *>(base + ehdr->e_phoff);
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_LOAD) {
                size_t seg_end = phdr[i].p_vaddr + phdr[i].p_memsz;
                if (seg_end > total_size) total_size = seg_end;
            }
        }
        total_size = (total_size + 4095) & ~(size_t)4095;
    }
    if (total_size == 0) total_size = 0x100000;

    g_self_range.base = base;
    g_self_range.size = total_size;

    // Zero the ELF header (first 0x1000 bytes) via /proc/self/mem.
    // Removes ELF magic, program headers, and embedded path strings.
    // hideModuleMaps already anonymized the VMA, but the ELF signature
    // is still in memory — AnoSDK's memory scanner looks for it.
    int fd = open("/proc/self/mem", O_RDWR);
    if (fd >= 0) {
        uint8_t zeros[0x1000] = {};
        ssize_t written = pwrite(fd, zeros, sizeof(zeros), (off_t)base);
        close(fd);
        if (written > 0)
            LOGI("ELF header zeroed at 0x%lx (%zd bytes)", base, (size_t)written);
        else
            LOGE("pwrite on /proc/self/mem failed");
    } else {
        LOGE("open(/proc/self/mem) failed");
    }

    // VMA rename — defense-in-depth (hideModuleMaps already did this for
    // regions it found, but covers any segments it may have missed)
    prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME,
          reinterpret_cast<void *>(base), total_size, nullptr);

    LOGI("Self hidden: base=0x%lx size=0x%zx — ELF zeroed / VMA renamed",
         base, total_size);
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
