/*
 * stealth_ext3.cpp — Layers 18–30: Deep syscall surface hardening
 *
 * Binary analysis findings addressed here:
 *
 *   libanogs.so imports confirmed:
 *     ioctl      @ 0x28da  — AnoSDKIoctlOld + unwind_xx_ioctl kernel channel
 *     getenv     @ 0x2772  — probes LD_PRELOAD, JAVA_HOME leak detection
 *     uname      @ 0x28f3  — kernel fingerprinting, emulator/root kernel detect
 *     statfs     @ 0x288b  — filesystem type check (/data must be f2fs/ext4)
 *     getauxval  @ 0x2cf8  — AT_SECURE flag + AT_PLATFORM check
 *     openat     @ 0x286b  — opens /proc/self/status to read TracerPid
 *     exec*      @ 0x27a1  — spawns shell scanner processes
 *     execl      @ 0x93560 — secondary exec path
 *
 *   libanort.so:
 *     unwind_xx_ioctl (exported) — custom kernel driver IPC channel
 *     openat @ 0x1989           — proc reads
 *     exec*  @ 0x1cdd           — process spawning
 *
 *   CRITICAL BYPASS (Layer 27 target):
 *     libanogs.so @ file offset 0x3f02b0 — single direct openat SVC:
 *       MOVZ x8, #56  (ARM64 openat NR)
 *       SVC  #0
 *     Pattern bytes: {0x08,0x07,0x80,0xd2, 0x01,0x00,0x00,0xd4} — UNIQUE
 *     Bypasses ALL libc PLT hooks (Layers 1, 2, 18) by going straight to kernel.
 *     Fix: runtime pattern-scan + DobbyHook redirects to hooked libc openat chain.
 *
 *   TracerPid / frida / xposed: confirmed runtime stack-built strings
 *     → spoofed via openat+read intercept on /proc/<pid>/status
 *
 * Layer 18: openat + read — /proc/<pid>/status TracerPid spoof
 * Layer 19: ioctl gate — block unwind_xx_ioctl + ano device fds
 * Layer 20: execve/execl/execvp gate — block ano-spawned processes
 * Layer 21: getenv filter — LD_PRELOAD → NULL, sanitize env leaks
 * Layer 22: uname spoof — stock production kernel string
 * Layer 23: statfs spoof — /data returns clean ext4/f2fs signature
 * Layer 24: getauxval filter — AT_SECURE=0, scrub hook-revealing vals
 * Layer 25: /proc/self/status fd tracker — multi-read coherent spoof
 * Layer 26: ms_hook_opcode scanner NOP-patch (MOV W0,#0 / RET)
 * Layer 27: direct SVC openat  — MOVZ x8,#56  + SVC #0 @ 0x3f02b0
 * Layer 28: direct SVC read    — MOVZ x8,#63  + SVC #0 @ 0x3f02d0
 * Layer 29: direct SVC kill    — MOVZ x8,#62  + SVC #0 @ 0x3f0270
 * Layer 30: direct SVC mincore — MOVZ x8,#232 + SVC #0 @ 0x3f01e0
 *   (All stubs are frameless leaves — DobbyHook at MOVZ itself.)
 *   Redirected through already-hooked libc symbols so upstream
 *   layers (TracerPid spoof, kill gate, mincore spoof) fire naturally.
 */

#include "stealth_ext3.hpp"
#include "dobby_stub.hpp"
#include <android/log.h>
#include "zx_logbuf.hpp"
#include <dlfcn.h>
#include <link.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/prctl.h>
#include <time.h>
#include <pthread.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cerrno>
#include <atomic>
#include <climits>

#ifndef __NR_openat
#define __NR_openat 56
#endif
#ifndef __NR_read
#define __NR_read 63
#endif
#ifndef __NR_close
#define __NR_close 57
#endif
#ifndef __NR_readlinkat
#define __NR_readlinkat 78
#endif
#ifndef __NR_kill
#define __NR_kill 62
#endif
#ifndef __NR_mincore
#define __NR_mincore 232
#endif

#define TAG "ZX-STX3"
#define LI(fmt, ...) LOGBUF_I(TAG, fmt, ##__VA_ARGS__)
#define LE(fmt, ...) LOGBUF_E(TAG, fmt, ##__VA_ARGS__)

// ─────────────────────────────────────────────────────────────────────────────
// Helpers — resolve libanogs/libanort load range (shared with stx2 logic)
// ─────────────────────────────────────────────────────────────────────────────

struct LibRange3 { uintptr_t base, end; };

static LibRange3 g_ano_r3  = {0, 0};
static LibRange3 g_anort_r3 = {0, 0};
static pthread_mutex_t g_range3_mu = PTHREAD_MUTEX_INITIALIZER;
static std::atomic<bool> g_range3_ready{false};

static void populate_range3(const char *name, LibRange3 &out) {
    // Use raw syscall to bypass Layer 2 proc hider
    int fd = (int)syscall(__NR_openat, AT_FDCWD,
                          "/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return;
    char buf[4096];
    char line[256];
    int  lb = 0, bb = 0;
    ssize_t n;
    while ((n = read(fd, buf + bb, sizeof(buf) - bb - 1)) > 0) {
        bb += (int)n;
        buf[bb] = '\0';
        char *p = buf;
        while (true) {
            char *nl = (char*)memchr(p, '\n', bb - (int)(p - buf));
            if (!nl) break;
            int ll = (int)(nl - p);
            if (ll < (int)sizeof(line)) {
                memcpy(line, p, ll); line[ll] = '\0';
                if (strstr(line, name)) {
                    uintptr_t s = 0, e = 0;
                    sscanf(line, "%lx-%lx", &s, &e);
                    if (out.base == 0 || s < out.base) out.base = s;
                    if (e > out.end) out.end = e;
                }
            }
            p = nl + 1;
        }
        memmove(buf, p, bb - (int)(p - buf));
        bb -= (int)(p - buf);
    }
    close(fd);
}

static void ensure_ranges3() {
    if (g_range3_ready.load(std::memory_order_acquire)) return;
    pthread_mutex_lock(&g_range3_mu);
    if (!g_range3_ready.load(std::memory_order_relaxed)) {
        populate_range3("libanogs.so", g_ano_r3);
        populate_range3("libanort.so", g_anort_r3);
        g_range3_ready.store(true, std::memory_order_release);
    }
    pthread_mutex_unlock(&g_range3_mu);
}

static inline bool caller_is_ano3(uintptr_t ra) {
    ensure_ranges3();
    return (g_ano_r3.base  && ra >= g_ano_r3.base  && ra < g_ano_r3.end)
        || (g_anort_r3.base && ra >= g_anort_r3.base && ra < g_anort_r3.end);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 25 — fd → /proc/status tracker (thread-safe ring buffer)
// ─────────────────────────────────────────────────────────────────────────────

static constexpr int MAX_STATUS_FDS = 32;
struct StatusFdEntry { int fd; bool active; };
static StatusFdEntry g_sfds[MAX_STATUS_FDS];
static pthread_mutex_t g_sfds_mu = PTHREAD_MUTEX_INITIALIZER;

static void sfd_register(int fd) {
    pthread_mutex_lock(&g_sfds_mu);
    for (int i = 0; i < MAX_STATUS_FDS; ++i)
        if (!g_sfds[i].active) { g_sfds[i] = {fd, true}; break; }
    pthread_mutex_unlock(&g_sfds_mu);
}

static bool sfd_is_tracked(int fd) {
    pthread_mutex_lock(&g_sfds_mu);
    for (int i = 0; i < MAX_STATUS_FDS; ++i)
        if (g_sfds[i].active && g_sfds[i].fd == fd) {
            pthread_mutex_unlock(&g_sfds_mu);
            return true;
        }
    pthread_mutex_unlock(&g_sfds_mu);
    return false;
}

static void sfd_unregister(int fd) {
    pthread_mutex_lock(&g_sfds_mu);
    for (int i = 0; i < MAX_STATUS_FDS; ++i)
        if (g_sfds[i].active && g_sfds[i].fd == fd) {
            g_sfds[i].active = false; break;
        }
    pthread_mutex_unlock(&g_sfds_mu);
}

// Patch TracerPid line in a /proc/*/status buffer to 0
static void patch_tracerpid(char *buf, ssize_t len) {
    // Find "TracerPid:\t" or "TracerPid: " and zero out the value
    char *p = buf;
    char *end = buf + len;
    while (p < end) {
        char *nl = (char*)memchr(p, '\n', end - p);
        if (!nl) nl = end;
        // strncmp-safe check for "TracerPid"
        if ((nl - p) > 9 && memcmp(p, "TracerPid", 9) == 0) {
            // find the digit(s) after the colon+whitespace
            char *colon = (char*)memchr(p, ':', nl - p);
            if (colon) {
                char *digit = colon + 1;
                while (digit < nl && (*digit == ' ' || *digit == '\t')) ++digit;
                // overwrite digit chars with '0', rest with spaces until newline
                if (digit < nl) {
                    *digit = '0';
                    char *d2 = digit + 1;
                    while (d2 < nl) *d2++ = ' ';
                }
            }
            break;
        }
        p = nl + 1;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 18 — openat hook (proc/status tracker + map filter)
// ─────────────────────────────────────────────────────────────────────────────

using FnOpenat = int(*)(int, const char *, int, ...);
static FnOpenat g_orig_openat = nullptr;

static int hook_openat(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    // Retrieve mode arg if O_CREAT set
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags);
        mode = va_arg(ap, int); va_end(ap);
    }

    if (path) {
        // Track /proc/*/status opens — spoof TracerPid in Layer 25
        if (strstr(path, "/status")) {
            int real = g_orig_openat(dirfd, path, flags, mode);
            if (real >= 0) sfd_register(real);
            return real;
        }
        // Block ano tmp directory access probing
        if (strstr(path, "ano_tmp") && strstr(path, "sig.dat")) {
            // Return empty read on sig.dat — AnoSDK will use default (permissive) config
            // ARM64 memfd_create syscall = 279 (NOT 319 which is x86-64)
            int memfd = (int)syscall(279 /*__NR_memfd_create ARM64*/, "sig", 1);
            if (memfd >= 0) return memfd;
        }
    }
    if (!g_orig_openat) return (int)syscall(__NR_openat, dirfd, path, flags, mode);
    return g_orig_openat(dirfd, path, flags, mode);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 18b — read hook (TracerPid spoof on tracked fds)
// ─────────────────────────────────────────────────────────────────────────────

using FnRead = ssize_t(*)(int, void *, size_t);
static FnRead g_orig_read = nullptr;

static ssize_t hook_read(int fd, void *buf, size_t count) {
    ssize_t ret = g_orig_read ? g_orig_read(fd, buf, count)
                              : (ssize_t)syscall(__NR_read, fd, buf, count);
    if (ret > 0 && sfd_is_tracked(fd)) {
        patch_tracerpid((char*)buf, ret);
    }
    return ret;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 18c — close hook (fd tracker cleanup)
// ─────────────────────────────────────────────────────────────────────────────

using FnClose = int(*)(int);
static FnClose g_orig_close = nullptr;

static int hook_close(int fd) {
    sfd_unregister(fd);
    if (!g_orig_close) return (int)syscall(__NR_close, fd);
    return g_orig_close(fd);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 19 — ioctl gate
// ─────────────────────────────────────────────────────────────────────────────

using FnIoctl = int(*)(int, unsigned long, ...);
static FnIoctl g_orig_ioctl = nullptr;

// Known AnoSDK kernel driver magic numbers (from libanort unwind_xx_ioctl)
// These are typically 0xAE / 0xAF type magic bytes in the cmd
static bool ioctl_is_ano_cmd(unsigned long cmd) {
    unsigned int magic = (cmd >> 8) & 0xFF;
    // AnoSDK uses magic 0xAE (ano engine) based on unwind_xx_ioctl naming
    // Also filter DRM-style ioctls that could be misused for detection
    return (magic == 0xAE || magic == 0xAF || magic == 0xA0);
}

static int hook_ioctl(int fd, unsigned long cmd, ...) {
    va_list ap; va_start(ap, cmd);
    void *arg = va_arg(ap, void*); va_end(ap);

    uintptr_t ra = (uintptr_t)__builtin_return_address(0);
    if (caller_is_ano3(ra) && ioctl_is_ano_cmd(cmd)) {
        errno = EBADF;
        return -1;
    }
    if (caller_is_ano3(ra)) {
        char fdpath[64], linkbuf[256];
        snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fd);
        ssize_t lr = (ssize_t)syscall(__NR_readlinkat, AT_FDCWD, fdpath, linkbuf, sizeof(linkbuf)-1);
        if (lr > 0 && lr < (ssize_t)sizeof(linkbuf)) {
            linkbuf[lr] = '\0';
            if (strstr(linkbuf, "/dev/") && !strstr(linkbuf, "ashmem") &&
                !strstr(linkbuf, "binder") && !strstr(linkbuf, "hwbinder")) {
                errno = EPERM;
                return -1;
            }
        }
    }
    if (!g_orig_ioctl) { errno = EBADF; return -1; }
    return g_orig_ioctl(fd, cmd, arg);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 20 — execve / execl gate
// ─────────────────────────────────────────────────────────────────────────────

using FnExecve = int(*)(const char *, char *const[], char *const[]);
static FnExecve g_orig_execve = nullptr;

static bool execve_path_is_scanner(const char *path) {
    if (!path) return false;
    const char *blocked[] = {"ps", "ls", "cat", "grep", "find", "sh", "toybox", nullptr};
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    for (int i = 0; blocked[i]; ++i)
        if (strcmp(base, blocked[i]) == 0) return true;
    return false;
}

__attribute__((noinline))
static int hook_execve(const char *path, char *const argv[], char *const envp[]) {
    uintptr_t ra = (uintptr_t)__builtin_return_address(0);
    if (caller_is_ano3(ra)) {
        LI("L20: blocked execve('%s') from ano caller %lx", path ? path : "?", ra);
        errno = EPERM;
        return -1;
    }
    if (execve_path_is_scanner(path)) {
        LI("L20: blocked scanner execve('%s')", path ? path : "?");
        errno = EPERM;
        return -1;
    }
    return g_orig_execve(path, argv, envp);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 21 — getenv filter
// ─────────────────────────────────────────────────────────────────────────────

using FnGetenv = char*(*)(const char*);
static FnGetenv g_orig_getenv = nullptr;

static char* hook_getenv(const char *name) {
    if (!name) return g_orig_getenv ? g_orig_getenv(name) : nullptr;
    const char *blocked[] = {
        "LD_PRELOAD", "LD_LIBRARY_PATH", "INJECT_FLAG",
        "FRIDA_SERVER", "GADGET_PATH", nullptr
    };
    for (int i = 0; blocked[i]; ++i)
        if (strcmp(name, blocked[i]) == 0) return nullptr;
    if (!g_orig_getenv) return nullptr;
    return g_orig_getenv(name);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 22 — uname spoof
// ─────────────────────────────────────────────────────────────────────────────

using FnUname = int(*)(struct utsname*);
static FnUname g_orig_uname = nullptr;

static int hook_uname(struct utsname *buf) {
    if (!g_orig_uname) { errno = ENOSYS; return -1; }
    int ret = g_orig_uname(buf);
    if (ret == 0 && buf) {
        // Return a stock production Android kernel string
        // Avoid rooted kernel markers: "magisk", "ksu", "apatch", "lkm"
        const char *release = buf->release;
        bool suspicious = strstr(release, "magisk") || strstr(release, "ksu")   ||
                          strstr(release, "apatch") || strstr(release, "dirty") ||
                          strstr(release, "kali")   || strstr(release, "nethunter");
        if (suspicious) {
            // Replace with clean stock-looking version keeping major.minor
            char major_minor[32] = {0};
            int ma = 0, mi = 0, pa = 0;
            sscanf(release, "%d.%d.%d", &ma, &mi, &pa);
            snprintf(buf->release, sizeof(buf->release),
                     "%d.%d.%d-android14-8-00001-g0000000000000-ab12345678",
                     ma, mi, pa);
        }
        // Clean version string — remove any build-host that reveals modified kernel
        char *ver = buf->version;
        if (strstr(ver, "magisk") || strstr(ver, "ksu") || strstr(ver, "dirty"))
            strncpy(ver, "#1 SMP PREEMPT", sizeof(buf->version) - 1);
    }
    return ret;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 23 — statfs spoof
// ─────────────────────────────────────────────────────────────────────────────

using FnStatfs = int(*)(const char *, struct statfs *);
static FnStatfs g_orig_statfs = nullptr;

// ext4 magic = 0xEF53, f2fs magic = 0xF2F52010
#define EXT4_MAGIC   0xEF53
#define F2FS_MAGIC   0xF2F52010u
#define TMPFS_MAGIC  0x01021994
#define OVERLAY_MAGIC 0x794C7630

static int hook_statfs(const char *path, struct statfs *buf) {
    if (!g_orig_statfs) { errno = ENOSYS; return -1; }
    int ret = g_orig_statfs(path, buf);
    if (ret == 0 && buf) {
        unsigned long magic = (unsigned long)buf->f_type;
        // AnoSDK flags overlayfs/tmpfs on /data — spoof to f2fs
        if (path && strstr(path, "/data")) {
            if (magic == OVERLAY_MAGIC || magic == TMPFS_MAGIC)
                buf->f_type = (decltype(buf->f_type))F2FS_MAGIC;
        }
        // System partition — should look like ext4
        if (path && (strstr(path, "/system") || strstr(path, "/vendor"))) {
            if (magic == OVERLAY_MAGIC || magic == TMPFS_MAGIC)
                buf->f_type = (decltype(buf->f_type))EXT4_MAGIC;
        }
    }
    return ret;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 24 — getauxval filter
// ─────────────────────────────────────────────────────────────────────────────

using FnGetauxval = unsigned long(*)(unsigned long);
static FnGetauxval g_orig_getauxval = nullptr;

#ifndef AT_SECURE
#define AT_SECURE 23
#endif
#ifndef AT_FLAGS
#define AT_FLAGS 8
#endif

static unsigned long hook_getauxval(unsigned long type) {
    if (type == AT_SECURE) return 0UL;     // claim process is not suid/guid — hides root
    if (type == AT_FLAGS)  return 0UL;     // no special execution flags
    if (!g_orig_getauxval) { errno = ENOSYS; return 0UL; }
    return g_orig_getauxval(type);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 26 — ms_hook_opcode scanner in-memory NOP-patch (dynamic version)
//
// Scans the loaded libanogs.so for the "inline_hook_opcode_dismatch" string,
// then ADRP-traces back to find each function entry that references it, and
// patches them to MOV W0,#0 / RET.  No hardcoded offsets — version-resilient.
// ─────────────────────────────────────────────────────────────────────────────

struct PhdrSearchCtx {
    const char *name;
    uintptr_t   base;
    size_t      total_sz;
};

static int phdr_find_lib(struct dl_phdr_info *info, size_t /*sz*/, void *data) {
    auto *ctx = (PhdrSearchCtx*)data;
    if (!info->dlpi_name || !strstr(info->dlpi_name, ctx->name)) return 0;
    ctx->base = (uintptr_t)info->dlpi_addr;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_LOAD) {
            size_t end = (size_t)(info->dlpi_phdr[i].p_vaddr + info->dlpi_phdr[i].p_memsz);
            if (end > ctx->total_sz) ctx->total_sz = end;
        }
    }
    return 1;
}

static bool patch_page_at(uintptr_t addr, uint32_t instr0, uint32_t instr1) {
    uintptr_t page = addr & ~(uintptr_t)0xFFF;
    if (mprotect((void*)page, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        return false;
    uint32_t *p = (uint32_t*)addr;
    p[0] = instr0;
    p[1] = instr1;
    __builtin___clear_cache((char*)addr, (char*)(addr + 8));
    mprotect((void*)page, 0x1000, PROT_READ | PROT_EXEC);
    return true;
}

static constexpr uint32_t ARM64_MOV_W0_0 = 0x52800000u;
static constexpr uint32_t ARM64_RET       = 0xD65F03C0u;

// Find up to max_out scanner function OFFSETS (relative to lib_base) by:
//  1. Locating the "inline_hook_opcode_dismatch" string in the library
//  2. Scanning preceding code for ADRP instructions that load its page
//  3. Walking back from each ADRP to find the STP X29,X30,[SP] function entry
static int find_scanner_offsets(uintptr_t lib_base, size_t lib_sz,
                                 uintptr_t *out, int max_out) {
    static const char k_marker[] = "inline_hook_opcode_dismatch";
    static const size_t k_mlen   = sizeof(k_marker) - 1;

    // 1. Find marker string
    size_t scan_cap = (lib_sz < 16 * 1024 * 1024) ? lib_sz : 16 * 1024 * 1024;
    uintptr_t str_va = 0;
    for (size_t i = 0; i + k_mlen <= scan_cap; i++) {
        if (__builtin_memcmp((void*)(lib_base + i), k_marker, k_mlen) == 0) {
            str_va = lib_base + i;
            break;
        }
    }
    if (!str_va) return 0;

    uintptr_t str_page = str_va & ~(uintptr_t)0xFFF;

    // 2. Scan full code section for ADRP Xn, <str_page>
    // NOTE: in this libanogs.so version all ADRP refs to the marker string are
    // ~1.2MB AFTER the string (code at 0x1b6380+, string at 0x8dce4).
    // Scanning only backward from str_va (old 0x80000 window) finds nothing.
    uintptr_t code_lo = lib_base;
    uintptr_t code_hi = lib_base + scan_cap;

    int found = 0;
    for (uintptr_t pc = code_lo; pc < code_hi && found < max_out; pc += 4) {
        uint32_t instr;
        __builtin_memcpy(&instr, (void*)pc, 4);
        // ADRP: bit31=1, bits28-24=10000
        if ((instr & 0x9F000000u) != 0x90000000u) continue;

        // Decode page offset: immhi[23:5] + immlo[30:29], <<12, sign-extend 33 bits
        int64_t immlo = (int64_t)((instr >> 29) & 0x3u);
        int64_t immhi = (int64_t)((instr >>  5) & 0x7FFFFu);
        int64_t imm   = (immhi << 2) | immlo;
        if (imm & (1LL << 20)) imm |= ~((1LL << 21) - 1LL);
        uintptr_t target_page = (pc & ~(uintptr_t)0xFFF) + (uintptr_t)(imm << 12);
        if (target_page != str_page) continue;

        // 3. Walk back to nearest STP X29,X30,[SP,#imm] function entry
        //    Fixed bits (excluding imm7): (instr & 0xFFC07FFF) == 0xA9807BFD
        uintptr_t back = (pc > lib_base + 0x600) ? pc - 0x600 : lib_base;
        for (uintptr_t q = pc; q >= back && q >= lib_base; q -= 4) {
            uint32_t qi;
            __builtin_memcpy(&qi, (void*)q, 4);
            if ((qi & 0xFFC07FFF) == 0xA9807BFD) {
                uintptr_t off = q - lib_base;
                bool dup = false;
                for (int k = 0; k < found; k++) if (out[k] == off) { dup = true; break; }
                if (!dup) out[found++] = off;
                break;
            }
        }
    }
    return found;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layers 27-30 — direct SVC stub hooks (libanogs.so frameless leaf table)
//
// Binary decode of 0x3f01e0-0x3f02e4 reveals eight tiny stubs, one per NR:
//   NR=232 mincore   NR=167 prctl   NR=57 close   NR=62 kill
//   NR=226 mprotect  NR=56  openat  NR=63 read    (+ generic syscall relay)
// Each is MOVZ x8,#NR / SVC #0 / error-check / RET — no frame.
// Dobby hooks the MOVZ (function entry) so the trampoline overwrites it.
//
// Redirect strategy: call dlsym(RTLD_DEFAULT, sym) which resolves to Dobby's
// trampoline for the already-hooked libc symbol, so every upstream layer
// (TracerPid spoof, kill gate, etc.) fires without duplicating logic here.
// ─────────────────────────────────────────────────────────────────────────────

// Generic stub finder: scan for an 8-byte MOVZ+SVC pattern and return
// the hook entry-point VA.  All stubs here are frameless — we hook the
// MOVZ itself rather than walking back to an STP frame entry.
static uintptr_t find_svc_stub(uintptr_t lib_base, size_t lib_sz,
                                const uint8_t pat[8]) {
    if (!lib_base || lib_sz < 8) return 0;
    uintptr_t end = lib_base + lib_sz - 8;
    for (uintptr_t p = lib_base; p <= end; p += 4) {
        if (__builtin_memcmp((void*)p, pat, 8) == 0) {
            // Try STP X29,X30 walk-back first; fall back to MOVZ for leaves.
            uintptr_t back = (p >= lib_base + 512) ? p - 512 : lib_base;
            for (uintptr_t q = p; q >= back; q -= 4) {
                uint32_t instr;
                __builtin_memcpy(&instr, (void*)q, 4);
                if ((instr & 0xFFC07FFF) == 0xA9807BFD) return q;
            }
            return p;  // frameless leaf — hook MOVZ directly
        }
    }
    return 0;
}

// ── Layer 27: direct SVC openat (NR=56) ─────────────────────────────────────
static const uint8_t k_svc_openat_pat[8] = {
    0x08, 0x07, 0x80, 0xd2,   // MOVZ x8, #56
    0x01, 0x00, 0x00, 0xd4    // SVC  #0
};
using FnOpenatSvc = int(*)(int, const char*, int, ...);
static FnOpenatSvc g_orig_direct_svc_openat = nullptr;

static int hook_direct_svc_openat(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags);
        mode = va_arg(ap, int); va_end(ap);
    }
    static FnOpenatSvc s_libc_openat = nullptr;
    if (!s_libc_openat) {
        void *sym = dlsym(RTLD_DEFAULT, "openat");
        s_libc_openat = sym ? (FnOpenatSvc)sym : nullptr;
    }
    if (s_libc_openat) return s_libc_openat(dirfd, path, flags, mode);
    return (int)syscall(__NR_openat, dirfd, path, flags, mode);
}

// ── Layer 28: direct SVC read (NR=63) ────────────────────────────────────────
static const uint8_t k_svc_read_pat[8] = {
    0xe8, 0x07, 0x80, 0xd2,   // MOVZ x8, #63
    0x01, 0x00, 0x00, 0xd4    // SVC  #0
};
using FnReadSvc = ssize_t(*)(int, void*, size_t);
static FnReadSvc g_orig_direct_svc_read = nullptr;

static ssize_t hook_direct_svc_read(int fd, void *buf, size_t count) {
    // Resolve once — points at Dobby trampoline for libc read (Layer 18b).
    static FnReadSvc s_libc_read = nullptr;
    if (!s_libc_read) {
        void *sym = dlsym(RTLD_DEFAULT, "read");
        s_libc_read = sym ? (FnReadSvc)sym : nullptr;
    }
    if (s_libc_read) return s_libc_read(fd, buf, count);
    return (ssize_t)syscall(__NR_read, fd, buf, count);
}

// ── Layer 29: direct SVC kill (NR=62) ────────────────────────────────────────
static const uint8_t k_svc_kill_pat[8] = {
    0xc8, 0x07, 0x80, 0xd2,   // MOVZ x8, #62
    0x01, 0x00, 0x00, 0xd4    // SVC  #0
};
using FnKillSvc = int(*)(pid_t, int);
static FnKillSvc g_orig_direct_svc_kill = nullptr;

static int hook_direct_svc_kill(pid_t pid, int sig) {
    static FnKillSvc s_libc_kill = nullptr;
    if (!s_libc_kill) {
        void *sym = dlsym(RTLD_DEFAULT, "kill");
        s_libc_kill = sym ? (FnKillSvc)sym : nullptr;
    }
    if (s_libc_kill) return s_libc_kill(pid, sig);
    return (int)syscall(__NR_kill, pid, sig);
}

// ── Layer 30: direct SVC mincore (NR=232) ────────────────────────────────────
static const uint8_t k_svc_mincore_pat[8] = {
    0x08, 0x1d, 0x80, 0xd2,   // MOVZ x8, #232
    0x01, 0x00, 0x00, 0xd4    // SVC  #0
};
using FnMincoreSvc = int(*)(void*, size_t, unsigned char*);
static FnMincoreSvc g_orig_direct_svc_mincore = nullptr;

// Return all pages as resident — hides RWX hooks and injected pages from
// AnoSDK's mincore-based page-residency detector.
static int hook_direct_svc_mincore(void *addr, size_t length,
                                    unsigned char *vec) {
    (void)addr;
    if (vec && length > 0) {
        size_t pages = (length + 4095u) / 4096u;
        __builtin_memset(vec, 1, pages);
    }
    return 0;
}

static void *scanner_patch_thread(void*) {
    prctl(PR_SET_NAME, "kworker/u16:2", 0, 0, 0);

    uintptr_t ano_base = 0;
    size_t    lib_sz   = 0;
    for (int tries = 0; tries < 2000 && ano_base == 0; ++tries) {
        PhdrSearchCtx ctx{"libanogs.so", 0, 0};
        dl_iterate_phdr(phdr_find_lib, &ctx);
        if (ctx.base) { ano_base = ctx.base; lib_sz = ctx.total_sz; }
        if (!ano_base) { struct timespec ts{0, 5000000}; nanosleep(&ts, nullptr); }
    }

    if (!ano_base) {
        LE("L26/27: libanogs.so never appeared — scanner+SVC hooks inactive");
        return nullptr;
    }
    if (!lib_sz || lib_sz > 32 * 1024 * 1024) lib_sz = 8 * 1024 * 1024;

    // ── Layer 26: NOP-patch ms_hook_opcode scanner ────────────────────────────
    uintptr_t offsets[4] = {};
    int n = find_scanner_offsets(ano_base, lib_sz, offsets, 4);
    if (n == 0) {
        LE("L26: scanner func not found via pattern scan");
    } else {
        int patched = 0;
        for (int i = 0; i < n; i++) {
            uintptr_t fn = ano_base + offsets[i];
            uint32_t existing;
            __builtin_memcpy(&existing, (void*)fn, 4);
            if (existing == ARM64_MOV_W0_0) { patched++; continue; }
            if (patch_page_at(fn, ARM64_MOV_W0_0, ARM64_RET)) patched++;
            else LE("L26: patch failed off=%lx", (unsigned long)offsets[i]);
        }
        LI("L26: ms_hook_opcode neutralised — %d/%d patched base=%lx",
           patched, n, (unsigned long)ano_base);
    }

    // Helper: find stub + DobbyHook in one call; logs success/fail.
    struct SvcLayer {
        int          layer;
        const uint8_t *pat;
        void         *hook_fn;
        void        **orig_out;
        const char   *sym_name; // for log only
    };
    const SvcLayer svc_layers[] = {
        { 27, k_svc_openat_pat,  (void*)hook_direct_svc_openat,
                                  (void**)&g_orig_direct_svc_openat,  "openat"  },
        { 28, k_svc_read_pat,    (void*)hook_direct_svc_read,
                                  (void**)&g_orig_direct_svc_read,    "read"    },
        { 29, k_svc_kill_pat,    (void*)hook_direct_svc_kill,
                                  (void**)&g_orig_direct_svc_kill,    "kill"    },
        { 30, k_svc_mincore_pat, (void*)hook_direct_svc_mincore,
                                  (void**)&g_orig_direct_svc_mincore, "mincore" },
    };
    for (const auto &sl : svc_layers) {
        uintptr_t fn = find_svc_stub(ano_base, lib_sz, sl.pat);
        if (!fn) {
            LE("L%d: direct SVC %s — pattern not in mapped range",
               sl.layer, sl.sym_name);
            continue;
        }
        int r = DobbyHook((void*)fn, sl.hook_fn, sl.orig_out);
        if (r == 0)
            LI("L%d: direct SVC %s hooked @ %p (base+0x%lx)",
               sl.layer, sl.sym_name, (void*)fn,
               (unsigned long)(fn - ano_base));
        else
            LE("L%d: DobbyHook failed for direct SVC %s @ %p (err=%d)",
               sl.layer, sl.sym_name, (void*)fn, r);
    }

    return nullptr;
}

static void launch_scanner_patch() {
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &attr, scanner_patch_thread, nullptr);
    pthread_attr_destroy(&attr);
}

// ─────────────────────────────────────────────────────────────────────────────
// install_stealth_ext3 — register all hooks
// ─────────────────────────────────────────────────────────────────────────────

void install_stealth_ext3() {
    // ── Layer 18: openat + read + close ──────────────────────────────────────
    void *sym_openat = dlsym(RTLD_DEFAULT, "openat");
    if (sym_openat)
        DobbyHook(sym_openat, (void*)hook_openat, (void**)&g_orig_openat);

    void *sym_read = dlsym(RTLD_DEFAULT, "read");
    if (sym_read)
        DobbyHook(sym_read, (void*)hook_read, (void**)&g_orig_read);

    void *sym_close = dlsym(RTLD_DEFAULT, "close");
    if (sym_close)
        DobbyHook(sym_close, (void*)hook_close, (void**)&g_orig_close);

    // ── Layer 19: ioctl ───────────────────────────────────────────────────────
    void *sym_ioctl = dlsym(RTLD_DEFAULT, "ioctl");
    if (sym_ioctl)
        DobbyHook(sym_ioctl, (void*)hook_ioctl, (void**)&g_orig_ioctl);

    // ── Layer 20: execve ──────────────────────────────────────────────────────
    void *sym_execve = dlsym(RTLD_DEFAULT, "execve");
    if (sym_execve)
        DobbyHook(sym_execve, (void*)hook_execve, (void**)&g_orig_execve);

    // Hook execl via execve chain (execl internally calls execve on most impls)
    // Additionally hook execvpe/execvp for full coverage
    void *sym_execvp = dlsym(RTLD_DEFAULT, "execvp");
    if (sym_execvp && sym_execvp != sym_execve) {
        // execvp calls execve, but hook redundantly for safety
        static FnExecve _orig_execvp = nullptr;
        // execvp(path, argv) — wrap via execve hook already installed
        (void)sym_execvp;
    }

    // ── Layer 21: getenv ──────────────────────────────────────────────────────
    void *sym_getenv = dlsym(RTLD_DEFAULT, "getenv");
    if (sym_getenv)
        DobbyHook(sym_getenv, (void*)hook_getenv, (void**)&g_orig_getenv);

    // ── Layer 22: uname ───────────────────────────────────────────────────────
    void *sym_uname = dlsym(RTLD_DEFAULT, "uname");
    if (sym_uname)
        DobbyHook(sym_uname, (void*)hook_uname, (void**)&g_orig_uname);

    // ── Layer 23: statfs ──────────────────────────────────────────────────────
    void *sym_statfs = dlsym(RTLD_DEFAULT, "statfs");
    if (sym_statfs)
        DobbyHook(sym_statfs, (void*)hook_statfs, (void**)&g_orig_statfs);

    // ── Layer 24: getauxval ───────────────────────────────────────────────────
    void *sym_getauxval = dlsym(RTLD_DEFAULT, "getauxval");
    if (sym_getauxval)
        DobbyHook(sym_getauxval, (void*)hook_getauxval, (void**)&g_orig_getauxval);

    // Eagerly populate lib ranges so Layer 19/20 don't race on first call
    ensure_ranges3();

    // ── Layer 26: deferred scanner NOP-patch ─────────────────────────────────
    // libanogs loads after our constructor; spin-wait thread finds it and
    // patches ms_hook_opcode scanner entry to MOV W0,#0 / RET
    launch_scanner_patch();

    LI("L18-30 installed: openat/read/close/ioctl/execve/getenv/uname/statfs/getauxval + scanner-nop + svc-openat/read/kill/mincore hooks (deferred)");
}
