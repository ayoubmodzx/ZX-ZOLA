// AnoSDK bypass v2.18 — GOT patching, zero libc inline hooks
//
// All intercepts planted in libanogs.so and libanort.so own GOT tables.
// libc.so is NEVER modified: AnoSDK code integrity scanner reads libc function
// bytes directly and reports bin_patch_cnt > 0 in the heartbeat → server ban.
// GOT entries are 8-byte pointer values — the scanner does NOT check them.
//
// Write path: /proc/self/mem pwrite64 — bypasses RELRO on .got.plt pages.
// ELF DYNAMIC parser matches by symbol name → survives minor GOT layout updates.
//
// CONSTRAINT: AnoSDKIoctl cmd<0x10 (init/heartbeat) MUST always reach original.
// We NEVER touch AnoSDK's own exported symbols.
//
// Detection fixes vs. v2.12:
//   • Removed Dobby on libc openat/exit/kill/abort  → bin_patch_cnt now 0
//   • Added __openat_2 / __open_2 / open / fopen     → maps reads now filtered
//   • Added syscall GOT hook                         → raw SYS_openat filtered
//   • Added ptrace GOT hook                          → anti-debug defeated
//   • Added fork GOT hook                            → self-inspection blocked
//   • Added popen/pclose GOT hook                    → shell probes blocked
//   • Added dl_iterate_phdr GOT hook (was Dobby)     → library scan defeated

#include "anosdk_bypass.hpp"
#include <android/log.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <pthread.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define TAG "ZX-ANO"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

#ifndef R_AARCH64_GLOB_DAT
#define R_AARCH64_GLOB_DAT  1025
#endif
#ifndef R_AARCH64_JUMP_SLOT
#define R_AARCH64_JUMP_SLOT 1026
#endif

// ── /proc/self/maps filter ────────────────────────────────────────────────────
// Creates a memfd populated with a filtered copy of /proc/self/maps that omits
// all lines referencing our module.  All reads use raw syscalls so this function
// itself never recurses through any patched GOT slot.

static int make_filtered_maps() {
    int real_fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY, 0);
    if (real_fd < 0) return -1;

    int mem_fd = (int)syscall(SYS_memfd_create, "maps", 0U);
    if (mem_fd < 0) { syscall(SYS_close, real_fd); return -1; }

    char buf[4096], line[512];
    int llen = 0;
    for (;;) {
        ssize_t n = (ssize_t)syscall(SYS_read, real_fd, buf, sizeof(buf));
        if (n <= 0) break;
        for (ssize_t i = 0; i < n; i++) {
            char c = buf[i];
            if (llen < (int)sizeof(line) - 1) line[llen++] = c;
            if (c == '\n' || llen >= (int)sizeof(line) - 1) {
                line[llen] = '\0';
                bool hide = strstr(line, "arm64-v8a.so") ||
                            strstr(line, "zx_zola")      ||
                            strstr(line, "zx-zola")      ||
                            strstr(line, "com.zx.zola");
                if (!hide) syscall(SYS_write, mem_fd, line, (size_t)llen);
                llen = 0;
            }
        }
    }
    if (llen > 0) {
        line[llen] = '\0';
        if (!strstr(line, "zx_zola") && !strstr(line, "arm64-v8a.so"))
            syscall(SYS_write, mem_fd, line, (size_t)llen);
    }
    syscall(SYS_close, real_fd);
    syscall(SYS_lseek, mem_fd, 0, SEEK_SET);
    return mem_fd;
}

// Build a filtered /proc/self/status that hides TracerPid (debugger detection).
// Zygisk injection leaves TracerPid != 0 in the process status — AnoSDK reads this.
static int make_filtered_status(const char *real_path) {
    int real_fd = (int)syscall(SYS_openat, AT_FDCWD, real_path, O_RDONLY, 0);
    if (real_fd < 0) return -1;
    int mem_fd = (int)syscall(SYS_memfd_create, "status", 0U);
    if (mem_fd < 0) { syscall(SYS_close, real_fd); return -1; }
    char buf[4096], line[512];
    int llen = 0;
    for (;;) {
        ssize_t n = (ssize_t)syscall(SYS_read, real_fd, buf, sizeof(buf));
        if (n <= 0) break;
        for (ssize_t i = 0; i < n; i++) {
            char c = buf[i];
            if (llen < (int)sizeof(line) - 1) line[llen++] = c;
            if (c == '\n' || llen >= (int)sizeof(line) - 1) {
                line[llen] = '\0';
                if (strncmp(line, "TracerPid:", 10) == 0) {
                    const char *zeroed = "TracerPid:\t0\n";
                    syscall(SYS_write, mem_fd, zeroed, __builtin_strlen(zeroed));
                } else {
                    syscall(SYS_write, mem_fd, line, (size_t)llen);
                }
                llen = 0;
            }
        }
    }
    if (llen > 0) syscall(SYS_write, mem_fd, line, (size_t)llen);
    syscall(SYS_close, real_fd);
    syscall(SYS_lseek, mem_fd, 0, SEEK_SET);
    return mem_fd;
}

static bool is_self_maps(const char *path) {
    if (!path) return false;
    if (strcmp(path, "/proc/self/maps")  == 0) return true;
    if (strcmp(path, "/proc/self/smaps") == 0) return true;
    char buf[64];
    int pid = (int)getpid();
    snprintf(buf, sizeof(buf), "/proc/%d/maps",  pid); if (strcmp(path, buf) == 0) return true;
    snprintf(buf, sizeof(buf), "/proc/%d/smaps", pid); if (strcmp(path, buf) == 0) return true;
    // Per-thread maps (AnoSDK may scan each thread's maps separately)
    snprintf(buf, sizeof(buf), "/proc/%d/task/",  pid);
    if (path && strncmp(path, buf, strlen(buf)) == 0 && strstr(path, "/maps")) return true;
    return false;
}

static bool is_self_status(const char *path) {
    if (!path) return false;
    if (strcmp(path, "/proc/self/status") == 0) return true;
    char buf[64];
    int pid = (int)getpid();
    snprintf(buf, sizeof(buf), "/proc/%d/status", pid);
    return strcmp(path, buf) == 0;
}

// ── GOT hook functions ────────────────────────────────────────────────────────
// These replace GOT entries in libanogs.so and libanort.so.
// Every forwarding call goes through libzx_zola.so's own unpatched PLT/GOT,
// which resolves directly to the real libc — no cross-library re-entrancy.

// Protection 2: maps + status file access — open() family
static int hook_open(const char *path, int flags, mode_t mode) {
    if (is_self_maps(path))   { int fd = make_filtered_maps();           if (fd >= 0) return fd; }
    if (is_self_status(path)) { int fd = make_filtered_status(path);     if (fd >= 0) return fd; }
    return ::open(path, flags, mode);
}

static int hook_open2(const char *path, int flags) {
    if (is_self_maps(path))   { int fd = make_filtered_maps();           if (fd >= 0) return fd; }
    if (is_self_status(path)) { int fd = make_filtered_status(path);     if (fd >= 0) return fd; }
    return ::open(path, flags);
}

static int hook_openat2(int dirfd, const char *path, int flags) {
    if (is_self_maps(path))   { int fd = make_filtered_maps();           if (fd >= 0) return fd; }
    if (is_self_status(path)) { int fd = make_filtered_status(path);     if (fd >= 0) return fd; }
    return ::openat(dirfd, path, flags);
}

static FILE *hook_fopen(const char *path, const char *mode) {
    if (is_self_maps(path)) {
        int fd = make_filtered_maps();
        if (fd >= 0) { FILE *f = ::fdopen(fd, "r"); if (f) return f; ::close(fd); }
    }
    if (is_self_status(path)) {
        int fd = make_filtered_status(path);
        if (fd >= 0) { FILE *f = ::fdopen(fd, "r"); if (f) return f; ::close(fd); }
    }
    return ::fopen(path, mode);
}

// Protection 6: shell execution — popen/pclose
static FILE *hook_popen(const char *cmd, const char *type) {
    (void)cmd; (void)type;
    errno = EPERM;
    return nullptr;
}
static int hook_pclose(FILE *stream) {
    (void)stream;
    return 0;
}

// Protection 8: process termination
static int hook_kill(pid_t pid, int sig) {
    pid_t self = getpid();
    if ((pid == self || pid == 0) &&
        (sig == SIGABRT || sig == SIGKILL || sig == SIGTERM)) {
        LOGE("BLOCKED kill(%d,%d) tid=%d", pid, sig, gettid());
        return 0;
    }
    return ::kill(pid, sig);
}

[[noreturn]] static void hook_exit(int code) {
    if (code != 0 || gettid() != getpid()) {
        LOGE("BLOCKED exit(%d) tid=%d", code, gettid());
        for (;;) usleep(2000000);
    }
    ::exit(0);
    __builtin_unreachable();
}

[[noreturn]] static void hook__exit(int code) {
    if (code != 0 || gettid() != getpid()) {
        LOGE("BLOCKED _exit(%d) tid=%d", code, gettid());
        for (;;) usleep(2000000);
    }
    ::_exit(0);
    __builtin_unreachable();
}

[[noreturn]] static void hook_abort() {
    LOGE("BLOCKED abort() tid=%d", gettid());
    for (;;) usleep(2000000);
    __builtin_unreachable();
}

// Protection 4: ptrace anti-debug — always return 0 (PTRACE_TRACEME success = no debugger)
static long hook_ptrace(int req, pid_t pid, void *addr, void *data) {
    (void)req; (void)pid; (void)addr; (void)data;
    return 0;
}

// Protection 5: fork-based self-inspection — return -1/EAGAIN, no child spawns
static pid_t hook_fork() {
    errno = EAGAIN;
    return (pid_t)-1;
}

// Protection 7: raw syscall bypass — intercept SYS_openat targeting /proc/self/maps
// AArch64 ABI: syscall(nr, a0, a1, a2, ...) → x0=nr, x1=a0, x2=a1=path, x3=a2=flags
static long hook_syscall_got(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
    if (nr == __NR_openat && a1 != 0) {
        const char *path = (const char *)a1;
        if (is_self_maps(path))   return (long)make_filtered_maps();
        if (is_self_status(path)) return (long)make_filtered_status(path);
    }
    return syscall(nr, a0, a1, a2, a3, a4, a5);
}

// Protection 9: ioctl interception — AnoSDK sends ban-triggering detection reports via ioctl.
// cmd layout (AnoSDK v4.x+): cmd < 0x10 = init/heartbeat (MUST pass through).
//                              cmd >= 0x10 = detection report → zero out payload, block ban.
// We log every call so logcat shows exactly what AnoSDK is trying to report.
// Note: AnoSDK opens its own fd (usually /dev/anoSDK or a socket) — we can't know which fd
// it uses, so we intercept ALL ioctl and pass non-AnoSDK calls through unchanged.
#include <sys/ioctl.h>
static int hook_ioctl(int fd, unsigned long req, void *arg) {
    // AnoSDK detection cmds are in the 0x10–0xFF range (internal protocol).
    // Heartbeat/init cmds < 0x10 must pass through untouched.
    unsigned long cmd = req & 0xFF;
    if (cmd >= 0x10) {
        // Log first 32 bytes of payload so we can diagnose what was detected
        if (arg) {
            const uint8_t *p = (const uint8_t *)arg;
            LOGI("[IOCTL-BAN] fd=%d req=0x%lx cmd=0x%lx payload: "
                 "%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x "
                 "%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
                 fd, req, cmd,
                 p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7],
                 p[8],p[9],p[10],p[11],p[12],p[13],p[14],p[15],
                 p[16],p[17],p[18],p[19],p[20],p[21],p[22],p[23],
                 p[24],p[25],p[26],p[27],p[28],p[29],p[30],p[31]);
            // Zero out the detection payload so the report carries no ban data
            __builtin_memset(arg, 0, 64);
        } else {
            LOGI("[IOCTL-BAN] fd=%d req=0x%lx cmd=0x%lx (null arg)", fd, req, cmd);
        }
    }
    return ::ioctl(fd, req, arg);
}

// Protection 3: dl_iterate_phdr library enumeration — wrap callback, drop our entry
struct DlHideCtx {
    int  (*user_cb)(struct dl_phdr_info *, size_t, void *);
    void *user_data;
};
static int dl_hide_trampoline(struct dl_phdr_info *info, size_t sz, void *raw) {
    auto *ctx = static_cast<DlHideCtx *>(raw);
    if (info->dlpi_name && strstr(info->dlpi_name, "libzx_zola"))
        return 0;
    return ctx->user_cb(info, sz, ctx->user_data);
}
static int hook_dl_iterate_phdr(
        int (*cb)(struct dl_phdr_info *, size_t, void *), void *data) {
    DlHideCtx ctx{ cb, data };
    return ::dl_iterate_phdr(dl_hide_trampoline, &ctx);
}

// ── GOT patching infrastructure ───────────────────────────────────────────────

struct PatchEntry {
    const char *sym_name;
    void       *new_fn;
};

// Write one 8-byte GOT slot via /proc/self/mem, bypassing RELRO.
static bool patchGotSlot(uintptr_t slot_addr, uintptr_t new_val) {
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/mem", O_RDWR, 0);
    if (fd < 0) return false;
    ssize_t n = (ssize_t)syscall(SYS_pwrite64, fd,
                                  &new_val, sizeof(new_val), (off_t)slot_addr);
    syscall(SYS_close, fd);
    return n == (ssize_t)sizeof(uintptr_t);
}

// Return the load base of a named library by scanning /proc/self/maps.
// Uses raw syscalls — must not call any function whose GOT we may be patching.
static uintptr_t findLibBase(const char *so_name) {
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY, 0);
    if (fd < 0) return 0;
    char buf[4096], line[512];
    int llen = 0;
    uintptr_t result = 0;
    for (;;) {
        ssize_t n = (ssize_t)syscall(SYS_read, fd, buf, sizeof(buf));
        if (n <= 0) break;
        for (ssize_t i = 0; i < n && !result; i++) {
            char c = buf[i];
            if (llen < (int)sizeof(line) - 1) line[llen++] = c;
            if (c == '\n' || llen >= (int)sizeof(line) - 1) {
                line[llen] = '\0';
                if (strstr(line, so_name)) {
                    uintptr_t start;
                    if (sscanf(line, "%lx-", &start) == 1) result = start;
                }
                llen = 0;
            }
        }
        if (result) break;
    }
    syscall(SYS_close, fd);
    return result;
}

// Walk both DT_JMPREL (.rela.plt / JUMP_SLOT) and DT_RELA (.rela.dyn / GLOB_DAT).
// Patch every entry whose symbol name matches an entry in the table.
static int patchLibGot(uintptr_t base, const PatchEntry *entries, size_t count) {
    if (!base || count == 0) return 0;
    auto *ehdr = reinterpret_cast<Elf64_Ehdr *>(base);
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) return 0;

    Elf64_Dyn *dyn = nullptr;
    auto *phdr = reinterpret_cast<Elf64_Phdr *>(base + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = reinterpret_cast<Elf64_Dyn *>(base + phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return 0;

    Elf64_Rela *plt_rela = nullptr; size_t plt_sz = 0;
    Elf64_Rela *dyn_rela = nullptr; size_t dyn_sz = 0;
    Elf64_Sym  *symtab   = nullptr;
    const char *strtab   = nullptr;

    for (Elf64_Dyn *d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
        case DT_JMPREL:   plt_rela = reinterpret_cast<Elf64_Rela *>(base + d->d_un.d_ptr); break;
        case DT_PLTRELSZ: plt_sz   = d->d_un.d_val;  break;
        case DT_RELA:     dyn_rela = reinterpret_cast<Elf64_Rela *>(base + d->d_un.d_ptr); break;
        case DT_RELASZ:   dyn_sz   = d->d_un.d_val;  break;
        case DT_SYMTAB:   symtab   = reinterpret_cast<Elf64_Sym  *>(base + d->d_un.d_ptr); break;
        case DT_STRTAB:   strtab   = reinterpret_cast<const char *>(base + d->d_un.d_ptr); break;
        default: break;
        }
    }
    if (!symtab || !strtab) return 0;

    int patched = 0;
    auto scanRela = [&](Elf64_Rela *rel, size_t sz) {
        if (!rel || sz == 0) return;
        size_t nrela = sz / sizeof(Elf64_Rela);
        for (size_t i = 0; i < nrela; i++) {
            uint32_t type = ELF64_R_TYPE(rel[i].r_info);
            if (type != R_AARCH64_JUMP_SLOT && type != R_AARCH64_GLOB_DAT) continue;
            uint32_t sidx = ELF64_R_SYM(rel[i].r_info);
            const char *name = strtab + symtab[sidx].st_name;
            for (size_t j = 0; j < count; j++) {
                if (strcmp(name, entries[j].sym_name) == 0) {
                    uintptr_t slot = base + rel[i].r_offset;
                    if (patchGotSlot(slot, reinterpret_cast<uintptr_t>(entries[j].new_fn))) {
                        LOGI("GOT[%s] slot=0x%lx → %p", name, slot, entries[j].new_fn);
                        patched++;
                    }
                    break;
                }
            }
        }
    };
    scanRela(plt_rela, plt_sz);
    scanRela(dyn_rela, dyn_sz);
    return patched;
}

// ── Patch tables (symbol name → hook function) ───────────────────────────────

static const PatchEntry kAnogsEntries[] = {
    // Protection 2: maps reads (all open variants + fopen)
    { "open",             reinterpret_cast<void *>(hook_open)            },
    { "__open_2",         reinterpret_cast<void *>(hook_open2)           },
    { "__openat_2",       reinterpret_cast<void *>(hook_openat2)         },
    { "fopen",            reinterpret_cast<void *>(hook_fopen)           },
    // Protection 6: shell execution
    { "popen",            reinterpret_cast<void *>(hook_popen)           },
    { "pclose",           reinterpret_cast<void *>(hook_pclose)          },
    // Protection 8: kill/exit/abort
    { "kill",             reinterpret_cast<void *>(hook_kill)            },
    { "exit",             reinterpret_cast<void *>(hook_exit)            },
    { "_exit",            reinterpret_cast<void *>(hook__exit)           },
    { "abort",            reinterpret_cast<void *>(hook_abort)           },
    // Protection 4: ptrace anti-debug
    { "ptrace",           reinterpret_cast<void *>(hook_ptrace)          },
    // Protection 5: fork self-inspection
    { "fork",             reinterpret_cast<void *>(hook_fork)            },
    // Protection 7: raw syscall bypass
    { "syscall",          reinterpret_cast<void *>(hook_syscall_got)     },
    // Protection 3: dl_iterate_phdr library enumeration
    { "dl_iterate_phdr",  reinterpret_cast<void *>(hook_dl_iterate_phdr) },
    // Protection 9: ioctl detection-report interception
    { "ioctl",            reinterpret_cast<void *>(hook_ioctl)           },
};

static const PatchEntry kAnortEntries[] = {
    { "open",             reinterpret_cast<void *>(hook_open)        },
    { "__open_2",         reinterpret_cast<void *>(hook_open2)       },
    { "__openat_2",       reinterpret_cast<void *>(hook_openat2)     },
    { "fopen",            reinterpret_cast<void *>(hook_fopen)       },
    { "kill",             reinterpret_cast<void *>(hook_kill)        },
    { "_exit",            reinterpret_cast<void *>(hook__exit)       },
    { "ptrace",           reinterpret_cast<void *>(hook_ptrace)      },
    { "fork",             reinterpret_cast<void *>(hook_fork)        },
    { "syscall",          reinterpret_cast<void *>(hook_syscall_got) },
    { "ioctl",            reinterpret_cast<void *>(hook_ioctl)       },
};

// ── Watcher thread ────────────────────────────────────────────────────────────

static void *gotWatcherThread(void *) {
    // First 50 attempts: 10ms intervals (0–500ms) — catches early AnoSDK load.
    // Remaining up to 600 total: 100ms intervals (50–60s window).
    constexpr int kMaxAttempts = 650;
    bool anogs_done = false;
    bool anort_done = false;

    for (int attempt = 0; attempt < kMaxAttempts && (!anogs_done || !anort_done); attempt++) {
        usleep(attempt < 50 ? 10000u : 100000u);

        if (!anogs_done) {
            uintptr_t base = findLibBase("libanogs.so");
            if (base) {
                static const int kAnogsExpected = (int)(sizeof(kAnogsEntries)/sizeof(kAnogsEntries[0]));
                int n = patchLibGot(base, kAnogsEntries, kAnogsExpected);
                LOGI("libanogs.so GOT: %d/%d slots patched (base=0x%lx)", n, kAnogsExpected, base);
                anogs_done = (n >= kAnogsExpected);
            }
        }
        if (!anort_done) {
            uintptr_t base = findLibBase("libanort.so");
            if (base) {
                static const int kAnortExpected = (int)(sizeof(kAnortEntries)/sizeof(kAnortEntries[0]));
                int n = patchLibGot(base, kAnortEntries, kAnortExpected);
                LOGI("libanort.so GOT: %d/%d slots patched (base=0x%lx)", n, kAnortExpected, base);
                anort_done = (n >= kAnortExpected);
            }
        }
    }

    if (!anogs_done) LOGE("libanogs.so never loaded — GOT not patched!");
    if (!anort_done) LOGE("libanort.so never loaded — GOT not patched!");
    return nullptr;
}

// ── Public API ────────────────────────────────────────────────────────────────

void AnoBypass::installEarly() {
    // Signal handlers only — Dobby on libc = AnoSDK code integrity scanner detects it.
    // All function-level intercepts are planted via GOT patching in startWatcher().
    struct sigaction sa{};
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGABRT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    LOGI("AnoBypass v2.18: signal handlers installed (no libc Dobby, GOT-only)");
}

void AnoBypass::startWatcher() {
    static bool s_started = false;
    if (s_started) return;
    s_started = true;
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int r = pthread_create(&tid, &attr, gotWatcherThread, nullptr);
    pthread_attr_destroy(&attr);
    if (r != 0)
        LOGE("AnoBypass: failed to create GOT watcher thread (errno=%d)", r);
    else
        LOGI("AnoBypass: GOT watcher thread launched");
}

bool AnoBypass::install() {
    installEarly();
    startWatcher();
    return true;
}

void AnoBypass::remove() {
    LOGI("AnoSDK bypass v2.13 removed");
}
