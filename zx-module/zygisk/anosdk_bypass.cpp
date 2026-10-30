// AnoSDK bypass v2.22 — GOT patching, zero libc inline hooks
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
#include <sys/mman.h>
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
    // Direct SYS_ioctl — same filtering as hook_ioctl (a0=fd, a1=req, a2=arg)
    if (nr == __NR_ioctl) {
        unsigned long req  = (unsigned long)a1;
        unsigned long type = (req >> 8) & 0xFF;
        unsigned long num  = req & 0xFF;
        bool is_system = type == 0x54 || type == 0x66 || type == 0x53 || type == 0x89 || type == 0x00;
        if (!is_system && a2 != 0 && num >= 0x10)
            __builtin_memset((void *)a2, 0, 64);
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
    // ioctl encoding: bits[15:8] = type/magic (device), bits[7:0] = number (cmd)
    // Standard Linux ioctls use type bytes like 'T'(0x54), 'f'(0x66), 'S'(0x53), etc.
    // AnoSDK uses a private type byte — log ALL calls first time to discover it.
    // Only zero payload when type byte is NOT a known system type.
    unsigned long type = (req >> 8) & 0xFF;
    unsigned long num  = req & 0xFF;

    // Known safe system ioctl type bytes — never zero these
    bool is_system_ioctl =
        type == 0x54 || // 'T' — terminal ioctls (TIOCGWINSZ etc.)
        type == 0x66 || // 'f' — file ioctls (FIONREAD etc.)
        type == 0x53 || // 'S' — socket ioctls
        type == 0x89 || // socket/network ioctls
        type == 0x00;   // anonymous ioctls

    if (!is_system_ioctl) {
        if (arg) {
            const uint8_t *p = (const uint8_t *)arg;
            LOGI("[IOCTL-BAN] fd=%d req=0x%lx type=0x%lx num=0x%lx payload: "
                 "%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x "
                 "%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
                 fd, req, type, num,
                 p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7],
                 p[8],p[9],p[10],p[11],p[12],p[13],p[14],p[15],
                 p[16],p[17],p[18],p[19],p[20],p[21],p[22],p[23],
                 p[24],p[25],p[26],p[27],p[28],p[29],p[30],p[31]);
            if (num >= 0x10)
                __builtin_memset(arg, 0, 64);
        } else {
            LOGI("[IOCTL-BAN] fd=%d req=0x%lx type=0x%lx num=0x%lx (null arg)", fd, req, type, num);
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
    // Zygisk module path: /data/adb/modules/zx_zola_v2/zygisk/arm64-v8a.so
    // Hide by module name AND by the generic arm64-v8a.so filename to catch both
    if (info->dlpi_name &&
        (strstr(info->dlpi_name, "zx_zola") ||
         strstr(info->dlpi_name, "arm64-v8a.so")))
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

// Write one 8-byte GOT slot by temporarily making the RELRO page writable.
// mprotect on the process's own mapped pages is not blocked by SELinux unlike
// pwrite64 to /proc/self/mem which is denied in the untrusted_app SELinux domain.
// We never set PROT_EXEC — W^X stays intact, only PROT_WRITE is added then removed.
static bool patchGotSlot(uintptr_t slot_addr, uintptr_t new_val) {
    constexpr size_t kPage = 4096;
    uintptr_t page = slot_addr & ~(kPage - 1u);
    if (mprotect(reinterpret_cast<void *>(page), kPage, PROT_READ | PROT_WRITE) != 0)
        return false;
    *reinterpret_cast<volatile uintptr_t *>(slot_addr) = new_val;
    __sync_synchronize();
    mprotect(reinterpret_cast<void *>(page), kPage, PROT_READ);
    return true;
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
                    uintptr_t slot    = base + rel[i].r_offset;
                    uintptr_t new_val = reinterpret_cast<uintptr_t>(entries[j].new_fn);
                    uintptr_t cur_val;
                    __builtin_memcpy(&cur_val, reinterpret_cast<const void *>(slot), sizeof(cur_val));
                    if (cur_val == new_val) {
                        // Slot already points at our hook — count it, don't re-write or re-log
                        patched++;
                    } else if (patchGotSlot(slot, new_val)) {
                        LOGI("GOT[%s] slot=0x%lx → %p", name, slot, entries[j].new_fn);
                        patched++;
                    } else {
                        LOGE("GOT[%s] PATCH FAILED slot=0x%lx errno=%d", name, slot, errno);
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

// ── One-shot GOT diagnostic ──────────────────────────────────────────────────
// Called once per library when the first GOT patch attempt returns 0.
// Dumps ELF structure + actual symbol names so we can discover mismatches.
static void diagLibGot(const char *lib_name, uintptr_t base) {
    LOGI("[DIAG] === %s base=0x%lx ===", lib_name, base);

    auto *ehdr = reinterpret_cast<Elf64_Ehdr *>(base);
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        LOGE("[DIAG] %s: BAD ELF magic — findLibBase returned wrong address", lib_name);
        return;
    }
    LOGI("[DIAG] %s: ELF OK e_type=%u e_phnum=%u", lib_name, ehdr->e_type, ehdr->e_phnum);

    Elf64_Dyn *dyn = nullptr;
    auto *phdr = reinterpret_cast<Elf64_Phdr *>(base + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = reinterpret_cast<Elf64_Dyn *>(base + phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) { LOGE("[DIAG] %s: NO PT_DYNAMIC", lib_name); return; }

    Elf64_Rela *plt_rela = nullptr; size_t plt_sz = 0;
    Elf64_Rela *dyn_rela = nullptr; size_t dyn_sz = 0;
    Elf64_Sym  *symtab   = nullptr;
    const char *strtab   = nullptr;

    for (Elf64_Dyn *d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
        case DT_JMPREL:   plt_rela = reinterpret_cast<Elf64_Rela *>(base + d->d_un.d_ptr); break;
        case DT_PLTRELSZ: plt_sz   = d->d_un.d_val; break;
        case DT_RELA:     dyn_rela = reinterpret_cast<Elf64_Rela *>(base + d->d_un.d_ptr); break;
        case DT_RELASZ:   dyn_sz   = d->d_un.d_val; break;
        case DT_SYMTAB:   symtab   = reinterpret_cast<Elf64_Sym  *>(base + d->d_un.d_ptr); break;
        case DT_STRTAB:   strtab   = reinterpret_cast<const char *>(base + d->d_un.d_ptr); break;
        default: break;
        }
    }
    LOGI("[DIAG] %s: JMPREL=%p plt_sz=%zu RELA=%p rela_sz=%zu SYMTAB=%p STRTAB=%p",
         lib_name, plt_rela, plt_sz, dyn_rela, dyn_sz, symtab, strtab);

    if (!symtab || !strtab) {
        LOGE("[DIAG] %s: MISSING SYMTAB or STRTAB — cannot scan GOT symbols", lib_name);
        return;
    }

    // Test whether mprotect+write works on the first GOT slot
    if (plt_rela && plt_sz >= sizeof(Elf64_Rela)) {
        uintptr_t test_slot = base + plt_rela[0].r_offset;
        uintptr_t cur_val;
        __builtin_memcpy(&cur_val, reinterpret_cast<void *>(test_slot), sizeof(cur_val));
        int r = mprotect(reinterpret_cast<void *>(test_slot & ~4095u), 4096, PROT_READ | PROT_WRITE);
        if (r == 0) {
            *reinterpret_cast<volatile uintptr_t *>(test_slot) = cur_val; // no-op write
            mprotect(reinterpret_cast<void *>(test_slot & ~4095u), 4096, PROT_READ);
            LOGI("[DIAG] %s: mprotect test slot=0x%lx OK — write path should work", lib_name, test_slot);
        } else {
            LOGE("[DIAG] %s: mprotect test FAILED errno=%d — cannot write GOT", lib_name, errno);
        }
    }

    // Dump first 40 PLT (JUMP_SLOT) symbol names
    if (plt_rela && plt_sz > 0) {
        size_t nrela = plt_sz / sizeof(Elf64_Rela);
        LOGI("[DIAG] %s: JMPREL count=%zu — first symbols:", lib_name, nrela);
        for (size_t i = 0; i < nrela && i < 40; i++) {
            uint32_t sidx = ELF64_R_SYM(plt_rela[i].r_info);
            uint32_t type = ELF64_R_TYPE(plt_rela[i].r_info);
            const char *name = strtab + symtab[sidx].st_name;
            LOGI("[DIAG]   PLT[%02zu] type=%u  %s", i, type, name);
        }
    } else {
        LOGI("[DIAG] %s: NO JMPREL section (plt_rela=null or sz=0)", lib_name);
    }

    // Dump first 40 GLOB_DAT symbol names
    if (dyn_rela && dyn_sz > 0) {
        size_t nrela = dyn_sz / sizeof(Elf64_Rela);
        int shown = 0;
        LOGI("[DIAG] %s: RELA count=%zu — GLOB_DAT symbols:", lib_name, nrela);
        for (size_t i = 0; i < nrela && shown < 40; i++) {
            uint32_t type = ELF64_R_TYPE(dyn_rela[i].r_info);
            if (type != R_AARCH64_GLOB_DAT) continue;
            uint32_t sidx = ELF64_R_SYM(dyn_rela[i].r_info);
            const char *name = strtab + symtab[sidx].st_name;
            LOGI("[DIAG]   DYN[%02zu] GLOB_DAT  %s", i, name);
            shown++;
        }
    } else {
        LOGI("[DIAG] %s: NO RELA section", lib_name);
    }
    LOGI("[DIAG] === %s END ===", lib_name);
}

// ── Patch tables (symbol name → hook function) ───────────────────────────────

static const PatchEntry kAnogsEntries[] = {
    // Protection 2: maps reads (all open variants + fopen)
    { "open",             reinterpret_cast<void *>(hook_open)            },
    { "__open_2",         reinterpret_cast<void *>(hook_open2)           },
    { "openat",           reinterpret_cast<void *>(hook_openat2)         },
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
    { "openat",           reinterpret_cast<void *>(hook_openat2)     },
    { "syscall",          reinterpret_cast<void *>(hook_syscall_got) },
    { "ioctl",            reinterpret_cast<void *>(hook_ioctl)       },
};

// ── Watcher thread ────────────────────────────────────────────────────────────

static void *gotWatcherThread(void *) {
    // Phase 1 (attempts 0–49):  10ms sleep → library usually loads within ~200ms
    // Phase 2 (attempts 50–199): 100ms sleep → covers slow JIT/dex load paths
    // Give-up: if library IS found but 0 slots patch for 50 consecutive attempts
    //          → run one-shot diagnostic then stop retrying that library.
    constexpr int kMaxAttempts  = 200;
    constexpr int kZeroGiveUp   = 50;

    static const int kAnogsExp = (int)(sizeof(kAnogsEntries)/sizeof(kAnogsEntries[0]));
    static const int kAnortExp = (int)(sizeof(kAnortEntries)/sizeof(kAnortEntries[0]));

    bool anogs_done = false, anort_done = false;
    bool anogs_diag = false, anort_diag = false;
    int  anogs_zero   = 0,     anort_zero   = 0;
    int  anogs_prev   = -1,    anort_prev   = -1;
    int  anogs_stable = 0,     anort_stable = 0;

    for (int attempt = 0; attempt < kMaxAttempts && (!anogs_done || !anort_done); attempt++) {
        usleep(attempt < 50 ? 10000u : 100000u);

        if (!anogs_done) {
            uintptr_t base = findLibBase("libanogs.so");
            if (base) {
                int n = patchLibGot(base, kAnogsEntries, kAnogsExp);
                if (n != anogs_prev) {
                    LOGI("libanogs.so GOT: %d/%d slots patched (base=0x%lx)", n, kAnogsExp, base);
                    anogs_prev   = n;
                    anogs_stable = 0;
                }
                if (n == 0) {
                    anogs_zero++;
                    if (!anogs_diag) {
                        anogs_diag = true;
                        diagLibGot("libanogs.so", base);
                    }
                    if (anogs_zero >= kZeroGiveUp) {
                        LOGE("libanogs.so: GIVING UP after %d zero-patch attempts — AnoSDK may statically link libc", kZeroGiveUp);
                        anogs_done = true;
                    }
                } else {
                    anogs_zero = 0;
                    if (n >= kAnogsExp) {
                        anogs_done = true;
                    } else if (++anogs_stable >= 3) {
                        // n > 0 but stuck below expected — some symbols absent from this lib's GOT
                        LOGI("libanogs.so GOT: stable at %d/%d — marking done", n, kAnogsExp);
                        anogs_done = true;
                    }
                }
            }
        }

        if (!anort_done) {
            uintptr_t base = findLibBase("libanort.so");
            if (base) {
                int n = patchLibGot(base, kAnortEntries, kAnortExp);
                if (n != anort_prev) {
                    LOGI("libanort.so GOT: %d/%d slots patched (base=0x%lx)", n, kAnortExp, base);
                    anort_prev   = n;
                    anort_stable = 0;
                }
                if (n == 0) {
                    anort_zero++;
                    if (!anort_diag) {
                        anort_diag = true;
                        diagLibGot("libanort.so", base);
                    }
                    if (anort_zero >= kZeroGiveUp) {
                        LOGE("libanort.so: GIVING UP after %d zero-patch attempts — AnoSDK may statically link libc", kZeroGiveUp);
                        anort_done = true;
                    }
                } else {
                    anort_zero = 0;
                    if (n >= kAnortExp) {
                        anort_done = true;
                    } else if (++anort_stable >= 3) {
                        LOGI("libanort.so GOT: stable at %d/%d — marking done", n, kAnortExp);
                        anort_done = true;
                    }
                }
            }
        }
    }

    LOGI("AnoBypass: watcher done — anogs=%s anort=%s",
         (anogs_prev == kAnogsExp ? "OK" : (anogs_prev > 0 ? "partial" : "FAILED")),
         (anort_prev == kAnortExp ? "OK" : (anort_prev > 0 ? "partial" : "FAILED")));
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
    LOGI("AnoBypass v2.22: signal handlers installed (mprotect GOT write, no /proc/self/mem)");
}

void AnoBypass::startWatcher() {
    // pthread_once guarantees exactly one watcher thread even if startWatcher()
    // is called concurrently from multiple async worker threads.
    static pthread_once_t s_once = PTHREAD_ONCE_INIT;
    static auto launch = []() {
        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        int r = pthread_create(&tid, &attr, gotWatcherThread, nullptr);
        pthread_attr_destroy(&attr);
        if (r != 0) LOGE("AnoBypass: watcher thread create failed errno=%d", r);
        else         LOGI("AnoBypass: GOT watcher thread launched");
    };
    pthread_once(&s_once, []{ launch(); });
}

bool AnoBypass::install() {
    installEarly();
    startWatcher();
    return true;
}

void AnoBypass::remove() {
    LOGI("AnoSDK bypass v2.13 removed");
}
