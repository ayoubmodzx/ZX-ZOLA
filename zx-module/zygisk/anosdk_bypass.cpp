// AnoSDK bypass v2.52 — GOT + trampoline seccomp, 35 protections + mountinfo/status/diag fixes
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
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/vfs.h>
#include <sys/ucontext.h>
#include <linux/filter.h>

#ifndef __NR_seccomp
#define __NR_seccomp 277
#endif
#ifndef __NR_newfstatat
#define __NR_newfstatat 79
#endif
#ifndef __NR_faccessat
#define __NR_faccessat 48
#endif
#ifndef __NR_faccessat2
#define __NR_faccessat2 439
#endif
#ifndef __NR_statx
#define __NR_statx 291
#endif
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif
#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC (1UL << 0)
#endif
#ifndef SECCOMP_RET_TRAP
#define SECCOMP_RET_TRAP  0x00030000U
#endif
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW 0x7fff0000U
#endif
#ifndef AUDIT_ARCH_AARCH64
#define AUDIT_ARCH_AARCH64 0xC00000B7U
#endif
#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

#ifndef PR_SET_VMA
#define PR_SET_VMA              0x53564d41
#define PR_SET_VMA_ANON_NAME    0
#endif

#define TAG "SurfaceFlinger"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Runtime string builder — keeps module identifiers out of .rodata so AnoSDK
// memory scanners can't pattern-match our filter strings in anonymous pages.
// Each string is assembled on the stack from individual chars at runtime.
// volatile prevents the compiler from optimizing these back into .rodata constants.
struct ObfStr {
    static void mod_id(char *b)    { volatile char *p=(volatile char*)b; p[0]='z';p[1]='x';p[2]='_';p[3]='z';p[4]='o';p[5]='l';p[6]='a';p[7]=0; }
    static void mod_dash(char *b)  { volatile char *p=(volatile char*)b; p[0]='z';p[1]='x';p[2]='-';p[3]='z';p[4]='o';p[5]='l';p[6]='a';p[7]=0; }
    static void mod_pkg(char *b)   { volatile char *p=(volatile char*)b; p[0]='c';p[1]='o';p[2]='m';p[3]='.';p[4]='z';p[5]='x';p[6]='.';p[7]='z';p[8]='o';p[9]='l';p[10]='a';p[11]=0; }
    static void arm_so(char *b)    { volatile char *p=(volatile char*)b; p[0]='a';p[1]='r';p[2]='m';p[3]='6';p[4]='4';p[5]='-';p[6]='v';p[7]='8';p[8]='a';p[9]='.';p[10]='s';p[11]='o';p[12]=0; }
    static void sock_name(char *b) { volatile char *p=(volatile char*)b; p[0]='g';p[1]='f';p[2]='x';p[3]='_';p[4]='p';p[5]='i';p[6]='p';p[7]='e';p[8]=0; }
    static void anogs(char *b)     { volatile char *p=(volatile char*)b; p[0]='l';p[1]='i';p[2]='b';p[3]='a';p[4]='n';p[5]='o';p[6]='g';p[7]='s';p[8]='.';p[9]='s';p[10]='o';p[11]=0; }
    static void anort(char *b)     { volatile char *p=(volatile char*)b; p[0]='l';p[1]='i';p[2]='b';p[3]='a';p[4]='n';p[5]='o';p[6]='r';p[7]='t';p[8]='.';p[9]='s';p[10]='o';p[11]=0; }
    static void payload(char *b)   { volatile char *p=(volatile char*)b; p[0]='p';p[1]='a';p[2]='y';p[3]='l';p[4]='o';p[5]='a';p[6]='d';p[7]=0; }
};

#ifndef R_AARCH64_GLOB_DAT
#define R_AARCH64_GLOB_DAT  1025
#endif
#ifndef R_AARCH64_JUMP_SLOT
#define R_AARCH64_JUMP_SLOT 1026
#endif

// ── Syscall trampoline ───────────────────────────────────────────────────────
// Executable page with a bare SVC #0 that our seccomp BPF whitelists by IP.
// After seccomp is installed, ALL openat/readlinkat in the process are trapped
// EXCEPT when issued from this page — so our own filter functions and
// pass-through paths call through here to avoid recursive SIGSYS.
static void *s_trampoline = nullptr;
static uintptr_t s_trampoline_start = 0;
static uintptr_t s_trampoline_end   = 0;

typedef long (*trampoline_fn_t)(long, long, long, long, long, long, long);

static bool setupTrampoline() {
    void *page = mmap(nullptr, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return false;

    static const uint32_t code[] = {
        0xAA0003E8, // MOV X8, X0   — syscall nr
        0xAA0103E0, // MOV X0, X1   — arg0
        0xAA0203E1, // MOV X1, X2   — arg1
        0xAA0303E2, // MOV X2, X3   — arg2
        0xAA0403E3, // MOV X3, X4   — arg3
        0xAA0503E4, // MOV X4, X5   — arg4
        0xAA0603E5, // MOV X5, X6   — arg5
        0xD4000001, // SVC #0
        0xD65F03C0, // RET
    };

    __builtin_memcpy(page, code, sizeof(code));
    mprotect(page, 4096, PROT_READ | PROT_EXEC);

    s_trampoline       = page;
    s_trampoline_start = (uintptr_t)page;
    s_trampoline_end   = s_trampoline_start + 4096;

    prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME,
          (unsigned long)page, (unsigned long)4096, "linker_alloc_small");
    return true;
}

static inline long safe_syscall(long nr, long a0=0, long a1=0, long a2=0,
                                long a3=0, long a4=0, long a5=0) {
    if (__builtin_expect(s_trampoline != nullptr, 1))
        return ((trampoline_fn_t)s_trampoline)(nr, a0, a1, a2, a3, a4, a5);
    return syscall(nr, a0, a1, a2, a3, a4, a5);
}

// ── /proc/self/maps filter ────────────────────────────────────────────────────
// Creates a memfd populated with a filtered copy of /proc/self/maps that omits
// all lines referencing our module.  All reads use raw syscalls so this function
// itself never recurses through any patched GOT slot.

static int make_filtered_maps(const char *proc_path = "/proc/self/maps") {
    int real_fd = (int)safe_syscall(__NR_openat, (long)AT_FDCWD, (long)proc_path, (long)O_RDONLY, 0L);
    if (real_fd < 0) return -1;

    int mem_fd = (int)syscall(SYS_memfd_create, "jit-cache", 0U);
    if (mem_fd < 0) { syscall(SYS_close, real_fd); return -1; }

    char f1[16], f2[16], f3[16], f4[16], f5[16];
    ObfStr::arm_so(f1); ObfStr::mod_id(f2); ObfStr::mod_dash(f3); ObfStr::mod_pkg(f4); ObfStr::payload(f5);
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
                bool hide = strstr(line, f1) || strstr(line, f2) ||
                            strstr(line, f3) || strstr(line, f4) ||
                            strstr(line, f5);
                if (!hide) syscall(SYS_write, mem_fd, line, (size_t)llen);
                llen = 0;
            }
        }
    }
    if (llen > 0) {
        line[llen] = '\0';
        if (!strstr(line, f2) && !strstr(line, f1))
            syscall(SYS_write, mem_fd, line, (size_t)llen);
    }
    syscall(SYS_close, real_fd);
    syscall(SYS_lseek, mem_fd, 0, SEEK_SET);
    return mem_fd;
}

// Build a filtered /proc/net/unix that hides our abstract socket from enumeration.
// AnoSDK scans this file for suspicious socket names — our socket would appear as @gfx_pipe.
// Defense-in-depth: the socket itself is renamed, but filter anyway for GOT-imported reads.
static int make_filtered_unix(const char *real_path) {
    int real_fd = (int)safe_syscall(__NR_openat, (long)AT_FDCWD, (long)real_path, (long)O_RDONLY, 0L);
    if (real_fd < 0) return -1;
    int mem_fd = (int)syscall(SYS_memfd_create, "jit-cache", 0U);
    if (mem_fd < 0) { syscall(SYS_close, real_fd); return -1; }
    char s1[16], s2[16], s3[16];
    ObfStr::sock_name(s1); ObfStr::mod_id(s2); ObfStr::mod_dash(s3);
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
                bool hide = strstr(line, s1) || strstr(line, s2) || strstr(line, s3);
                if (!hide) syscall(SYS_write, mem_fd, line, (size_t)llen);
                llen = 0;
            }
        }
    }
    if (llen > 0) {
        line[llen] = '\0';
        if (!strstr(line, s1) && !strstr(line, s2))
            syscall(SYS_write, mem_fd, line, (size_t)llen);
    }
    syscall(SYS_close, real_fd);
    syscall(SYS_lseek, mem_fd, 0, SEEK_SET);
    return mem_fd;
}

// Build a filtered /proc/self/status that hides TracerPid, Seccomp, NoNewPrivs.
// AnoSDK reads TracerPid for debugger check, and Seccomp:/NoNewPrivs: to detect
// seccomp filters — if those reveal a filter, it flags the process as tampered.
static int make_filtered_status(const char *real_path) {
    int real_fd = (int)safe_syscall(__NR_openat, (long)AT_FDCWD, (long)real_path, (long)O_RDONLY, 0L);
    if (real_fd < 0) return -1;
    int mem_fd = (int)syscall(SYS_memfd_create, "jit-cache", 0U);
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
                } else if (strncmp(line, "Seccomp:", 8) == 0) {
                    const char *zeroed = "Seccomp:\t0\n";
                    syscall(SYS_write, mem_fd, zeroed, __builtin_strlen(zeroed));
                } else if (strncmp(line, "Seccomp_filters:", 16) == 0) {
                    const char *zeroed = "Seccomp_filters:\t0\n";
                    syscall(SYS_write, mem_fd, zeroed, __builtin_strlen(zeroed));
                } else if (strncmp(line, "NoNewPrivs:", 11) == 0) {
                    const char *zeroed = "NoNewPrivs:\t0\n";
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
    if (strcmp(path, "/proc/self/smaps_rollup") == 0) return true;
    char buf[64];
    int pid = (int)getpid();
    snprintf(buf, sizeof(buf), "/proc/%d/maps",  pid); if (strcmp(path, buf) == 0) return true;
    snprintf(buf, sizeof(buf), "/proc/%d/smaps", pid); if (strcmp(path, buf) == 0) return true;
    snprintf(buf, sizeof(buf), "/proc/%d/task/",  pid);
    if (strncmp(path, buf, strlen(buf)) == 0 && strstr(path, "/maps")) return true;
    if (strncmp(path, "/proc/self/task/", 16) == 0 && strstr(path, "/maps")) return true;
    return false;
}

static bool is_self_mountinfo(const char *path) {
    if (!path) return false;
    if (strcmp(path, "/proc/self/mountinfo") == 0) return true;
    if (strcmp(path, "/proc/self/mounts") == 0) return true;
    if (strcmp(path, "/proc/mounts") == 0) return true;
    char buf[64];
    int pid = (int)getpid();
    snprintf(buf, sizeof(buf), "/proc/%d/mountinfo", pid); if (strcmp(path, buf) == 0) return true;
    snprintf(buf, sizeof(buf), "/proc/%d/mounts", pid); if (strcmp(path, buf) == 0) return true;
    return false;
}

static int make_filtered_mountinfo(const char *real_path) {
    int real_fd = (int)safe_syscall(__NR_openat, (long)AT_FDCWD, (long)real_path, (long)O_RDONLY, 0L);
    if (real_fd < 0) return -1;
    int mem_fd = (int)syscall(SYS_memfd_create, "jit-cache", 0U);
    if (mem_fd < 0) { syscall(SYS_close, real_fd); return -1; }
    char f1[16], f2[16], f3[16];
    ObfStr::mod_id(f1); ObfStr::mod_dash(f2); ObfStr::mod_pkg(f3);
    char buf[4096], line[1024];
    int llen = 0;
    for (;;) {
        ssize_t n = (ssize_t)syscall(SYS_read, real_fd, buf, sizeof(buf));
        if (n <= 0) break;
        for (ssize_t i = 0; i < n; i++) {
            char c = buf[i];
            if (llen < (int)sizeof(line) - 1) line[llen++] = c;
            if (c == '\n' || llen >= (int)sizeof(line) - 1) {
                line[llen] = '\0';
                bool hide = strstr(line, f1) || strstr(line, f2) || strstr(line, f3)
                         || strstr(line, "magisk") || strstr(line, "Magisk")
                         || strstr(line, "/sbin/.magisk") || strstr(line, "KSU")
                         || strstr(line, "kernelsu") || strstr(line, "tmpfs /system/")
                         || strstr(line, "tmpfs /vendor/") || strstr(line, "tmpfs /product/");
                if (!hide) syscall(SYS_write, mem_fd, line, (size_t)llen);
                llen = 0;
            }
        }
    }
    if (llen > 0) {
        line[llen] = '\0';
        if (!strstr(line, f1) && !strstr(line, f2) && !strstr(line, "magisk"))
            syscall(SYS_write, mem_fd, line, (size_t)llen);
    }
    syscall(SYS_close, real_fd);
    syscall(SYS_lseek, mem_fd, 0, SEEK_SET);
    return mem_fd;
}

static bool is_self_status(const char *path) {
    if (!path) return false;
    if (strcmp(path, "/proc/self/status") == 0) return true;
    if (strcmp(path, "/proc/self/wchan") == 0)  return true;
    char buf[64];
    int pid = (int)getpid();
    snprintf(buf, sizeof(buf), "/proc/%d/status", pid);
    if (strcmp(path, buf) == 0) return true;
    // Per-task status — AnoSDK reads /proc/self/task/<tid>/status for TracerPid
    snprintf(buf, sizeof(buf), "/proc/%d/task/", pid);
    if (strncmp(path, buf, strlen(buf)) == 0 && strstr(path, "/status")) return true;
    if (strncmp(path, "/proc/self/task/", 16) == 0 && strstr(path, "/status")) return true;
    return false;
}

static bool is_proc_net_unix(const char *path) {
    if (!path) return false;
    if (strcmp(path, "/proc/net/unix") == 0) return true;
    if (strcmp(path, "/proc/self/net/unix") == 0) return true;
    char buf[64];
    int pid = (int)getpid();
    snprintf(buf, sizeof(buf), "/proc/%d/net/unix", pid);
    return strcmp(path, buf) == 0;
}

// AnoSDK diagnostic counters (read by feature_engine diagThread)
uint32_t g_ano_kill_blocked   = 0;
uint32_t g_ano_exit_blocked   = 0;
uint32_t g_ano_abort_blocked  = 0;
uint32_t g_ano_maps_filtered  = 0;
uint32_t g_ano_ioctl_zeroed   = 0;
uint32_t g_ano_ptrace_blocked = 0;
uint32_t g_ano_fork_blocked   = 0;
uint32_t g_ano_dl_hidden      = 0;
uint32_t g_ano_svc_trapped    = 0;
uint32_t g_ano_mount_filtered = 0;

// SVC path diagnostic: log first 32 unique unfiltered openat paths from SIGSYS
static constexpr int kMaxDiagPaths = 32;
char s_diag_paths[kMaxDiagPaths][128];
int  s_diag_path_count = 0;

static void diag_log_svc_path(const char *path) {
    if (!path || s_diag_path_count >= kMaxDiagPaths) return;
    for (int i = 0; i < s_diag_path_count; i++)
        if (strcmp(s_diag_paths[i], path) == 0) return;
    size_t len = __builtin_strlen(path);
    if (len >= sizeof(s_diag_paths[0])) len = sizeof(s_diag_paths[0]) - 1;
    __builtin_memcpy(s_diag_paths[s_diag_path_count], path, len);
    s_diag_paths[s_diag_path_count][len] = '\0';
    s_diag_path_count++;
}

// Forward declarations for protections defined later in this file
static bool is_root_path(const char *p);
static bool is_self_environ(const char *path);
static int  make_filtered_environ();
static bool is_root_dir_entry(const char *name);
extern uint32_t g_ano_access_filtered;
extern uint32_t g_ano_getenv_filtered;
extern uint32_t g_ano_readdir_filtered;
extern uint32_t g_ano_dladdr_spoofed;
extern uint32_t g_ano_fstat_filtered;

// Forward declarations for hooks referenced by dlsym map (P26)
static ssize_t hook_read(int fd, void *buf, size_t count);
static ssize_t hook___read_chk(int fd, void *buf, size_t count, size_t buflen);
static char *hook_fgets(char *s, int size, FILE *stream);
static char *hook___fgets_chk(char *s, int size, FILE *stream, size_t slen);
static void *hook_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
static int hook_execl(const char *path, const char *arg, ...);
static int hook_execv(const char *path, char *const argv[]);
static unsigned long hook_getauxval(unsigned long type);
static void *hook_dlopen(const char *filename, int flags);
static ssize_t hook_pread(int fd, void *buf, size_t count, off_t offset);
static int hook_statfs(const char *path, struct statfs *buf);

//── GOT hook functions ────────────────────────────────────────────────────────
// These replace GOT entries in libanogs.so and libanort.so.
// Every forwarding call goes through libzx_zola.so's own unpatched PLT/GOT,
// which resolves directly to the real libc — no cross-library re-entrancy.

// Protection 2: maps + status file access — open() family
// Per-task comm/status filter — AnoSDK reads /proc/self/task/<tid>/comm and
// /proc/self/task/<tid>/status to discover suspicious thread names.
// Return a memfd with our thread names replaced by their camouflaged versions.
static bool is_task_comm(const char *path) {
    if (!path) return false;
    char buf[64];
    int pid = (int)getpid();
    snprintf(buf, sizeof(buf), "/proc/%d/task/", pid);
    if (strncmp(path, buf, strlen(buf)) == 0 && strstr(path, "/comm")) return true;
    if (strncmp(path, "/proc/self/task/", 16) == 0 && strstr(path, "/comm")) return true;
    return false;
}

static int hook_open(const char *path, int flags, mode_t mode) {
    if (is_self_maps(path))      { ++g_ano_maps_filtered;  int fd = make_filtered_maps(path);        if (fd >= 0) return fd; }
    if (is_self_mountinfo(path)) { ++g_ano_mount_filtered; int fd = make_filtered_mountinfo(path);   if (fd >= 0) return fd; }
    if (is_self_status(path))    { ++g_ano_maps_filtered;  int fd = make_filtered_status(path);      if (fd >= 0) return fd; }
    if (is_proc_net_unix(path))  { ++g_ano_maps_filtered;  int fd = make_filtered_unix(path);        if (fd >= 0) return fd; }
    if (is_self_environ(path))   { ++g_ano_maps_filtered;  int fd = make_filtered_environ();         if (fd >= 0) return fd; }
    if (is_root_path(path))      { ++g_ano_access_filtered; errno = ENOENT; return -1; }
    return ::open(path, flags, mode);
}

static int hook_open2(const char *path, int flags) {
    if (is_self_maps(path))      { ++g_ano_maps_filtered;  int fd = make_filtered_maps(path);        if (fd >= 0) return fd; }
    if (is_self_mountinfo(path)) { ++g_ano_mount_filtered; int fd = make_filtered_mountinfo(path);   if (fd >= 0) return fd; }
    if (is_self_status(path))    { ++g_ano_maps_filtered;  int fd = make_filtered_status(path);      if (fd >= 0) return fd; }
    if (is_proc_net_unix(path))  { ++g_ano_maps_filtered;  int fd = make_filtered_unix(path);        if (fd >= 0) return fd; }
    if (is_self_environ(path))   { ++g_ano_maps_filtered;  int fd = make_filtered_environ();         if (fd >= 0) return fd; }
    if (is_root_path(path))      { ++g_ano_access_filtered; errno = ENOENT; return -1; }
    return ::open(path, flags);
}

static int hook_openat2(int dirfd, const char *path, int flags) {
    if (is_self_maps(path))      { int fd = make_filtered_maps(path);        if (fd >= 0) return fd; }
    if (is_self_mountinfo(path)) { int fd = make_filtered_mountinfo(path);   if (fd >= 0) return fd; }
    if (is_self_status(path))    { int fd = make_filtered_status(path);      if (fd >= 0) return fd; }
    if (is_proc_net_unix(path))  { int fd = make_filtered_unix(path);        if (fd >= 0) return fd; }
    if (is_self_environ(path))   { int fd = make_filtered_environ();         if (fd >= 0) return fd; }
    if (is_root_path(path))      { ++g_ano_access_filtered; errno = ENOENT; return -1; }
    return ::openat(dirfd, path, flags);
}

static FILE *hook_fopen(const char *path, const char *mode) {
    if (is_self_maps(path)) {
        int fd = make_filtered_maps(path);
        if (fd >= 0) { FILE *f = ::fdopen(fd, "r"); if (f) return f; ::close(fd); }
    }
    if (is_self_mountinfo(path)) {
        int fd = make_filtered_mountinfo(path);
        if (fd >= 0) { FILE *f = ::fdopen(fd, "r"); if (f) return f; ::close(fd); }
    }
    if (is_self_status(path)) {
        int fd = make_filtered_status(path);
        if (fd >= 0) { FILE *f = ::fdopen(fd, "r"); if (f) return f; ::close(fd); }
    }
    if (is_proc_net_unix(path)) {
        int fd = make_filtered_unix(path);
        if (fd >= 0) { FILE *f = ::fdopen(fd, "r"); if (f) return f; ::close(fd); }
    }
    if (is_self_environ(path)) {
        int fd = make_filtered_environ();
        if (fd >= 0) { FILE *f = ::fdopen(fd, "r"); if (f) return f; ::close(fd); }
    }
    if (is_root_path(path)) { errno = ENOENT; return nullptr; }
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
        ++g_ano_kill_blocked;
        LOGE("BLOCKED kill(%d,%d) tid=%d", pid, sig, gettid());
        return 0;
    }
    return ::kill(pid, sig);
}

[[noreturn]] static void hook_exit(int code) {
    if (code != 0 || gettid() != getpid()) {
        ++g_ano_exit_blocked;
        LOGE("BLOCKED exit(%d) tid=%d", code, gettid());
        for (;;) usleep(2000000);
    }
    ::exit(0);
    __builtin_unreachable();
}

[[noreturn]] static void hook__exit(int code) {
    if (code != 0 || gettid() != getpid()) {
        ++g_ano_exit_blocked;
        LOGE("BLOCKED _exit(%d) tid=%d", code, gettid());
        for (;;) usleep(2000000);
    }
    ::_exit(0);
    __builtin_unreachable();
}

[[noreturn]] static void hook_abort() {
    ++g_ano_abort_blocked;
    LOGE("BLOCKED abort() tid=%d", gettid());
    for (;;) usleep(2000000);
    __builtin_unreachable();
}

// Protection 4: ptrace anti-debug — always return 0 (PTRACE_TRACEME success = no debugger)
static long hook_ptrace(int req, pid_t pid, void *addr, void *data) {
    ++g_ano_ptrace_blocked;
    (void)req; (void)pid; (void)addr; (void)data;
    return 0;
}

// Protection 5: fork-based self-inspection — return -1/EAGAIN, no child spawns
static pid_t hook_fork() {
    ++g_ano_fork_blocked;
    errno = EAGAIN;
    return (pid_t)-1;
}

// Protection 10: inotify filesystem watcher — AnoSDK uses inotify to watch
// /proc/self/maps for changes when modules load.  Block the watcher entirely.
#include <sys/inotify.h>
uint32_t g_ano_inotify_blocked = 0;
static int hook_inotify_init() {
    ++g_ano_inotify_blocked;
    errno = EMFILE;
    return -1;
}
static int hook_inotify_init1(int flags) {
    (void)flags;
    ++g_ano_inotify_blocked;
    errno = EMFILE;
    return -1;
}
static int hook_inotify_add_watch(int fd, const char *path, uint32_t mask) {
    (void)fd; (void)path; (void)mask;
    ++g_ano_inotify_blocked;
    errno = EBADF;
    return -1;
}

// Protection 11: mincore — AnoSDK uses this to check if injected code pages
// are resident in memory.  Return success with all pages marked NOT present.
uint32_t g_ano_mincore_spoofed = 0;
static int hook_mincore(void *addr, size_t length, unsigned char *vec) {
    (void)addr;
    if (vec && length > 0) {
        size_t pages = (length + 4095) / 4096;
        __builtin_memset(vec, 0, pages);
    }
    ++g_ano_mincore_spoofed;
    return 0;
}

// Protection 14: readlinkat — AnoSDK enumerates /proc/self/fd/* and readlink()s
// each one to discover open fds pointing to injected .so files or Magisk paths.
// Also checks /proc/self/exe for Zygisk binary injection artifacts.
uint32_t g_ano_readlink_filtered = 0;
static ssize_t hook_readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz) {
    ssize_t r = ::readlinkat(dirfd, pathname, buf, bufsiz);
    if (r > 0 && buf) {
        char tmp[512];
        size_t len = (size_t)r < sizeof(tmp) - 1 ? (size_t)r : sizeof(tmp) - 1;
        __builtin_memcpy(tmp, buf, len);
        tmp[len] = '\0';
        char h1[16], h2[16], h3[16], h4[16];
        ObfStr::mod_id(h1); ObfStr::mod_dash(h2); ObfStr::arm_so(h3); ObfStr::mod_pkg(h4);
        if (strstr(tmp, h1) || strstr(tmp, h2) || strstr(tmp, h3) || strstr(tmp, h4)
            || is_root_path(tmp)) {
            ++g_ano_readlink_filtered;
            errno = ENOENT;
            return -1;
        }
    }
    return r;
}
static ssize_t hook_readlink(const char *path, char *buf, size_t bufsiz) {
    return hook_readlinkat(AT_FDCWD, path, buf, bufsiz);
}

// Protection 15: access/faccessat — AnoSDK probes filesystem paths for root/Magisk
// artifacts. Return ENOENT for known injection paths.
uint32_t g_ano_access_filtered = 0;
// Runtime-built root path signatures — keeps detection strings out of .rodata
// so AnoSDK can't pattern-match them via memory scan.
static bool is_root_path(const char *p) {
    if (!p) return false;
    // Build each signature on the stack at runtime
    struct R {
        static void s0(char *b)  { volatile char *v=(volatile char*)b; v[0]='/';v[1]='d';v[2]='a';v[3]='t';v[4]='a';v[5]='/';v[6]='a';v[7]='d';v[8]='b';v[9]=0; }
        static void s1(char *b)  { volatile char *v=(volatile char*)b; v[0]='m';v[1]='a';v[2]='g';v[3]='i';v[4]='s';v[5]='k';v[6]=0; }
        static void s2(char *b)  { volatile char *v=(volatile char*)b; v[0]='s';v[1]='u';v[2]='p';v[3]='e';v[4]='r';v[5]='s';v[6]='u';v[7]=0; }
        static void s3(char *b)  { volatile char *v=(volatile char*)b; v[0]='/';v[1]='s';v[2]='u';v[3]=0; }
        static void s4(char *b)  { volatile char *v=(volatile char*)b; v[0]='b';v[1]='u';v[2]='s';v[3]='y';v[4]='b';v[5]='o';v[6]='x';v[7]=0; }
        static void s5(char *b)  { volatile char *v=(volatile char*)b; v[0]='z';v[1]='y';v[2]='g';v[3]='i';v[4]='s';v[5]='k';v[6]=0; }
        static void s6(char *b)  { volatile char *v=(volatile char*)b; v[0]='r';v[1]='i';v[2]='r';v[3]='u';v[4]=0; }
        static void s7(char *b)  { volatile char *v=(volatile char*)b; v[0]='x';v[1]='p';v[2]='o';v[3]='s';v[4]='e';v[5]='d';v[6]=0; }
        static void s8(char *b)  { volatile char *v=(volatile char*)b; v[0]='k';v[1]='e';v[2]='r';v[3]='n';v[4]='e';v[5]='l';v[6]='s';v[7]='u';v[8]=0; }
        static void s9(char *b)  { volatile char *v=(volatile char*)b; v[0]='a';v[1]='p';v[2]='a';v[3]='t';v[4]='c';v[5]='h';v[6]=0; }
    };
    char t[16];
    R::s0(t); if (strstr(p, t)) return true;
    R::s1(t); if (strstr(p, t)) return true;
    R::s2(t); if (strstr(p, t)) return true;
    R::s3(t); if (strstr(p, t)) return true;
    R::s4(t); if (strstr(p, t)) return true;
    R::s5(t); if (strstr(p, t)) return true;
    R::s6(t); if (strstr(p, t)) return true;
    R::s7(t); if (strstr(p, t)) return true;
    R::s8(t); if (strstr(p, t)) return true;
    R::s9(t); if (strstr(p, t)) return true;
    ObfStr::mod_id(t); if (strstr(p, t)) return true;
    return false;
}
static int hook_access(const char *path, int mode) {
    if (is_root_path(path)) { ++g_ano_access_filtered; errno = ENOENT; return -1; }
    return ::access(path, mode);
}
static int hook_faccessat(int dirfd, const char *path, int mode, int flags) {
    if (is_root_path(path)) { ++g_ano_access_filtered; errno = ENOENT; return -1; }
    return ::faccessat(dirfd, path, mode, flags);
}

// Protection 16: stat/fstatat/lstat — AnoSDK stats Magisk/module paths to detect root.
uint32_t g_ano_stat_filtered = 0;
static int hook_stat(const char *path, struct stat *st) {
    if (is_root_path(path)) { ++g_ano_stat_filtered; errno = ENOENT; return -1; }
    return ::stat(path, st);
}
static int hook_lstat(const char *path, struct stat *st) {
    if (is_root_path(path)) { ++g_ano_stat_filtered; errno = ENOENT; return -1; }
    return ::lstat(path, st);
}
static int hook_fstatat(int dirfd, const char *path, struct stat *st, int flags) {
    if (is_root_path(path)) { ++g_ano_stat_filtered; errno = ENOENT; return -1; }
    return ::fstatat(dirfd, path, st, flags);
}

// Protection 17: __system_property_get — AnoSDK reads system properties to detect root.
// Spoof only root-indicating properties; pass all others through untouched.
uint32_t g_ano_prop_spoofed = 0;
static int hook_system_property_get(const char *name, char *value) {
    int r = __system_property_get(name, value);
    if (name && value) {
        if (strcmp(name, "ro.debuggable") == 0 && value[0] == '1') {
            value[0] = '0'; value[1] = '\0'; ++g_ano_prop_spoofed;
        } else if (strcmp(name, "ro.secure") == 0 && value[0] == '0') {
            value[0] = '1'; value[1] = '\0'; ++g_ano_prop_spoofed;
        } else if (strcmp(name, "ro.build.selinux") == 0 && value[0] == '0') {
            value[0] = '1'; value[1] = '\0'; ++g_ano_prop_spoofed;
        } else if (strcmp(name, "ro.build.tags") == 0 && strstr(value, "test-keys")) {
            __builtin_memcpy(value, "release-keys", 13); ++g_ano_prop_spoofed;
        } else if (is_root_path(name)) {
            value[0] = '\0'; ++g_ano_prop_spoofed;
        }
    }
    return r;
}

// Protection 18: /proc/self/environ filter — AnoSDK reads environment variables
// to detect LD_PRELOAD, MAGISK_*, and other injection artifacts.
static int make_filtered_environ() {
    int real_fd = (int)safe_syscall(__NR_openat, (long)AT_FDCWD, (long)"/proc/self/environ", (long)O_RDONLY, 0L);
    if (real_fd < 0) return -1;
    int mem_fd = (int)syscall(SYS_memfd_create, "jit-cache", 0U);
    if (mem_fd < 0) { syscall(SYS_close, real_fd); return -1; }
    char buf[4096];
    for (;;) {
        ssize_t n = (ssize_t)syscall(SYS_read, real_fd, buf, sizeof(buf));
        if (n <= 0) break;
        ssize_t start = 0;
        for (ssize_t i = 0; i < n; i++) {
            if (buf[i] == '\0') {
                char *entry = buf + start;
                size_t elen = (size_t)(i - start);
                bool hide = false;
                if (elen > 0) {
                    // Build env prefix signatures at runtime
                    volatile char ld[12]; ld[0]='L';ld[1]='D';ld[2]='_';ld[3]='P';ld[4]='R';ld[5]='E';ld[6]='L';ld[7]='O';ld[8]='A';ld[9]='D';ld[10]='=';ld[11]=0;
                    volatile char mg[7]; mg[0]='M';mg[1]='A';mg[2]='G';mg[3]='I';mg[4]='S';mg[5]='K';mg[6]=0;
                    volatile char zg[7]; zg[0]='Z';zg[1]='Y';zg[2]='G';zg[3]='I';zg[4]='S';zg[5]='K';zg[6]=0;
                    volatile char ri[6]; ri[0]='R';ri[1]='I';ri[2]='R';ri[3]='U';ri[4]='_';ri[5]=0;
                    volatile char ks[5]; ks[0]='K';ks[1]='S';ks[2]='U';ks[3]='_';ks[4]=0;
                    if (strncmp(entry, (const char*)ld, 11) == 0) hide = true;
                    else if (strncmp(entry, (const char*)mg, 6) == 0) hide = true;
                    else if (strncmp(entry, (const char*)zg, 6) == 0) hide = true;
                    else if (strncmp(entry, (const char*)ri, 5) == 0)  hide = true;
                    else if (strncmp(entry, (const char*)ks, 4) == 0)   hide = true;
                }
                if (!hide) {
                    syscall(SYS_write, mem_fd, entry, elen + 1);
                }
                start = i + 1;
            }
        }
    }
    syscall(SYS_close, real_fd);
    syscall(SYS_lseek, mem_fd, 0, SEEK_SET);
    return mem_fd;
}

static bool is_self_environ(const char *path) {
    if (!path) return false;
    if (strcmp(path, "/proc/self/environ") == 0) return true;
    char buf[64];
    int pid = (int)getpid();
    snprintf(buf, sizeof(buf), "/proc/%d/environ", pid);
    return strcmp(path, buf) == 0;
}

// ── Detection report dump (logcat) ───────────────────────────────────────────
// All AnoSDK ioctl payloads + SVC diagnostic paths dumped to logcat.
// Capture with: logcat -s ZX-ZOLA | grep DUMP
#include <sys/ioctl.h>
#include <time.h>

static int s_dump_count = 0;

static void dump_write(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void dump_write(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    LOGI("[DUMP] %s", buf);
}

static void dump_hex(const uint8_t *data, size_t len) {
    for (size_t off = 0; off < len; off += 32) {
        char line[200];
        int pos = snprintf(line, sizeof(line), "%04zx: ", off);
        for (size_t j = 0; j < 32 && (off + j) < len; j++)
            pos += snprintf(line + pos, sizeof(line) - pos, "%02x", data[off + j]);
        pos += snprintf(line + pos, sizeof(line) - pos, " |");
        for (size_t j = 0; j < 32 && (off + j) < len; j++) {
            char c = (char)data[off + j];
            line[pos++] = (c >= 0x20 && c < 0x7f) ? c : '.';
        }
        line[pos++] = '|'; line[pos] = '\0';
        LOGI("[DUMP] %s", line);
    }
}

void dump_svc_paths() {
    if (s_diag_path_count == 0) return;
    LOGI("[DUMP] === Unfiltered SVC openat paths (%d) ===", s_diag_path_count);
    for (int i = 0; i < s_diag_path_count; i++)
        LOGI("[DUMP] SVC-PATH[%d] %s", i, s_diag_paths[i]);
}

// Protection 12: tp_syscall_imp — libanort.so exports a raw SVC #0 wrapper that
// bypasses ALL GOT hooks.  If libanogs.so imports it via GOT, this intercepts it.
// Same filtering logic as hook_syscall_got.
static long hook_tp_syscall(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
    if (nr == __NR_openat && a1 != 0) {
        const char *path = (const char *)a1;
        if (is_self_maps(path))      return (long)make_filtered_maps(path);
        if (is_self_mountinfo(path)) return (long)make_filtered_mountinfo(path);
        if (is_self_status(path))    return (long)make_filtered_status(path);
        if (is_proc_net_unix(path))  return (long)make_filtered_unix(path);
        if (is_self_environ(path))   return (long)make_filtered_environ();
    }
    if (nr == __NR_ioctl) {
        unsigned long req  = (unsigned long)a1;
        unsigned long type = (req >> 8) & 0xFF;
        unsigned long num  = req & 0xFF;
        bool is_system = type == 0x54 || type == 0x66 || type == 0x53 || type == 0x89 || type == 0x00;
        if (!is_system && a2 != 0) {
            size_t psz = (req >> 16) & 0x3FFF;
            if (psz == 0) psz = 64; if (psz > 512) psz = 512;
            dump_write("[TP-IOCTL] fd=%ld req=0x%lx cmd=0x%02lx size=%zu %s\n",
                       a0, req, num, psz, num < 0x10 ? "(HEARTBEAT)" : "(ZEROED)");
            dump_hex((const uint8_t *)a2, psz);
            if (num >= 0x10) { ++g_ano_ioctl_zeroed; __builtin_memset((void *)a2, 0, psz); }
        }
    }
    return syscall(nr, a0, a1, a2, a3, a4, a5);
}

// Protection 13: unwind_xx_ioctl — libanort.so secondary ioctl interface that
// may bypass our primary ioctl GOT hook.  Same zero-payload logic.
static int hook_unwind_ioctl(int fd, unsigned long req, void *arg) {
    unsigned long type = (req >> 8) & 0xFF;
    unsigned long num  = req & 0xFF;
    bool is_system = type == 0x54 || type == 0x66 || type == 0x53 || type == 0x89 || type == 0x00;
    if (!is_system && arg) {
        size_t psz = (req >> 16) & 0x3FFF;
        if (psz == 0) psz = 64; if (psz > 512) psz = 512;
        dump_write("[UNWIND-IOCTL] fd=%d req=0x%lx cmd=0x%02lx size=%zu %s\n",
                   fd, req, num, psz, num < 0x10 ? "(HEARTBEAT)" : "(ZEROED)");
        dump_hex((const uint8_t *)arg, psz);
        if (num >= 0x10) { ++g_ano_ioctl_zeroed; __builtin_memset(arg, 0, psz); }
    }
    return ::ioctl(fd, req, arg);
}

// Protection 7: raw syscall bypass — intercept SYS_openat targeting /proc/self/maps
// AArch64 ABI: syscall(nr, a0, a1, a2, ...) → x0=nr, x1=a0, x2=a1=path, x3=a2=flags
static long hook_syscall_got(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
    if (nr == __NR_openat && a1 != 0) {
        const char *path = (const char *)a1;
        if (is_self_maps(path))      return (long)make_filtered_maps(path);
        if (is_self_mountinfo(path)) return (long)make_filtered_mountinfo(path);
        if (is_self_status(path))    return (long)make_filtered_status(path);
        if (is_proc_net_unix(path))  return (long)make_filtered_unix(path);
        if (is_self_environ(path))   return (long)make_filtered_environ();
    }
    if (nr == __NR_ioctl) {
        unsigned long req  = (unsigned long)a1;
        unsigned long type = (req >> 8) & 0xFF;
        unsigned long num  = req & 0xFF;
        bool is_system = type == 0x54 || type == 0x66 || type == 0x53 || type == 0x89 || type == 0x00;
        if (!is_system && a2 != 0) {
            size_t psz = (req >> 16) & 0x3FFF;
            if (psz == 0) psz = 64; if (psz > 512) psz = 512;
            dump_write("[GOT-IOCTL] fd=%ld req=0x%lx cmd=0x%02lx size=%zu %s\n",
                       a0, req, num, psz, num < 0x10 ? "(HEARTBEAT)" : "(ZEROED)");
            dump_hex((const uint8_t *)a2, psz);
            if (num >= 0x10) { ++g_ano_ioctl_zeroed; __builtin_memset((void *)a2, 0, psz); }
        }
    }
    return syscall(nr, a0, a1, a2, a3, a4, a5);
}

// Protection 9: ioctl interception — AnoSDK sends ban-triggering detection reports via ioctl.
// cmd layout (AnoSDK v4.x+): cmd < 0x10 = init/heartbeat (MUST pass through).
//                              cmd >= 0x10 = detection report → zero out payload, block ban.
// Full payload dumped to file + logcat before zeroing.
static int hook_ioctl(int fd, unsigned long req, void *arg) {
    unsigned long type = (req >> 8) & 0xFF;
    unsigned long num  = req & 0xFF;

    bool is_system_ioctl =
        type == 0x54 || type == 0x66 || type == 0x53 ||
        type == 0x89 || type == 0x00;

    if (!is_system_ioctl) {
        size_t payload_sz = (req >> 16) & 0x3FFF;
        if (payload_sz == 0) payload_sz = 64;
        if (payload_sz > 512) payload_sz = 512;

        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);

        if (arg) {
            const uint8_t *p = (const uint8_t *)arg;
            s_dump_count++;

            LOGI("[IOCTL-BAN] #%d fd=%d req=0x%lx type=0x%lx num=0x%lx size=%zu "
                 "first32: %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x "
                 "%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
                 s_dump_count, fd, req, type, num, payload_sz,
                 p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7],
                 p[8],p[9],p[10],p[11],p[12],p[13],p[14],p[15],
                 p[16],p[17],p[18],p[19],p[20],p[21],p[22],p[23],
                 p[24],p[25],p[26],p[27],p[28],p[29],p[30],p[31]);

            dump_write("[IOCTL #%d] t=%.3f fd=%d req=0x%lx type=0x%02lx cmd=0x%02lx size=%zu %s\n",
                       s_dump_count, ts.tv_sec + ts.tv_nsec / 1e9,
                       fd, req, type, num, payload_sz,
                       num < 0x10 ? "(HEARTBEAT — passed through)" : "(REPORT — ZEROED)");
            dump_hex(p, payload_sz);

            if (num >= 0x10) {
                ++g_ano_ioctl_zeroed;
                __builtin_memset(arg, 0, payload_sz);
            }
        } else {
            LOGI("[IOCTL-BAN] fd=%d req=0x%lx type=0x%lx num=0x%lx (null arg)", fd, req, type, num);
            dump_write("[IOCTL] t=%.3f fd=%d req=0x%lx type=0x%02lx cmd=0x%02lx (null arg)\n",
                       ts.tv_sec + ts.tv_nsec / 1e9, fd, req, type, num);
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
    if (info->dlpi_name) {
        char h1[16], h2[16];
        ObfStr::mod_id(h1); ObfStr::arm_so(h2);
        if (strstr(info->dlpi_name, h1) || strstr(info->dlpi_name, h2)) {
            ++g_ano_dl_hidden;
            return 0;
        }
    }
    return ctx->user_cb(info, sz, ctx->user_data);
}
static int hook_dl_iterate_phdr(
        int (*cb)(struct dl_phdr_info *, size_t, void *), void *data) {
    DlHideCtx ctx{ cb, data };
    return ::dl_iterate_phdr(dl_hide_trampoline, &ctx);
}

// Protection 19: getenv — AnoSDK calls getenv() directly to read LD_PRELOAD,
// MAGISK_*, ZYGISK_*, RIRU_*, KSU_ environment variables.  This bypasses our
// /proc/self/environ filter.  Return NULL for all root-indicating env vars.
uint32_t g_ano_getenv_filtered = 0;
static char *hook_getenv(const char *name) {
    if (!name) return ::getenv(name);
    volatile char ld[11]; ld[0]='L';ld[1]='D';ld[2]='_';ld[3]='P';ld[4]='R';ld[5]='E';ld[6]='L';ld[7]='O';ld[8]='A';ld[9]='D';ld[10]=0;
    volatile char ldl[16]; ldl[0]='L';ldl[1]='D';ldl[2]='_';ldl[3]='L';ldl[4]='I';ldl[5]='B';ldl[6]='R';ldl[7]='A';ldl[8]='R';ldl[9]='Y';ldl[10]='_';ldl[11]='P';ldl[12]='A';ldl[13]='T';ldl[14]='H';ldl[15]=0;
    volatile char mg[8]; mg[0]='M';mg[1]='A';mg[2]='G';mg[3]='I';mg[4]='S';mg[5]='K';mg[6]='_';mg[7]=0;
    volatile char zg[8]; zg[0]='Z';zg[1]='Y';zg[2]='G';zg[3]='I';zg[4]='S';zg[5]='K';zg[6]='_';zg[7]=0;
    volatile char ri[6]; ri[0]='R';ri[1]='I';ri[2]='R';ri[3]='U';ri[4]='_';ri[5]=0;
    volatile char ks[5]; ks[0]='K';ks[1]='S';ks[2]='U';ks[3]='_';ks[4]=0;
    if (strcmp(name, (const char*)ld) == 0)             { ++g_ano_getenv_filtered; return nullptr; }
    if (strcmp(name, (const char*)ldl) == 0)            { ++g_ano_getenv_filtered; return nullptr; }
    if (strncmp(name, (const char*)mg, 7) == 0)        { ++g_ano_getenv_filtered; return nullptr; }
    if (strncmp(name, (const char*)zg, 7) == 0)        { ++g_ano_getenv_filtered; return nullptr; }
    if (strncmp(name, (const char*)ri, 5) == 0)        { ++g_ano_getenv_filtered; return nullptr; }
    if (strncmp(name, (const char*)ks, 4) == 0)        { ++g_ano_getenv_filtered; return nullptr; }
    if (is_root_path(name))                            { ++g_ano_getenv_filtered; return nullptr; }
    return ::getenv(name);
}

// Protection 20: opendir + readdir — AnoSDK enumerates /data/adb/, /sbin/, etc.
// to discover Magisk/root files via directory listing.
uint32_t g_ano_readdir_filtered = 0;
static bool is_root_dir_entry(const char *name) {
    if (!name) return false;
    struct D {
        static void s0(char *b)  { volatile char *v=(volatile char*)b; v[0]='s';v[1]='u';v[2]=0; }
        static void s1(char *b)  { volatile char *v=(volatile char*)b; v[0]='m';v[1]='a';v[2]='g';v[3]='i';v[4]='s';v[5]='k';v[6]=0; }
        static void s2(char *b)  { volatile char *v=(volatile char*)b; v[0]='.';v[1]='m';v[2]='a';v[3]='g';v[4]='i';v[5]='s';v[6]='k';v[7]=0; }
        static void s3(char *b)  { volatile char *v=(volatile char*)b; v[0]='b';v[1]='u';v[2]='s';v[3]='y';v[4]='b';v[5]='o';v[6]='x';v[7]=0; }
        static void s4(char *b)  { volatile char *v=(volatile char*)b; v[0]='s';v[1]='u';v[2]='p';v[3]='e';v[4]='r';v[5]='s';v[6]='u';v[7]=0; }
        static void s5(char *b)  { volatile char *v=(volatile char*)b; v[0]='z';v[1]='y';v[2]='g';v[3]='i';v[4]='s';v[5]='k';v[6]=0; }
        static void s6(char *b)  { volatile char *v=(volatile char*)b; v[0]='r';v[1]='i';v[2]='r';v[3]='u';v[4]=0; }
        static void s7(char *b)  { volatile char *v=(volatile char*)b; v[0]='x';v[1]='p';v[2]='o';v[3]='s';v[4]='e';v[5]='d';v[6]=0; }
        static void s8(char *b)  { volatile char *v=(volatile char*)b; v[0]='k';v[1]='e';v[2]='r';v[3]='n';v[4]='e';v[5]='l';v[6]='s';v[7]='u';v[8]=0; }
        static void s9(char *b)  { volatile char *v=(volatile char*)b; v[0]='a';v[1]='p';v[2]='a';v[3]='t';v[4]='c';v[5]='h';v[6]=0; }
        static void s10(char *b) { volatile char *v=(volatile char*)b; v[0]='d';v[1]='a';v[2]='e';v[3]='m';v[4]='o';v[5]='n';v[6]='s';v[7]='u';v[8]=0; }
    };
    char t[16];
    D::s0(t);  if (strcmp(name, t) == 0) return true;
    D::s1(t);  if (strstr(name, t)) return true;
    D::s2(t);  if (strcmp(name, t) == 0) return true;
    D::s3(t);  if (strstr(name, t)) return true;
    D::s4(t);  if (strstr(name, t)) return true;
    D::s5(t);  if (strstr(name, t)) return true;
    D::s6(t);  if (strstr(name, t)) return true;
    D::s7(t);  if (strstr(name, t)) return true;
    D::s8(t);  if (strstr(name, t)) return true;
    D::s9(t);  if (strstr(name, t)) return true;
    D::s10(t); if (strstr(name, t)) return true;
    char h1[16];
    ObfStr::mod_id(h1);
    if (strstr(name, h1)) return true;
    return false;
}
static DIR *hook_opendir(const char *name) {
    if (name && is_root_path(name)) {
        ++g_ano_readdir_filtered;
        errno = ENOENT;
        return nullptr;
    }
    return ::opendir(name);
}
static struct dirent *hook_readdir(DIR *dirp) {
    struct dirent *entry;
    for (;;) {
        entry = ::readdir(dirp);
        if (!entry) return nullptr;
        const char *n = entry->d_name;
        if (n[0] == '.' && (n[1] == '\0' || (n[1] == '.' && n[2] == '\0')))
            return entry;
        if (is_root_dir_entry(n)) { ++g_ano_readdir_filtered; continue; }
        return entry;
    }
}

// Protection 21: dladdr — AnoSDK reverse-lookups function pointers via dladdr()
// to discover injected .so files.  If the result's dli_fname contains our module
// name, return 0 (address not found) to hide the module's presence.
uint32_t g_ano_dladdr_spoofed = 0;
static int hook_dladdr(const void *addr, Dl_info *info) {
    int r = ::dladdr(addr, info);
    if (r && info && info->dli_fname) {
        char h1[16], h2[16], h3[16];
        ObfStr::mod_id(h1); ObfStr::mod_dash(h2); ObfStr::arm_so(h3);
        if (strstr(info->dli_fname, h1) || strstr(info->dli_fname, h2) || strstr(info->dli_fname, h3)) {
            ++g_ano_dladdr_spoofed;
            __builtin_memset(info, 0, sizeof(Dl_info));
            return 0;
        }
        if (is_root_path(info->dli_fname)) {
            ++g_ano_dladdr_spoofed;
            __builtin_memset(info, 0, sizeof(Dl_info));
            return 0;
        }
    }
    return r;
}

// Protection 22: fstat — AnoSDK may stat open file descriptors to detect injected
// .so files by inode/device.  Check via /proc/self/fd/<fd> readlink target.
uint32_t g_ano_fstat_filtered = 0;
static int hook_fstat(int fd, struct stat *st) {
    char link_path[64], target[512];
    snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", fd);
    ssize_t len = (ssize_t)syscall(SYS_readlinkat, AT_FDCWD, link_path, target, sizeof(target) - 1);
    if (len > 0) {
        target[len] = '\0';
        char h1[16], h2[16], h3[16];
        ObfStr::mod_id(h1); ObfStr::mod_dash(h2); ObfStr::arm_so(h3);
        if (strstr(target, h1) || strstr(target, h2) || strstr(target, h3) || is_root_path(target)) {
            ++g_ano_fstat_filtered;
            errno = EBADF;
            return -1;
        }
    }
    return ::fstat(fd, st);
}

// Protection 23: pread — libanort.so uses pread() to read file content by fd.
// If the fd points to /proc/self/maps or /proc/self/environ, serve filtered content.
static ssize_t hook_pread(int fd, void *buf, size_t count, off_t offset) {
    char link_path[64], target[256];
    snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", fd);
    ssize_t len = (ssize_t)syscall(SYS_readlinkat, AT_FDCWD, link_path, target, sizeof(target) - 1);
    if (len > 0) {
        target[len] = '\0';
        if (is_self_maps(target)) {
            int ffd = make_filtered_maps(target);
            if (ffd >= 0) {
                ssize_t r = ::pread(ffd, buf, count, offset);
                ::close(ffd);
                return r;
            }
        }
        if (is_self_mountinfo(target)) {
            int ffd = make_filtered_mountinfo(target);
            if (ffd >= 0) {
                ssize_t r = ::pread(ffd, buf, count, offset);
                ::close(ffd);
                return r;
            }
        }
        if (is_self_environ(target)) {
            int ffd = make_filtered_environ();
            if (ffd >= 0) {
                ssize_t r = ::pread(ffd, buf, count, offset);
                ::close(ffd);
                return r;
            }
        }
    }
    return ::pread(fd, buf, count, offset);
}

// Protection 24: prctl — intercept PR_GET_NAME to prevent thread name detection.
// AnoSDK can call prctl(PR_GET_NAME) on suspicious threads.  Also intercept
// PR_SET_VMA_ANON_NAME to sanitize VMA naming that could reveal our module.
static int hook_prctl(int option, unsigned long a2, unsigned long a3,
                      unsigned long a4, unsigned long a5) {
    if (option == PR_SET_VMA && a2 == PR_SET_VMA_ANON_NAME && a3 != 0) {
        // prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, start, len, name)
        //       option       a2                     a3    a4   a5
        const char *vma_name = (const char *)a5;
        if (vma_name) {
            char h1[16];
            ObfStr::mod_id(h1);
            if (strstr(vma_name, h1) || is_root_path(vma_name))
                return ::prctl(option, a2, a3, a4, (unsigned long)"");
        }
    }
    return ::prctl(option, a2, a3, a4, a5);
}

// Protection 25: statfs — AnoSDK checks filesystem type of root-related paths.
static int hook_statfs(const char *path, struct statfs *buf) {
    if (path && is_root_path(path)) {
        errno = ENOENT;
        return -1;
    }
    return ::statfs(path, buf);
}

// Forward declarations for hooks defined later but referenced in kMap
static int hook_sigaction(int sig, const struct sigaction *act, struct sigaction *oldact);
static int hook_clock_gettime(clockid_t clk, struct timespec *tp);

// Protection 26: dlsym — AnoSDK resolves symbol addresses via dlsym() and
// compares them against its own GOT entries to detect GOT hooking.  Return our
// hook addresses for hooked symbols so the comparison passes.
static void *hook_dlsym(void *handle, const char *name) {
    if (name) {
        struct M { const char *s; void *h; };
        static const M kMap[] = {
            {"open",             (void*)hook_open},
            {"__open_2",         (void*)hook_open2},
            {"openat",           (void*)hook_openat2},
            {"__openat_2",       (void*)hook_openat2},
            {"fopen",            (void*)hook_fopen},
            {"popen",            (void*)hook_popen},
            {"syscall",          (void*)hook_syscall_got},
            {"ptrace",           (void*)hook_ptrace},
            {"fork",             (void*)hook_fork},
            {"dl_iterate_phdr",  (void*)hook_dl_iterate_phdr},
            {"ioctl",            (void*)hook_ioctl},
            {"access",           (void*)hook_access},
            {"faccessat",        (void*)hook_faccessat},
            {"stat",             (void*)hook_stat},
            {"lstat",            (void*)hook_lstat},
            {"fstat",            (void*)hook_fstat},
            {"fstatat",          (void*)hook_fstatat},
            {"readlink",         (void*)hook_readlink},
            {"readlinkat",       (void*)hook_readlinkat},
            {"getenv",           (void*)hook_getenv},
            {"opendir",          (void*)hook_opendir},
            {"readdir",          (void*)hook_readdir},
            {"dladdr",           (void*)hook_dladdr},
            {"prctl",            (void*)hook_prctl},
            {"mincore",          (void*)hook_mincore},
            {"kill",             (void*)hook_kill},
            {"inotify_init",     (void*)hook_inotify_init},
            {"__system_property_get", (void*)hook_system_property_get},
            {"read",             (void*)hook_read},
            {"__read_chk",       (void*)hook___read_chk},
            {"fgets",            (void*)hook_fgets},
            {"__fgets_chk",      (void*)hook___fgets_chk},
            {"mmap",             (void*)hook_mmap},
            {"getauxval",        (void*)hook_getauxval},
            {"execl",            (void*)hook_execl},
            {"execv",            (void*)hook_execv},
            {"sigaction",        (void*)hook_sigaction},
            {"statfs",           (void*)hook_statfs},
            {"pread",            (void*)hook_pread},
            {"dlopen",           (void*)hook_dlopen},
            {"clock_gettime",    (void*)hook_clock_gettime},
        };
        for (const auto &e : kMap) {
            if (strcmp(name, e.s) == 0) return e.h;
        }
    }
    return ::dlsym(handle, name);
}

// Protection 28: read / __read_chk — if tp_syscall_imp opens /proc files via raw
// SVC #0, subsequent read() calls still go through the GOT.  Check fd targets
// and serve filtered content for /proc/self/status, environ, net/unix.
// /proc/self/maps is already invisible via hideModuleMaps().
uint32_t g_ano_read_filtered = 0;
static bool is_proc_fd(int fd, char *out, size_t outsz) {
    char lp[48];
    snprintf(lp, sizeof(lp), "/proc/self/fd/%d", fd);
    ssize_t r = (ssize_t)syscall(SYS_readlinkat, AT_FDCWD, lp, out, outsz - 1);
    if (r > 0) { out[r] = '\0'; return true; }
    return false;
}
static ssize_t hook_read(int fd, void *buf, size_t count) {
    if (fd >= 0 && count > 0) {
        char target[256];
        if (is_proc_fd(fd, target, sizeof(target))) {
            if (is_self_maps(target)) {
                int ffd = make_filtered_maps(target);
                if (ffd >= 0) {
                    off_t off = ::lseek(fd, 0, SEEK_CUR);
                    if (off < 0) off = 0;
                    ssize_t r = ::pread(ffd, buf, count, off);
                    if (r > 0) ::lseek(fd, off + r, SEEK_SET);
                    ::close(ffd);
                    ++g_ano_read_filtered;
                    return r >= 0 ? r : 0;
                }
            }
            if (is_self_mountinfo(target)) {
                int ffd = make_filtered_mountinfo(target);
                if (ffd >= 0) {
                    off_t off = ::lseek(fd, 0, SEEK_CUR);
                    if (off < 0) off = 0;
                    ssize_t r = ::pread(ffd, buf, count, off);
                    if (r > 0) ::lseek(fd, off + r, SEEK_SET);
                    ::close(ffd);
                    ++g_ano_read_filtered;
                    return r >= 0 ? r : 0;
                }
            }
            if (is_self_status(target)) {
                int ffd = make_filtered_status(target);
                if (ffd >= 0) {
                    off_t off = ::lseek(fd, 0, SEEK_CUR);
                    if (off < 0) off = 0;
                    ssize_t r = ::pread(ffd, buf, count, off);
                    if (r > 0) ::lseek(fd, off + r, SEEK_SET);
                    ::close(ffd);
                    ++g_ano_read_filtered;
                    return r >= 0 ? r : 0;
                }
            }
            if (is_proc_net_unix(target)) {
                int ffd = make_filtered_unix(target);
                if (ffd >= 0) {
                    off_t off = ::lseek(fd, 0, SEEK_CUR);
                    if (off < 0) off = 0;
                    ssize_t r = ::pread(ffd, buf, count, off);
                    if (r > 0) ::lseek(fd, off + r, SEEK_SET);
                    ::close(ffd);
                    ++g_ano_read_filtered;
                    return r >= 0 ? r : 0;
                }
            }
            if (is_self_environ(target)) {
                int ffd = make_filtered_environ();
                if (ffd >= 0) {
                    off_t off = ::lseek(fd, 0, SEEK_CUR);
                    if (off < 0) off = 0;
                    ssize_t r = ::pread(ffd, buf, count, off);
                    if (r > 0) ::lseek(fd, off + r, SEEK_SET);
                    ::close(ffd);
                    ++g_ano_read_filtered;
                    return r >= 0 ? r : 0;
                }
            }
        }
    }
    return ::read(fd, buf, count);
}
static ssize_t hook___read_chk(int fd, void *buf, size_t count, size_t buflen) {
    (void)buflen;
    return hook_read(fd, buf, count);
}

// Protection 29: fgets / __fgets_chk — line-by-line reads of /proc files opened
// via raw syscall.  Check underlying fd via fileno().
uint32_t g_ano_fgets_filtered = 0;
static char *hook_fgets(char *s, int size, FILE *stream) {
    if (stream && size > 0) {
        int fd = fileno(stream);
        if (fd >= 0) {
            char target[256];
            if (is_proc_fd(fd, target, sizeof(target))) {
                if (is_self_status(target) || is_self_maps(target) ||
                    is_proc_net_unix(target) || is_self_environ(target)) {
                    ++g_ano_fgets_filtered;
                    if (is_self_status(target)) {
                        char *r = ::fgets(s, size, stream);
                        if (r && strncmp(s, "TracerPid:", 10) == 0) {
                            snprintf(s, (size_t)size, "TracerPid:\t0\n");
                        }
                        return r;
                    }
                }
            }
        }
    }
    return ::fgets(s, size, stream);
}
static char *hook___fgets_chk(char *s, int size, FILE *stream, size_t slen) {
    (void)slen;
    return hook_fgets(s, size, stream);
}

// Protection 30: mmap — AnoSDK could mmap /proc/self/maps or other /proc files.
// Block mmap on suspicious /proc file descriptors.
uint32_t g_ano_mmap_filtered = 0;
static void *hook_mmap(void *addr, size_t length, int prot, int flags,
                       int fd, off_t offset) {
    if (fd >= 0 && !(flags & MAP_ANONYMOUS)) {
        char target[256];
        if (is_proc_fd(fd, target, sizeof(target))) {
            if (is_self_maps(target) || is_self_status(target) ||
                is_proc_net_unix(target) || is_self_environ(target)) {
                ++g_ano_mmap_filtered;
                errno = ENODEV;
                return MAP_FAILED;
            }
        }
    }
    return ::mmap(addr, length, prot, flags, fd, offset);
}

// Protection 31: execl/execv — AnoSDK can exec shell commands to probe root.
static int hook_execl(const char *path, const char *arg, ...) {
    (void)path; (void)arg;
    errno = EACCES;
    return -1;
}
static int hook_execv(const char *path, char *const argv[]) {
    (void)path; (void)argv;
    errno = EACCES;
    return -1;
}

// Protection 32: getauxval — AT_SECURE reveals LD_PRELOAD injection.
// AT_HWCAP/AT_HWCAP2 are safe to pass through.
#include <sys/auxv.h>
static unsigned long hook_getauxval(unsigned long type) {
    if (type == AT_SECURE) return 0;
    return ::getauxval(type);
}

// Protection 33: sigaction — AnoSDK reads back signal handlers via
// sigaction(sig, NULL, &old) and may dladdr() the handler address.
// When querying SIGABRT/SIGTERM (which we installed noop handlers on),
// report SIG_DFL so the handler address is never exposed.
static int hook_sigaction(int sig, const struct sigaction *act,
                          struct sigaction *oldact) {
    // Block AnoSDK from overriding our SIGSYS handler (seccomp SVC filter)
    if (sig == SIGSYS && act != nullptr)
        return 0;

    int r = ::sigaction(sig, act, oldact);
    if (r == 0 && oldact && !act &&
        (sig == SIGABRT || sig == SIGTERM || sig == SIGSYS)) {
        if (oldact->sa_handler != SIG_DFL && oldact->sa_handler != SIG_IGN) {
            oldact->sa_handler = SIG_DFL;
            sigemptyset(&oldact->sa_mask);
            oldact->sa_flags = 0;
        }
    }
    return r;
}

// Protection 34: clock_gettime — AnoSDK measures execution time across hooked
// functions.  If a GOT-hooked call takes significantly longer than a direct SVC,
// it raises a timing anomaly flag.  Compensate by caching the baseline timestamp
// and returning it when calls arrive in rapid succession (< 100 µs apart),
// which masks the overhead of our hook chain.
#include <time.h>
static thread_local struct timespec s_last_ts = {};
static thread_local uint64_t       s_last_ns = 0;
static int hook_clock_gettime(clockid_t clk, struct timespec *tp) {
    int r = ::clock_gettime(clk, tp);
    if (r == 0 && tp && (clk == CLOCK_MONOTONIC || clk == CLOCK_MONOTONIC_RAW)) {
        uint64_t now = (uint64_t)tp->tv_sec * 1000000000ULL + (uint64_t)tp->tv_nsec;
        uint64_t delta = now - s_last_ns;
        if (s_last_ns != 0 && delta < 100000) {
            *tp = s_last_ts;
        } else {
            s_last_ts = *tp;
            s_last_ns = now;
        }
    }
    return r;
}

// Protection 27: dlopen — AnoSDK may try to dlopen libraries by name to scan
// them.  Block opening our module or root-related paths.
static void *hook_dlopen(const char *filename, int flags) {
    if (filename) {
        char h1[16], h2[16], h3[16];
        ObfStr::mod_id(h1); ObfStr::mod_dash(h2); ObfStr::arm_so(h3);
        if (strstr(filename, h1) || strstr(filename, h2) || strstr(filename, h3)
            || is_root_path(filename)) {
            errno = ENOENT;
            return nullptr;
        }
    }
    return ::dlopen(filename, flags);
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
    int fd = (int)safe_syscall(__NR_openat, (long)AT_FDCWD, (long)"/proc/self/maps", (long)O_RDONLY, 0L);
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
    // Protection 10: inotify filesystem watcher
    { "inotify_init",     reinterpret_cast<void *>(hook_inotify_init)    },
    { "inotify_init1",    reinterpret_cast<void *>(hook_inotify_init1)   },
    { "inotify_add_watch",reinterpret_cast<void *>(hook_inotify_add_watch)},
    // Protection 11: mincore memory page detection
    { "mincore",          reinterpret_cast<void *>(hook_mincore)         },
    // Protection 12: tp_syscall_imp raw syscall (if imported via GOT)
    { "tp_syscall_imp",   reinterpret_cast<void *>(hook_tp_syscall)      },
    // Protection 14: readlinkat — /proc/self/fd enumeration
    { "readlinkat",       reinterpret_cast<void *>(hook_readlinkat)      },
    { "readlink",         reinterpret_cast<void *>(hook_readlink)        },
    // Protection 15: access — root path probing
    { "access",           reinterpret_cast<void *>(hook_access)          },
    { "faccessat",        reinterpret_cast<void *>(hook_faccessat)       },
    // Protection 16: stat — root path detection
    { "stat",             reinterpret_cast<void *>(hook_stat)            },
    { "lstat",            reinterpret_cast<void *>(hook_lstat)           },
    { "fstatat",          reinterpret_cast<void *>(hook_fstatat)         },
    // Protection 17: system property spoofing
    { "__system_property_get", reinterpret_cast<void *>(hook_system_property_get) },
    // Protection 19: getenv — direct env var reads
    { "getenv",           reinterpret_cast<void *>(hook_getenv)            },
    // Protection 20: opendir/readdir — directory enumeration
    { "opendir",          reinterpret_cast<void *>(hook_opendir)           },
    { "readdir",          reinterpret_cast<void *>(hook_readdir)           },
    // Protection 21: dladdr — reverse function pointer lookup
    { "dladdr",           reinterpret_cast<void *>(hook_dladdr)            },
    // Protection 22: fstat — fd stat detection
    { "fstat",            reinterpret_cast<void *>(hook_fstat)             },
    // Protection 24: prctl — thread/VMA name detection
    { "prctl",            reinterpret_cast<void *>(hook_prctl)             },
    // Protection 25: statfs — filesystem type probing
    { "statfs",           reinterpret_cast<void *>(hook_statfs)            },
    // Protection 26: dlsym — GOT integrity check defense
    { "dlsym",            reinterpret_cast<void *>(hook_dlsym)             },
    // Protection 27: dlopen — prevent module/root library loading
    { "dlopen",           reinterpret_cast<void *>(hook_dlopen)            },
    // Protection 28: read — filter /proc reads from SVC-opened fds
    { "read",             reinterpret_cast<void *>(hook_read)              },
    { "__read_chk",       reinterpret_cast<void *>(hook___read_chk)        },
    // Protection 29: fgets — line-by-line /proc reads
    { "fgets",            reinterpret_cast<void *>(hook_fgets)             },
    { "__fgets_chk",      reinterpret_cast<void *>(hook___fgets_chk)       },
    // Protection 30: mmap — block mmap of /proc file fds
    { "mmap",             reinterpret_cast<void *>(hook_mmap)              },
    // Protection 31: execl — block command execution
    { "execl",            reinterpret_cast<void *>(hook_execl)             },
    // Protection 32: getauxval — spoof AT_SECURE
    { "getauxval",        reinterpret_cast<void *>(hook_getauxval)         },
    // Protection 33: sigaction — hide our signal handler addresses
    { "sigaction",        reinterpret_cast<void *>(hook_sigaction)         },
    // Protection 34: clock_gettime — timing anomaly defense
    { "clock_gettime",    reinterpret_cast<void *>(hook_clock_gettime)     },
};

static const PatchEntry kAnortEntries[] = {
    { "open",             reinterpret_cast<void *>(hook_open)            },
    { "__open_2",         reinterpret_cast<void *>(hook_open2)           },
    { "__openat_2",       reinterpret_cast<void *>(hook_openat2)         },
    { "openat",           reinterpret_cast<void *>(hook_openat2)         },
    { "fopen",            reinterpret_cast<void *>(hook_fopen)           },
    { "popen",            reinterpret_cast<void *>(hook_popen)           },
    { "pclose",           reinterpret_cast<void *>(hook_pclose)          },
    { "kill",             reinterpret_cast<void *>(hook_kill)            },
    { "exit",             reinterpret_cast<void *>(hook_exit)            },
    { "_exit",            reinterpret_cast<void *>(hook__exit)           },
    { "abort",            reinterpret_cast<void *>(hook_abort)           },
    { "ptrace",           reinterpret_cast<void *>(hook_ptrace)          },
    { "fork",             reinterpret_cast<void *>(hook_fork)            },
    { "syscall",          reinterpret_cast<void *>(hook_syscall_got)     },
    { "ioctl",            reinterpret_cast<void *>(hook_ioctl)           },
    { "dl_iterate_phdr",  reinterpret_cast<void *>(hook_dl_iterate_phdr) },
    // Protection 10-13: inotify, mincore, tp_syscall, secondary ioctl
    { "inotify_init",     reinterpret_cast<void *>(hook_inotify_init)    },
    { "inotify_init1",    reinterpret_cast<void *>(hook_inotify_init1)   },
    { "inotify_add_watch",reinterpret_cast<void *>(hook_inotify_add_watch)},
    { "mincore",          reinterpret_cast<void *>(hook_mincore)         },
    { "tp_syscall_imp",   reinterpret_cast<void *>(hook_tp_syscall)      },
    { "unwind_xx_ioctl",  reinterpret_cast<void *>(hook_unwind_ioctl)    },
    { "unwind_xx_info_query", reinterpret_cast<void *>(hook_unwind_ioctl)},
    // Protection 14-17: same as anogs
    { "readlinkat",       reinterpret_cast<void *>(hook_readlinkat)      },
    { "readlink",         reinterpret_cast<void *>(hook_readlink)        },
    { "access",           reinterpret_cast<void *>(hook_access)          },
    { "faccessat",        reinterpret_cast<void *>(hook_faccessat)       },
    { "stat",             reinterpret_cast<void *>(hook_stat)            },
    { "lstat",            reinterpret_cast<void *>(hook_lstat)           },
    { "fstatat",          reinterpret_cast<void *>(hook_fstatat)         },
    { "__system_property_get", reinterpret_cast<void *>(hook_system_property_get) },
    // Protection 19: getenv — direct env var reads
    { "getenv",           reinterpret_cast<void *>(hook_getenv)            },
    // Protection 20: opendir/readdir — directory enumeration
    { "opendir",          reinterpret_cast<void *>(hook_opendir)           },
    { "readdir",          reinterpret_cast<void *>(hook_readdir)           },
    // Protection 21: dladdr — reverse function pointer lookup
    { "dladdr",           reinterpret_cast<void *>(hook_dladdr)            },
    // Protection 22: fstat — fd stat detection
    { "fstat",            reinterpret_cast<void *>(hook_fstat)             },
    // Protection 23: pread — direct fd read bypass
    { "pread",            reinterpret_cast<void *>(hook_pread)             },
    // Protection 24: prctl — thread/VMA name detection
    { "prctl",            reinterpret_cast<void *>(hook_prctl)             },
    // Protection 26: dlsym — GOT integrity check defense
    { "dlsym",            reinterpret_cast<void *>(hook_dlsym)             },
    // Protection 27: dlopen — prevent module/root library loading
    { "dlopen",           reinterpret_cast<void *>(hook_dlopen)            },
    // Protection 28: read — filter /proc reads from SVC-opened fds
    { "read",             reinterpret_cast<void *>(hook_read)              },
    { "__read_chk",       reinterpret_cast<void *>(hook___read_chk)        },
    // Protection 29: fgets — line-by-line /proc reads
    { "fgets",            reinterpret_cast<void *>(hook_fgets)             },
    // Protection 30: mmap — block mmap of /proc file fds
    { "mmap",             reinterpret_cast<void *>(hook_mmap)              },
    // Protection 31: execv — block command execution (anort imports execv)
    { "execv",            reinterpret_cast<void *>(hook_execv)             },
    // Protection 33: sigaction — hide our signal handler addresses
    { "sigaction",        reinterpret_cast<void *>(hook_sigaction)         },
    // Protection 34: clock_gettime — timing anomaly defense
    { "clock_gettime",    reinterpret_cast<void *>(hook_clock_gettime)     },
};

// ── Protection 35: seccomp SVC filter ─────────────────────────────────────────
// libanogs.so contains 51 inline SVC #0 instructions that bypass ALL GOT hooks.
// These raw syscalls read /proc/self/maps, /proc/self/status, and send ioctl
// reports without touching any libc function we can intercept via GOT patching.
//
// Fix: install a seccomp-bpf filter that checks the instruction_pointer of each
// syscall.  When the IP falls inside libanogs.so or libanort.so text segments
// and the syscall is one of our filtered set (openat, readlinkat, ioctl), the
// kernel delivers SIGSYS instead of executing the syscall.  Our SIGSYS handler
// applies the same filtering logic as our GOT hooks: /proc paths get sanitised
// memfds, ioctl payloads get zeroed, everything else passes through.
//
// This closes the last major detection gap: raw SVC now gets the same treatment
// as GOT-hooked libc calls.

static void sigsys_handler(int sig, siginfo_t *info, void *uctx) {
    (void)sig; (void)info;
    ucontext_t *ctx = static_cast<ucontext_t *>(uctx);
    long nr = (long)ctx->uc_mcontext.regs[8];
    long a0 = (long)ctx->uc_mcontext.regs[0];
    long a1 = (long)ctx->uc_mcontext.regs[1];
    long a2 = (long)ctx->uc_mcontext.regs[2];
    long a3 = (long)ctx->uc_mcontext.regs[3];
    long a4 = (long)ctx->uc_mcontext.regs[4];
    long a5 = (long)ctx->uc_mcontext.regs[5];

    long result;

    switch (nr) {
        case __NR_openat: {
            if (a1) {
                const char *path = (const char *)a1;
                if (is_self_maps(path))      { ++g_ano_svc_trapped; result = (long)make_filtered_maps(path);      break; }
                if (is_self_mountinfo(path)) { ++g_ano_svc_trapped; result = (long)make_filtered_mountinfo(path); break; }
                if (is_self_status(path))    { ++g_ano_svc_trapped; result = (long)make_filtered_status(path);    break; }
                if (is_proc_net_unix(path))  { ++g_ano_svc_trapped; result = (long)make_filtered_unix(path);      break; }
                if (is_self_environ(path))   { ++g_ano_svc_trapped; result = (long)make_filtered_environ();       break; }
                if (is_root_path(path))      { ++g_ano_svc_trapped; result = -ENOENT; break; }
                diag_log_svc_path(path);
            }
            result = safe_syscall(__NR_openat, a0, a1, a2, a3);
            break;
        }
        case __NR_readlinkat: {
            if (a1) {
                const char *path = (const char *)a1;
                char pidpath[64];
                snprintf(pidpath, sizeof(pidpath), "/proc/%d/exe", (int)getpid());
                if (strcmp(path, "/proc/self/exe") == 0 || strcmp(path, pidpath) == 0) {
                    ++g_ano_svc_trapped;
                    const char *fake = "/system/bin/app_process64";
                    size_t len = __builtin_strlen(fake);
                    if (len > (size_t)a3) len = (size_t)a3;
                    __builtin_memcpy((char *)a2, fake, len);
                    result = (long)len;
                    break;
                }
            }
            result = safe_syscall(__NR_readlinkat, a0, a1, a2, a3);
            break;
        }
        case __NR_newfstatat: {
            // fstatat(dirfd, pathname, statbuf, flags)
            if (a1) {
                const char *path = (const char *)a1;
                if (is_root_path(path)) {
                    ++g_ano_svc_trapped;
                    result = -ENOENT;
                    break;
                }
            }
            result = safe_syscall(nr, a0, a1, a2, a3);
            break;
        }
        case __NR_faccessat:
        case __NR_faccessat2: {
            // faccessat(dirfd, pathname, mode, flags)
            if (a1) {
                const char *path = (const char *)a1;
                if (is_root_path(path)) {
                    ++g_ano_svc_trapped;
                    result = -ENOENT;
                    break;
                }
            }
            result = safe_syscall(nr, a0, a1, a2, a3);
            break;
        }
        case __NR_statx: {
            // statx(dirfd, pathname, flags, mask, statxbuf)
            if (a1) {
                const char *path = (const char *)a1;
                if (is_root_path(path)) {
                    ++g_ano_svc_trapped;
                    result = -ENOENT;
                    break;
                }
            }
            result = safe_syscall(nr, a0, a1, a2, a3, a4);
            break;
        }
        default:
            result = safe_syscall(nr, a0, a1, a2, a3, a4, a5);
            break;
    }

    ctx->uc_mcontext.regs[0] = (uint64_t)result;
}

static bool installSvcFilter() {
    if (!s_trampoline) {
        LOGE("[SECCOMP] no trampoline — cannot install");
        return false;
    }

    struct sigaction sa{};
    sa.sa_sigaction = sigsys_handler;
    sa.sa_flags     = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    if (::sigaction(SIGSYS, &sa, nullptr) != 0) {
        LOGE("[SECCOMP] sigaction(SIGSYS) failed errno=%d", errno);
        return false;
    }

    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    uint32_t tr_hi  = (uint32_t)(s_trampoline_start >> 32);
    uint32_t tr_lo  = (uint32_t)(s_trampoline_start & 0xFFFFFFFFULL);
    uint32_t tr_end = (uint32_t)(s_trampoline_end   & 0xFFFFFFFFULL);

    // BPF: trap filesystem-probing syscalls EXCEPT when IP is in our trampoline.
    // Covers raw SVC from anywhere (anonymous mmap, JIT, copied code stubs).
    // Trapped: openat, readlinkat, newfstatat, faccessat, faccessat2, statx
    struct sock_filter filt[] = {
        /* 0  */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 4),
        /* 1  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 0, 15),
        /* 2  */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
        /* 3  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat,      6, 0),
        /* 4  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_readlinkat,  5, 0),
        /* 5  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_newfstatat,  4, 0),
        /* 6  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_faccessat,   3, 0),
        /* 7  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_statx,       2, 0),
        /* 8  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_faccessat2,  1, 0),
        /* 9  */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        // ── Whitelist our trampoline page ──
        /*10 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 12),
        /*11 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, tr_hi, 0, 4),
        /*12 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 8),
        /*13 */ BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, tr_lo, 0, 2),
        /*14 */ BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, tr_end, 1, 0),
        /*15 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /*16 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        /*17 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len    = (unsigned short)(sizeof(filt) / sizeof(filt[0])),
        .filter = filt,
    };

    long ret = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                       SECCOMP_FILTER_FLAG_TSYNC, &prog);
    if (ret != 0)
        ret = prctl(PR_SET_SECCOMP, 2, (unsigned long)&prog, 0, 0);

    if (ret == 0)
        LOGI("[SECCOMP] SVC filter installed — trampoline=[0x%lx,0x%lx)",
             s_trampoline_start, s_trampoline_end);
    else
        LOGE("[SECCOMP] install failed errno=%d", errno);
    return ret == 0;
}

// ── Module map hiding ─────────────────────────────────────────────────────────
// libanort.so uses tp_syscall_imp (raw SVC #0) to read /proc/self/maps directly,
// bypassing ALL GOT hooks.  If our module shows up in maps → server-side ban.
//
// Fix: after loading, replace every file-backed mapping of our .so with an
// anonymous mapping containing the same bytes.  mremap(MREMAP_FIXED) swaps
// atomically — threads executing from the region keep running with identical
// content, but /proc/self/maps no longer shows a filename.

static void hideModuleMaps() {
    int fd = (int)safe_syscall(__NR_openat, (long)AT_FDCWD, (long)"/proc/self/maps", (long)O_RDONLY, 0L);
    if (fd < 0) return;

    struct Region { uintptr_t start, end; int prot; };
    Region regions[16];
    int nreg = 0;

    char buf[4096], line[512];
    int llen = 0;
    for (;;) {
        ssize_t n = (ssize_t)syscall(SYS_read, fd, buf, sizeof(buf));
        if (n <= 0) break;
        for (ssize_t i = 0; i < n; i++) {
            if (llen < (int)sizeof(line) - 1) line[llen++] = buf[i];
            if (buf[i] == '\n' || llen >= (int)sizeof(line) - 1) {
                line[llen] = '\0';
                char _f1[16], _f2[16], _f3[16], _f5[16];
                ObfStr::arm_so(_f1); ObfStr::mod_id(_f2); ObfStr::mod_dash(_f3); ObfStr::payload(_f5);
                if ((strstr(line, _f1) || strstr(line, _f2) ||
                     strstr(line, _f3) || strstr(line, _f5)) && nreg < 16) {
                    uintptr_t s = 0, e = 0;
                    char p[5] = {};
                    if (sscanf(line, "%lx-%lx %4s", &s, &e, p) == 3 && s < e) {
                        int prot = 0;
                        if (p[0] == 'r') prot |= PROT_READ;
                        if (p[1] == 'w') prot |= PROT_WRITE;
                        if (p[2] == 'x') prot |= PROT_EXEC;
                        regions[nreg++] = {s, e, prot};
                    }
                }
                llen = 0;
            }
        }
    }
    syscall(SYS_close, fd);

    if (nreg == 0) { LOGI("[HIDE] no module regions found in maps"); return; }

    int hidden = 0;
    for (int i = 0; i < nreg; i++) {
        size_t sz = regions[i].end - regions[i].start;

        // Allocate anonymous copy and duplicate content
        void *copy = mmap(nullptr, sz, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (copy == MAP_FAILED) {
            LOGE("[HIDE] mmap copy failed for 0x%lx sz=%zu errno=%d",
                 regions[i].start, sz, errno);
            continue;
        }
        __builtin_memcpy(copy, reinterpret_cast<void *>(regions[i].start), sz);

        // Set correct permissions on the copy BEFORE the atomic swap
        if (regions[i].prot != (PROT_READ | PROT_WRITE))
            mprotect(copy, sz, regions[i].prot);

        // Atomic swap: mremap moves our anonymous copy to the original address,
        // replacing the file-backed mapping.  Content is identical, so any thread
        // executing from .text keeps running uninterrupted.
        void *result = mremap(copy, sz, sz, MREMAP_MAYMOVE | MREMAP_FIXED,
                              reinterpret_cast<void *>(regions[i].start));
        if (result == MAP_FAILED) {
            LOGE("[HIDE] mremap failed for 0x%lx sz=%zu errno=%d — trying fallback",
                 regions[i].start, sz, errno);
            // Fallback for non-executable regions: mmap over + copy back
            if (!(regions[i].prot & PROT_EXEC)) {
                void *anon = mmap(reinterpret_cast<void *>(regions[i].start), sz,
                                  PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
                if (anon != MAP_FAILED) {
                    __builtin_memcpy(anon, copy, sz);
                    mprotect(anon, sz, regions[i].prot);
                    hidden++;
                }
            }
            munmap(copy, sz);
        } else {
            hidden++;
        }

        // Name the region to blend with normal Android allocations
        // Executable regions use "linker_alloc" (linker has r-xp anonymous pages)
        // Non-executable use "dalvik-LinearAlloc" (standard ART allocation)
        const char *vma_name = (regions[i].prot & PROT_EXEC)
                               ? "linker_alloc" : "dalvik-LinearAlloc";
        prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME,
              regions[i].start, sz, vma_name);
    }

    // Zero ELF headers in the first region of each module mapping.
    // Runs BEFORE seccomp, so open(/proc/self/mem) succeeds.
    // After this, AnoSDK's memory scanner can't find ELF magic in anonymous pages.
    int mem_fd = open("/proc/self/mem", O_RDWR);
    if (mem_fd >= 0) {
        uint8_t zeros[0x1000] = {};
        for (int i = 0; i < nreg; i++) {
            auto *hdr = reinterpret_cast<unsigned char *>(regions[i].start);
            if (hdr[0] == 0x7f && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F') {
                size_t chunk = (regions[i].end - regions[i].start);
                if (chunk > sizeof(zeros)) chunk = sizeof(zeros);
                pwrite(mem_fd, zeros, chunk, (off_t)regions[i].start);
                LOGI("[HIDE] ELF header zeroed at 0x%lx", regions[i].start);
            }
        }
        close(mem_fd);
    }

    LOGI("[HIDE] %d/%d module regions converted to anonymous", hidden, nreg);
}

// ── Watcher thread ────────────────────────────────────────────────────────────

static void *gotWatcherThread(void *) {
    // Hide thread name — default Zygisk thread names are suspicious in /proc/self/task/
    pthread_setname_np(pthread_self(), "Binder:9_3");

    // Phase 1 (attempts 0–49):  50ms sleep → ~2.5s fast scan for early loaders
    // Phase 2 (attempts 50–599): 500ms sleep → ~275s slow poll for late AnoSDK
    // Total window: ~277s ≈ 4.6 minutes — AnoSDK often loads 30-60s into game init
    constexpr int kMaxAttempts  = 600;
    constexpr int kZeroGiveUp   = 100;

    static const int kAnogsExp = (int)(sizeof(kAnogsEntries)/sizeof(kAnogsEntries[0]));
    static const int kAnortExp = (int)(sizeof(kAnortEntries)/sizeof(kAnortEntries[0]));

    bool anogs_done = false, anort_done = false;
    bool anogs_diag = false, anort_diag = false;
    int  anogs_zero   = 0,     anort_zero   = 0;
    int  anogs_prev   = -1,    anort_prev   = -1;
    int  anogs_stable = 0,     anort_stable = 0;

    char _anogs_name[16], _anort_name[16];
    ObfStr::anogs(_anogs_name); ObfStr::anort(_anort_name);

    for (int attempt = 0; attempt < kMaxAttempts && (!anogs_done || !anort_done); attempt++) {
        usleep(attempt < 50 ? 50000u : 500000u);

        if (attempt > 0 && attempt % 60 == 0)
            LOGI("watcher: poll #%d — anogs=%s anort=%s", attempt,
                 anogs_done ? "done" : (anogs_prev >= 0 ? "patching" : "not_loaded"),
                 anort_done ? "done" : (anort_prev >= 0 ? "patching" : "not_loaded"));

        if (!anogs_done) {
            uintptr_t base = findLibBase(_anogs_name);
            if (base) {
                int n = patchLibGot(base, kAnogsEntries, kAnogsExp);
                if (n != anogs_prev) {
                    LOGI("sdk-a GOT: %d/%d slots patched (base=0x%lx)", n, kAnogsExp, base);
                    anogs_prev   = n;
                    anogs_stable = 0;
                }
                if (n == 0) {
                    anogs_zero++;
                    if (!anogs_diag) {
                        anogs_diag = true;
                        char _ag[16]; ObfStr::anogs(_ag);
                        diagLibGot(_ag, base);
                    }
                    if (anogs_zero >= kZeroGiveUp) {
                        LOGE("sdk-a: GIVING UP after %d zero-patch attempts", kZeroGiveUp);
                        anogs_done = true;
                    }
                } else {
                    anogs_zero = 0;
                    if (n >= kAnogsExp) {
                        anogs_done = true;
                    } else if (++anogs_stable >= 3) {
                        LOGI("sdk-a GOT: stable at %d/%d — marking done", n, kAnogsExp);
                        anogs_done = true;
                    }
                }
            }
        }

        if (!anort_done) {
            uintptr_t base = findLibBase(_anort_name);
            if (base) {
                int n = patchLibGot(base, kAnortEntries, kAnortExp);
                if (n != anort_prev) {
                    LOGI("sdk-b GOT: %d/%d slots patched (base=0x%lx)", n, kAnortExp, base);
                    anort_prev   = n;
                    anort_stable = 0;
                }
                if (n == 0) {
                    anort_zero++;
                    if (!anort_diag) {
                        anort_diag = true;
                        char _ar[16]; ObfStr::anort(_ar);
                        diagLibGot(_ar, base);
                    }
                    if (anort_zero >= kZeroGiveUp) {
                        LOGE("sdk-b: GIVING UP after %d zero-patch attempts", kZeroGiveUp);
                        anort_done = true;
                    }
                } else {
                    anort_zero = 0;
                    if (n >= kAnortExp) {
                        anort_done = true;
                    } else if (++anort_stable >= 3) {
                        LOGI("sdk-b GOT: stable at %d/%d — marking done", n, kAnortExp);
                        anort_done = true;
                    }
                }
            }
        }
    }

    LOGI("AnoBypass: watcher done — anogs=%s anort=%s",
         (anogs_prev == kAnogsExp ? "OK" : (anogs_prev > 0 ? "partial" : "FAILED")),
         (anort_prev == kAnortExp ? "OK" : (anort_prev > 0 ? "partial" : "FAILED")));

    // seccomp + hideModuleMaps now run in installEarly() — before AnoSDK even loads

    return nullptr;
}

// ── Public API ────────────────────────────────────────────────────────────────

static void noop_sighandler(int) {}

void AnoBypass::installEarly() {
    // 1. Trampoline — must exist before seccomp filter
    if (!setupTrampoline())
        LOGE("init: trampoline mmap failed");

    // 2. Signal handlers — custom no-op instead of SIG_IGN (AnoSDK flags SIG_IGN)
    struct sigaction sa{};
    sa.sa_handler = noop_sighandler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGABRT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    // 3. Hide module maps IMMEDIATELY — before AnoSDK even loads.
    //    Defeats raw SVC openat /proc/self/maps before GOT hooks are in place.
    hideModuleMaps();

    // 4. Seccomp SVC filter — traps ALL openat/readlinkat except our trampoline.
    //    Installed before AnoSDK loads so there's zero race window.
    installSvcFilter();

    LOGI("init: trampoline + signal handlers + hide + seccomp installed");
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
    LOGI("cleanup complete");
}
