/*
 * stealth_ext.cpp — Layers 7–12: Beyond ZOLAM
 *
 * Derived from full binary analysis of libanogs.so (nm -D + strings):
 *
 * Critical AnoSDK capabilities confirmed and now neutralised:
 *   • dl_iterate_phdr       → enumerate ALL loaded ELF modules (L7)
 *   • opendir + readdir     → list /proc/self/fd entries (L8)
 *   • readlink              → resolve fd → file path (L8)
 *   • inotify_init/add_watch→ watch files for modification (L9)
 *   • popen                 → run shell commands: ps, ls /proc (L10)
 *   • dlopen                → reload itself / load Frida (L7b)
 *   • access                → check for cheat tool files (L10)
 *   • AnoSDKOnRecvSignature → SERVER pushes new scan signatures (L7c)
 *   • AnoSDKOnRecvData      → receives server-side scan results (L7c)
 *   • AnoSDKInitEx          → alternate init path (L7c)
 *   • AnoSDKIoctlOld        → legacy ioctl channel (L7c)
 *   • ptrace (via libc)     → can try to attach to processes (L12b)
 *
 * L7:  dl_iterate_phdr + dlopen + AnoSDK missing exports
 * L8:  /proc/self/fd readdir + readlink spoofing
 * L9:  inotify full nullifier
 * L10: popen gate + access() filter
 * L11: MADV_DONTDUMP + prctl(PR_SET_DUMPABLE,0)
 * L12: Hook integrity watchdog + rotating trampoline signatures
 */

#include "stealth_ext.hpp"
#include "stealth_ext2.hpp"   // stx2_register_rwx for new trampoline pages
#include "stealth_ext7.hpp"   // anogs_patch_got_import, is_hookable_arm64
#include "dobby_stub.hpp"
#include "anti_detect.hpp"
#include <android/log.h>
#include "zx_logbuf.hpp"
#include <dlfcn.h>
#include <link.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <signal.h>
#include <ucontext.h>
#ifndef __NR_openat
#define __NR_openat 56
#endif
#ifndef __NR_mprotect
#define __NR_mprotect 226
#endif
#include <pthread.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cerrno>
#include <atomic>

#define TAG "ZX-STX"
#define LI(fmt, ...) LOGBUF_I(TAG, fmt, ##__VA_ARGS__)
#define LE(fmt, ...) LOGBUF_E(TAG, fmt, ##__VA_ARGS__)

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time XOR (same key as anti_detect.cpp)
// ─────────────────────────────────────────────────────────────────────────────

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
#define OBF_DECODE(var, lit) \
    char var[sizeof(lit)];   \
    do { static constexpr Obf<sizeof(lit)> _o(lit); _o.decode(var); } while(0)

// ─────────────────────────────────────────────────────────────────────────────
// Shared state for /proc/self/fd DIR* tracking (Layer 8)
// ─────────────────────────────────────────────────────────────────────────────

static constexpr int MAX_FD_DIRS = 8;
static std::atomic<uintptr_t> g_fd_dirs[MAX_FD_DIRS];  // DIR* values for /proc/self/fd

static void fddir_add(DIR *d) {
    for (int i = 0; i < MAX_FD_DIRS; i++) {
        uintptr_t exp = 0;
        if (g_fd_dirs[i].compare_exchange_strong(exp, (uintptr_t)d)) return;
    }
}
static void fddir_del(DIR *d) {
    for (int i = 0; i < MAX_FD_DIRS; i++) {
        uintptr_t exp = (uintptr_t)d;
        g_fd_dirs[i].compare_exchange_strong(exp, 0u);
    }
}
static bool fddir_has(DIR *d) {
    for (int i = 0; i < MAX_FD_DIRS; i++)
        if (g_fd_dirs[i].load() == (uintptr_t)d) return true;
    return false;
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 7a — dl_iterate_phdr spoofing
//
// AnoSDK calls dl_iterate_phdr to walk ALL loaded ELF segments.
// It looks for unknown .so names it doesn't recognise (our payload).
// We intercept and skip any entry whose name contains our identifiers.
// ═════════════════════════════════════════════════════════════════════════════

using FnPhdrCb   = int(*)(dl_phdr_info*, size_t, void*);
using FnIterPhdr = int(*)(FnPhdrCb, void*);
static FnIterPhdr g_orig_iter_phdr = nullptr;

// libanogs range for caller-aware hiding (same logic as ext5/ext6)
static uintptr_t s_stx_ano_base = 0;
static uintptr_t s_stx_ano_end  = 0;

static int phdr_find_anogs_stx(dl_phdr_info *info, size_t /*sz*/, void * /*d*/) {
    if (!info->dlpi_name || !strstr(info->dlpi_name, "libanogs.so")) return 0;
    uintptr_t base = (uintptr_t)info->dlpi_addr, end = base;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) &ph = info->dlpi_phdr[i];
        if (ph.p_type == PT_LOAD) {
            uintptr_t se = base + ph.p_vaddr + ph.p_memsz;
            if (se > end) end = se;
        }
    }
    s_stx_ano_base = base; s_stx_ano_end = end; return 1;
}

struct PhdrWrap { FnPhdrCb real_cb; void *real_data; bool from_anogs; };

static int zx_phdr_filter(dl_phdr_info *info, size_t sz, void *data) {
    auto *w = static_cast<PhdrWrap*>(data);
    // Only hide from libanogs callers — IL2CPP exception unwinder must see our
    // .eh_frame or it crashes when unwinding through our hook stack frames
    if (w->from_anogs && info && info->dlpi_name) {
        const char *n = info->dlpi_name;
        if (strstr(n, "zx_") || strstr(n, "ZX_"))
            return 0;
    }
    return w->real_cb(info, sz, w->real_data);
}

static int __attribute__((noinline)) hook_dl_iterate_phdr(FnPhdrCb cb, void *data) {
    if (!g_orig_iter_phdr || !cb) return 0;
    uintptr_t lr = (uintptr_t)__builtin_return_address(0);
    if (!s_stx_ano_base) g_orig_iter_phdr(phdr_find_anogs_stx, nullptr);
    bool from_ano = (s_stx_ano_base && lr >= s_stx_ano_base && lr < s_stx_ano_end);
    PhdrWrap w{ cb, data, from_ano };
    return g_orig_iter_phdr(zx_phdr_filter, &w);
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 7b — dlopen interception
//
// Two purposes:
//  1. Block Frida agent / inject libraries from loading
//  2. Block AnoSDK self-reload when it detects tampering
//     (it tries to dlopen itself with a fresh address to escape hooks)
// ═════════════════════════════════════════════════════════════════════════════

using FnDlopen = void*(*)(const char*, int);
static FnDlopen g_orig_dlopen = nullptr;

static void* hook_dlopen(const char *path, int flags) {
    if (!g_orig_dlopen) return nullptr;
    if (path) {
        // Frida + common inject tool names
        if (strstr(path, "frida")   || strstr(path, "gadget")  ||
            strstr(path, "inject")  || strstr(path, "gum-js")  ||
            strstr(path, "linjector")) {
            LE("Blocked dlopen: %s", path);
            return nullptr;
        }
        // AnoSDK self-reload: return the already-loaded handle
        // so it thinks it succeeded but we remain in control
        if (strstr(path, "anogs")) {
            void *h = g_orig_dlopen(path, RTLD_NOLOAD | RTLD_LAZY);
            return h;
        }
    }
    return g_orig_dlopen(path, flags);
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 7c — AnoSDK missing export hooks
//
// Exports found in nm -D that our previous layers didn't cover:
//   AnoSDKInitEx         — alternate init path (bypasses our AnoSDKInit hook)
//   AnoSDKIoctlOld       — legacy Ioctl channel
//   AnoSDKForExport      — generic export wrapper
//   AnoSDKFree           — memory freeing (tied to scan results)
//   AnoSDKOnRecvData     — receives scan result data from game server
//   AnoSDKOnRecvSignature— SERVER pushes NEW memory signatures to scan for
//   AnoSDKRegistInfoListener — registers info listener callback
// ═════════════════════════════════════════════════════════════════════════════

static int  hook_AnoSDKInitEx(int id, void *d, int l, void *ex)
    { (void)id;(void)d;(void)l;(void)ex; return 0; }
static int  hook_AnoSDKIoctlOld(int c, void *d, int l)
    { (void)c;(void)d;(void)l; return 0; }
static int  hook_AnoSDKForExport(int a, void *b, int c)
    { (void)a;(void)b;(void)c; return 0; }
static void hook_AnoSDKFree(void *p) { (void)p; }
static int  hook_AnoSDKOnRecvData(void *d, int l)
    { (void)d;(void)l; return 0; }
// Most critical: kills server-pushed signature scanning
static int  hook_AnoSDKOnRecvSignature(void *sig, int l)
    { (void)sig;(void)l; return 0; }
static int  hook_AnoSDKRegistInfoListener(void *cb, void *ud)
    { (void)cb;(void)ud; return 0; }

static void install_ano_missing(void *h, const char *lib) {
    auto hk = [&](const char *sym, void *rep) {
        void *a = dlsym(h, sym);
        if (!a) { char buf[128]; snprintf(buf,sizeof(buf),"%s@@ANO",sym); a=dlsym(h,buf); }
        if (!a) a = DobbySymbolResolver(lib, sym);
        if (a) { DobbyHook(a, rep, nullptr); LI("L7c hooked %s", sym); }
    };
    hk("AnoSDKInitEx",            (void*)hook_AnoSDKInitEx);
    hk("AnoSDKIoctlOld",          (void*)hook_AnoSDKIoctlOld);
    hk("AnoSDKForExport",         (void*)hook_AnoSDKForExport);
    hk("AnoSDKFree",              (void*)hook_AnoSDKFree);
    hk("AnoSDKOnRecvData",        (void*)hook_AnoSDKOnRecvData);
    hk("AnoSDKOnRecvSignature",   (void*)hook_AnoSDKOnRecvSignature);
    hk("AnoSDKRegistInfoListener",(void*)hook_AnoSDKRegistInfoListener);
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 8 — /proc/self/fd spoofing
//
// AnoSDK opens /proc/self/fd as a directory, calls readdir to list all fds,
// then readlink on each to find paths → detects our injected .so.
// We hook opendir/closedir/readdir/readlink to hide our fds.
// ═════════════════════════════════════════════════════════════════════════════

using FnOpendir  = DIR*(*)(const char*);
using FnClosedir = int(*)(DIR*);
using FnReaddir  = dirent*(*)(DIR*);
using FnReadlink = ssize_t(*)(const char*, char*, size_t);

static FnOpendir  g_orig_opendir  = nullptr;
static FnClosedir g_orig_closedir = nullptr;
static FnReaddir  g_orig_readdir  = nullptr;
static FnReadlink g_orig_readlink = nullptr;

static bool is_fd_dir_path(const char *p) {
    if (!p) return false;
    // /proc/self/fd or /proc/<pid>/fd
    if (strncmp(p, "/proc/", 6) != 0) return false;
    const char *tail = p + 6;
    if (strncmp(tail, "self/fd", 7) == 0) return true;
    while (*tail >= '0' && *tail <= '9') tail++;
    return (strcmp(tail, "/fd") == 0);
}

static DIR* hook_opendir(const char *path) {
    DIR *d = g_orig_opendir ? g_orig_opendir(path) : nullptr;
    if (d && is_fd_dir_path(path)) fddir_add(d);
    return d;
}

static int hook_closedir(DIR *d) {
    fddir_del(d);
    return g_orig_closedir ? g_orig_closedir(d) : -1;
}

static dirent* hook_readdir(DIR *d) {
    if (!g_orig_readdir) return nullptr;
    if (!fddir_has(d)) return g_orig_readdir(d);

    // This is a /proc/self/fd listing — filter our fds
    while (true) {
        dirent *ent = g_orig_readdir(d);
        if (!ent) return nullptr;

        // Only numeric entries are fds
        const char *nm = ent->d_name;
        if (nm[0] < '0' || nm[0] > '9') return ent;

        // Check what this fd points to via readlink
        char fdpath[64], target[512]{};
        snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%s", nm);
        ssize_t r = g_orig_readlink ? g_orig_readlink(fdpath, target, sizeof(target)-1) : -1;
        if (r > 0) {
            target[r] = 0;
            if (strstr(target, "zx_") || strstr(target, "memfd:zx")) {
                continue;  // skip — fd belongs to our code
            }
        }
        return ent;
    }
}

static ssize_t hook_readlink(const char *path, char *buf, size_t sz) {
    if (!g_orig_readlink) return -1;
    ssize_t r = g_orig_readlink(path, buf, sz);
    if (r > 0 && path && strstr(path, "/proc/") && strstr(path, "/fd/")) {
        if ((size_t)r < sz) buf[r] = 0;
        if (strstr(buf, "zx_") || strstr(buf, "memfd:zx")) {
            // Return /dev/null as the fake path — looks like a closed anonymous fd
            static constexpr char kFake[] = "/dev/null";
            size_t n = strlen(kFake);
            if (n > sz) n = sz;
            memcpy(buf, kFake, n);
            return (ssize_t)n;
        }
    }
    return r;
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 10c — mprotect trap blocker
//
// libanogs calls mprotect(page, 4096, PROT_NONE) during its init to set up
// an "intentional crash trap" page. When detection fires, it accesses that
// page → SIGSEGV → process dies. We intercept mprotect from libanogs's GOT
// and silently discard any PROT_NONE call, leaving the page accessible.
// ═════════════════════════════════════════════════════════════════════════════

using FnMprotect = int(*)(void*, size_t, int);
static FnMprotect g_orig_mprotect = nullptr;

static int hook_mprotect(void *addr, size_t len, int prot) {
    // Only block PROT_NONE calls that target libanogs's own mapped region.
    // Blocking all PROT_NONE breaks libanogs's internal memory protection,
    // triggering detection via a path OTHER than the crash trap.
    if (prot == PROT_NONE && s_stx_ano_base) {
        uintptr_t a = (uintptr_t)addr;
        uintptr_t e = a + len;
        if (a >= s_stx_ano_base && e <= s_stx_ano_end) {
            LI("[mprotect] blocked PROT_NONE inside libanogs @ %p sz=%zu", addr, (size_t)len);
            return 0;
        }
    }
    return g_orig_mprotect ? g_orig_mprotect(addr, len, prot)
                           : (int)syscall(__NR_mprotect, addr, len, prot);
}

// ─────────────────────────────────────────────────────────────────────────────
// SIGSEGV suppressor — catches intentional crash-trap segfaults from libanogs
//
// libanogs's kill mechanism: it mprotect(PROT_NONE) a page at a fixed offset
// inside itself (observed: base+0x502000) and accesses it when detection fires.
// We install a SA_SIGINFO SIGSEGV handler; if si_addr falls inside libanogs's
// mapped range we advance PC by 4 (skip the faulting instruction) and return.
// This turns a fatal SIGSEGV into a skipped instruction.
// ─────────────────────────────────────────────────────────────────────────────

static uintptr_t s_sigv_ano_base = 0;
static uintptr_t s_sigv_ano_end  = 0;

static void __attribute__((noinline))
sigsegv_suppressor(int sig, siginfo_t *info, void *raw_ctx) {
    (void)sig;
    uintptr_t fault_addr = (uintptr_t)info->si_addr;
    if (s_sigv_ano_base && fault_addr >= s_sigv_ano_base && fault_addr < s_sigv_ano_end) {
        // Fault is inside libanogs — intentional crash trap.
        // Strategy: make the faulted page R/W and return WITHOUT changing PC.
        // The faulting instruction re-executes and succeeds (reads 0-bytes).
        // Returning via LR causes the crash-trap's CALLER to deref x0 as a
        // pointer (x0=0 after our fake return) → null-deref at 0x10 → die.
        uintptr_t fault_page = fault_addr & ~(uintptr_t)0xFFF;
        int r2 = (int)syscall(__NR_mprotect, (void*)fault_page, 0x1000,
                              PROT_READ | PROT_WRITE);
        ucontext_t *ctx2 = (ucontext_t*)raw_ctx;
#ifdef __aarch64__
        uintptr_t pc = ctx2->uc_mcontext.pc;
        uintptr_t lr = ctx2->uc_mcontext.regs[30];
#elif defined(__arm__)
        uintptr_t pc = ctx2->uc_mcontext.arm_pc;
        uintptr_t lr = ctx2->uc_mcontext.arm_lr;
#else
        uintptr_t pc = 0, lr = 0;
#endif
        if (r2 == 0) {
            // PROT_NONE page → now accessible; re-execute the faulting load.
            LI("[SIGSEGV] trap %p → unprotected pc=%p lr=%p — re-exec",
               (void*)fault_page, (void*)pc, (void*)lr);
            return; // resume at same PC; instruction re-executes successfully
        }
        // mprotect failed → page is genuinely unmapped (e.g. gap between ELF
        // LOAD segments hit by our full-library scanner).  Advance PC past the
        // faulting instruction so the scanner loop continues instead of spinning.
        LI("[SIGSEGV] trap %p → unmapped (r=%d) pc=%p — skip+4",
           (void*)fault_page, r2, (void*)pc);
#ifdef __aarch64__
        ctx2->uc_mcontext.pc += 4;
#elif defined(__arm__)
        ctx2->uc_mcontext.arm_pc += 4;
#endif
        return; // advance past unmapped access; loop continues
    }
    // Not from libanogs — re-deliver as default (die)
    LI("[SIGSEGV] non-ano fault=%p — reinstating default handler", (void*)fault_addr);
    struct sigaction dfl = {};
    dfl.sa_handler = SIG_DFL;
    sigemptyset(&dfl.sa_mask);
    sigaction(SIGSEGV, &dfl, nullptr);
    raise(SIGSEGV);
}

static void install_sigsegv_suppressor(uintptr_t ano_base, uintptr_t ano_end) {
    s_sigv_ano_base = ano_base;
    s_sigv_ano_end  = ano_end;
    struct sigaction sa = {};
    sa.sa_sigaction = sigsegv_suppressor;
    sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    // Use sigaction() — syscall 186 is mq_notify on ARM64, NOT rt_sigaction (134)
    int r = sigaction(SIGSEGV, &sa, nullptr);
    LI("SIGSEGV suppressor installed for libanogs [%lx-%lx] r=%d",
       (unsigned long)ano_base, (unsigned long)ano_end, r);
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 9 — inotify nullifier
//
// AnoSDK calls inotify_init() to create a watch fd, then inotify_add_watch()
// to monitor its own library for modification (our hooks change its bytes).
// We make inotify_init return -1 so the entire watch mechanism fails silently.
// ═════════════════════════════════════════════════════════════════════════════

using FnInotifyInit     = int(*)();
using FnInotifyAddWatch = int(*)(int, const char*, uint32_t);

static FnInotifyInit     g_orig_inotify_init = nullptr;
static FnInotifyAddWatch g_orig_inotify_add  = nullptr;

static int hook_inotify_init()  { errno = EPERM; return -1; }
static int hook_inotify_add(int fd, const char *path, uint32_t mask) {
    (void)fd; (void)path; (void)mask; return -1;
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 10a — popen gate
//
// AnoSDK uses popen() to run shell commands:
//   "cat /proc/self/maps", "ps -A", "ls /proc/self/fd"
// We intercept and return an empty pipe for security-sensitive queries.
// ═════════════════════════════════════════════════════════════════════════════

using FnPopen  = FILE*(*)(const char*, const char*);
using FnPclose = int(*)(FILE*);

static FnPopen  g_orig_popen  = nullptr;
static FnPclose g_orig_pclose = nullptr;

static bool is_sensitive_cmd(const char *cmd) {
    if (!cmd) return false;
    return strstr(cmd, "maps")    || strstr(cmd, "smaps")   ||
           strstr(cmd, "/proc/")  || strstr(cmd, "ps ")     ||
           strstr(cmd, "ps -")    || strstr(cmd, "lsof")    ||
           strstr(cmd, "/fd")     || strstr(cmd, "frida")   ||
           strstr(cmd, "inject")  || strstr(cmd, "zx_");
}

static FILE* hook_popen(const char *cmd, const char *type) {
    if (is_sensitive_cmd(cmd)) {
        // Return a pipe to /dev/null — AnoSDK gets empty output
        return g_orig_popen ? g_orig_popen(":", type) : nullptr;
    }
    return g_orig_popen ? g_orig_popen(cmd, type) : nullptr;
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 10b — access() filter
//
// AnoSDK calls access() to check if cheat tools exist:
//   /data/local/tmp/frida-server, /su/bin/su, /sbin/su, etc.
// We pass through legitimate checks but block tool-detection checks
// that might cause AnoSDK to enter a higher-alert scan mode.
// ═════════════════════════════════════════════════════════════════════════════

using FnAccess = int(*)(const char*, int);
static FnAccess g_orig_access = nullptr;

static int hook_access(const char *path, int mode) {
    if (path) {
        if (strstr(path, "frida") || strstr(path, "inject") ||
            strstr(path, "zx_")   || strstr(path, "xposed")) {
            errno = ENOENT;
            return -1;
        }
    }
    return g_orig_access ? g_orig_access(path, mode) : -1;
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 10d — fork() neutraliser
//
// libanogs detection dispatch at 0x258668:
//   CBZ W8 (byte[obj+0x876]==0) → 0x2586e8: SKIP fork, run detection in-process
//   fork@plt → CBZ W0 (child)  → 0x2586e8: same kill path from child
//
// Kill path 0x2586e8:
//   1. 0x2588a8: signal_reset — resets SIGSEGV to SIG_DFL
//   2. 0x25895c: detection loop → tail-calls 0x258d14 (ptrace/kill ops)
//   3. 0x258700: _exit(127) — FINAL FAILSAFE even if kill ops are hooked
//
// Fork hook blocks the fork-child path. _exit hook (Layer 10f) is the
// critical blocker for the in-process path (byte==0 bypasses fork entirely).
// ═════════════════════════════════════════════════════════════════════════════

using FnFork = pid_t(*)();
static FnFork g_orig_fork = nullptr;

static pid_t hook_fork() {
    // Non-zero return → parent path; CBZ W0 at 0x2586d0 NOT taken.
    LI("[fork] neutralised — no real fork");
    return (pid_t)2;
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 10f — _exit() / abort() blocker
//
// _exit(127) at 0x258700 is libanogs's FINAL failsafe after all kill ops.
// Runs in the main process when byte[obj+0x876]==0 (no-fork path).
// Hook both _exit and abort to return without terminating the process.
// Also re-install the SIGSEGV suppressor since 0x2588a8 resets it first.
// ═════════════════════════════════════════════════════════════════════════════

using FnExit  = void(*)(int);
using FnAbort = void(*)();
static FnExit  g_orig__exit = nullptr;
static FnAbort g_orig_abort = nullptr;

static void hook__exit(int code) {
    LI("[_exit] blocked code=%d — re-installing SIGSEGV suppressor", code);
    // Re-arm the SIGSEGV suppressor: 0x2588a8 reset it to SIG_DFL before calling us
    if (s_sigv_ano_base) install_sigsegv_suppressor(s_sigv_ano_base, s_sigv_ano_end);
    // Return without exiting — execution falls to the next instruction (new function)
}

static void hook_abort() {
    LI("[abort] blocked — re-installing SIGSEGV suppressor");
    if (s_sigv_ano_base) install_sigsegv_suppressor(s_sigv_ano_base, s_sigv_ano_end);
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 10e — ptrace() neutraliser
//
// libanogs calls ptrace(PTRACE_TRACEME) in a loop (17 call sites, 0x258b10).
// If PTRACE_TRACEME returns -EPERM (already traced), detection fires.
// Hook in GOT always reports success (0) so the anti-debug check passes.
// ═════════════════════════════════════════════════════════════════════════════

using FnPtrace = long(*)(int, pid_t, void*, void*);
static FnPtrace g_orig_ptrace = nullptr;

static long hook_ptrace(int req, pid_t pid, void *addr, void *data) {
    if (req == 0 /* PTRACE_TRACEME */) {
        LI("[ptrace] TRACEME spoofed → 0");
        return 0;
    }
    return g_orig_ptrace ? g_orig_ptrace(req, pid, addr, data) : -1;
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 11 — MADV_DONTDUMP + prctl anti-dump
//
// prctl(PR_SET_DUMPABLE, 0): prevents /proc/self/mem writes and core dumps
//   from any process that doesn't have CAP_SYS_PTRACE.
// MADV_DONTDUMP on anonymous rwxp pages: they are excluded from core dumps
//   and from /proc/PID/mem reads — our trampoline code becomes invisible
//   to memory analysis tools.
// ═════════════════════════════════════════════════════════════════════════════

static void install_anti_dump() {
    // Prevent external memory dump tools
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

    // Apply MADV_DONTDUMP to all anonymous rwxp pages (our trampolines)
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) { LE("L11: can't open maps"); return; }

    char line[256];
    int cnt = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, "rwxp")) continue;
        if (strchr(line, '/')) continue; // skip named .so mappings
        uintptr_t s = 0, e = 0;
        if (sscanf(line, "%lx-%lx", &s, &e) == 2 && s && e > s) {
            madvise((void*)s, e - s, MADV_DONTDUMP);
            cnt++;
        }
    }
    fclose(f);
    LI("L11 MADV_DONTDUMP applied to %d trampoline pages; PR_SET_DUMPABLE=0", cnt);
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 12a — Rotating trampoline signatures
//
// AnoSDK scans memory for fixed ARM64 hook patterns.
// Dobby uses: LDR X17, #8 (0x58000051) + BR X17 (0xD61F0220)
// We already scrub to LDR X16 in Layer 4.
// Here we rotate through 6 equivalent register variants every 30s.
// AnoSDK's pattern database can never build a reliable signature.
//
// Instruction encoding:
//   LDR Xn, #8 = 0x58000040 | n
//   BR  Xn     = 0xD61F0000 | (n << 5)
// All X9–X17 are caller-saved and safe to use in trampolines.
// ═════════════════════════════════════════════════════════════════════════════

static const struct { uint32_t ldr; uint32_t br; } k_variants[] = {
    { 0x58000050u, 0xD61F0200u },  // LDR X16 + BR X16  (current Layer 4)
    { 0x5800004Fu, 0xD61F01E0u },  // LDR X15 + BR X15
    { 0x5800004Eu, 0xD61F01C0u },  // LDR X14 + BR X14
    { 0x5800004Du, 0xD61F01A0u },  // LDR X13 + BR X13
    { 0x5800004Cu, 0xD61F0180u },  // LDR X12 + BR X12
    { 0x5800004Bu, 0xD61F0160u },  // LDR X11 + BR X11
    { 0x5800004Au, 0xD61F0140u },  // LDR X10 + BR X10
    { 0x58000049u, 0xD61F0120u },  // LDR X9  + BR X9
};
static constexpr int N_VARIANTS = (int)(sizeof(k_variants)/sizeof(k_variants[0]));
static std::atomic<int> g_var_idx{0};

// Rotate all registered trampoline signatures to a new register variant
static void rotate_trampolines() {
    int idx = (g_var_idx.fetch_add(1) + 1) % N_VARIANTS;
    const auto &v = k_variants[idx];

    const size_t ps = (size_t)getpagesize();

    // Scan all anonymous rwxp pages and rewrite the trampoline header
    // Use raw syscall to bypass Layer 2's hook_openat filter (which hides our
    // trampoline pages from regular fopen callers, making rotation never fire)
    int raw_fd = (int)syscall(__NR_openat, AT_FDCWD, "/proc/self/maps",
                              O_RDONLY | O_CLOEXEC, 0);
    if (raw_fd < 0) return;
    FILE *f = fdopen(raw_fd, "r");
    if (!f) { close(raw_fd); return; }

    char line[256];
    int cnt = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, "rwxp")) continue;
        if (strchr(line, '/')) continue;
        uintptr_t s = 0, e = 0;
        if (sscanf(line, "%lx-%lx", &s, &e) != 2 || !s || e <= s) continue;

        uintptr_t pg = s & ~(ps - 1);
        mprotect((void*)pg, ps, PROT_READ | PROT_WRITE | PROT_EXEC);

        uint8_t *p = (uint8_t*)s;
        // Each trampoline page starts with the 8-byte LDR+BR header
        // Verify the existing header matches ANY known variant (safety check)
        uint32_t cur_ldr; memcpy(&cur_ldr, p, 4);
        bool is_tramp = false;
        for (int i = 0; i < N_VARIANTS; i++) {
            if (cur_ldr == k_variants[i].ldr) { is_tramp = true; break; }
        }
        // Also check original Dobby X17 variant
        if (cur_ldr == 0x58000051u) is_tramp = true;

        if (is_tramp) {
            memcpy(p,     &v.ldr, 4);
            memcpy(p + 4, &v.br,  4);
            __builtin___clear_cache((char*)p, (char*)p + 8);
            cnt++;
        }
    }
    fclose(f);
    if (cnt) LI("L12 trampoline rotation → variant %d (%d pages)", idx, cnt);
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 12b — Hook integrity watchdog
//
// Background thread: every 5s re-checks that our critical AnoSDK hooks are
// still in place (AnoSDK tries to un-hook itself by writing original bytes
// back). If any hook byte pattern is wrong we re-apply via DobbyHook.
// Every 30s we also rotate trampoline signatures (Layer 12a).
// ═════════════════════════════════════════════════════════════════════════════

struct WdEntry { void *addr; void *hook; };
static WdEntry   g_wd[32];
static int       g_wd_n = 0;
static pthread_mutex_t g_wd_mu = PTHREAD_MUTEX_INITIALIZER;

void stx_watchdog_register(void *addr, void *hook) {
    pthread_mutex_lock(&g_wd_mu);
    if (g_wd_n < 32) g_wd[g_wd_n++] = { addr, hook };
    pthread_mutex_unlock(&g_wd_mu);
}

static std::atomic<bool> g_watchdog_run{false};

static void *watchdog_fn(void*) {
    // Disguise this thread as a kernel worker — hides from AnoSDK ps -T scan
    prctl(PR_SET_NAME, "kworker/0:2H", 0, 0, 0);
    int ticks = 0;
    while (g_watchdog_run.load()) {
        sleep(5);
        ticks++;

        // Re-apply MADV_DONTDUMP on any new anonymous rwxp pages
        // Also register them with stx2 so mincore spoof stays accurate
        {
            // Use raw syscall to bypass Layer 2 proc hider — we need to see
            // ALL anonymous rwxp pages, not just the unfiltered subset
            int fd = (int)syscall(__NR_openat, AT_FDCWD,
                                  "/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
            if (fd >= 0) {
                char buf[4096]; char line[256]; int ll = 0;
                ssize_t n;
                while ((n = read(fd, buf, sizeof(buf))) > 0) {
                    for (ssize_t i = 0; i < n; i++) {
                        char c = buf[i];
                        if (c != '\n' && ll < (int)sizeof(line)-1) { line[ll++]=c; continue; }
                        line[ll] = '\0'; ll = 0;
                        if (!strstr(line, "rwxp") || strchr(line, '/')) continue;
                        uintptr_t s = 0, e = 0;
                        if (sscanf(line, "%lx-%lx", &s, &e) == 2 && s && e > s) {
                            madvise((void*)s, e - s, MADV_DONTDUMP);
                            stx2_register_rwx((void*)s, e - s);
                        }
                    }
                }
                close(fd);
            }
        }

        // Re-check hook integrity
        pthread_mutex_lock(&g_wd_mu);
        for (int i = 0; i < g_wd_n; i++) {
            void *p = g_wd[i].addr;
            if (!p) continue;
            uint32_t insn; memcpy(&insn, p, 4);
            // Check if the first instruction is still one of our hook headers
            bool ok = false;
            for (int j = 0; j < N_VARIANTS; j++)
                if (insn == k_variants[j].ldr) { ok = true; break; }
            if (!ok) {
                DobbyDestroy(p);
                DobbyHook(p, g_wd[i].hook, nullptr);
            }
        }
        pthread_mutex_unlock(&g_wd_mu);

        // Every 30s (6 ticks × 5s) rotate trampoline signatures
        if (ticks % 6 == 0) rotate_trampolines();
    }
    return nullptr;
}

static void start_watchdog() {
    g_watchdog_run.store(true);
    pthread_t t;
    pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    pthread_create(&t, &a, watchdog_fn, nullptr);
    pthread_attr_destroy(&a);
    LI("L12b hook watchdog started (5s integrity check, 30s signature rotation)");
}

// ═════════════════════════════════════════════════════════════════════════════
// Helper: hook a libc symbol
// ═════════════════════════════════════════════════════════════════════════════

static bool hk_libc(void *libc, const char *sym, void *rep, void **orig) {
    void *a = dlsym(libc, sym);
    if (!a) return false;
    if (DobbyHook(a, rep, orig) == 0) {
        LI("hooked libc::%s", sym);
        return true;
    }
    return false;
}

// ═════════════════════════════════════════════════════════════════════════════
// Public entry point
// ═════════════════════════════════════════════════════════════════════════════

void install_stealth_ext() {
    // Resolve libc and libanogs handles
    OBF_DECODE(libc_name, "libc.so");
    OBF_DECODE(ano_name,  "libanogs.so");

    void *libc = dlopen(libc_name, RTLD_LAZY | RTLD_NOLOAD);
    if (!libc) libc = dlopen(libc_name, RTLD_LAZY);

    void *ano = dlopen(ano_name, RTLD_LAZY | RTLD_NOLOAD);

    // Resolve libanogs base address synchronously — needed for GOT patching
    // Must happen before L7a hooks dl_iterate_phdr
    dl_iterate_phdr(phdr_find_anogs_stx, nullptr);
    uintptr_t ano_base = s_stx_ano_base;
    uintptr_t ano_end  = s_stx_ano_end;
    if (ano_base) LI("libanogs base: 0x%lx end: 0x%lx", (unsigned long)ano_base, (unsigned long)ano_end);
    else          LE("libanogs base NOT found — GOT patching unavailable");

    // Install SIGSEGV suppressor BEFORE libanogs's background threads start scanning
    // (libanogs's crash trap fires a SIGSEGV at its own base+0x502000)
    LI("installing SIGSEGV suppressor...");
    if (ano_base) install_sigsegv_suppressor(ano_base, ano_end);


    // ── Layer 7a — dl_iterate_phdr ──────────────────────────────────────────
    // dl_iterate_phdr IS in libanogs's import (RELA[208], GOT 0x50fc28).
    // DobbyHook on bionic silently fails (non-hookable region); patch GOT instead.
    // Bionic hook attempted as fallback to cover other callers (e.g. libil2cpp).
    g_orig_iter_phdr = (FnIterPhdr)dlsym(libc, "dl_iterate_phdr");
    if (!g_orig_iter_phdr) g_orig_iter_phdr = (FnIterPhdr)dlsym(RTLD_DEFAULT, "dl_iterate_phdr");
    if (libc && !s_stx_ano_base) // only attempt bionic hook if GOT patch unavailable
        hk_libc(libc, "dl_iterate_phdr", (void*)hook_dl_iterate_phdr, (void**)&g_orig_iter_phdr);
    // GOT patch is done in L10 block below alongside other GOT patches

    // ── Layer 7b — dlopen ──────────────────────────────────────────────────
    // dlopen IS in libanogs imports — use GOT patch to avoid bionic body trampoline
    g_orig_dlopen = (FnDlopen)dlsym(libc, "dlopen");
    if (ano_base && g_orig_dlopen) {
        anogs_patch_got_import(ano_base, "dlopen", (void*)hook_dlopen);
        LI("L7b dlopen interceptor installed (GOT)");
    } else if (libc) {
        hk_libc(libc, "dlopen", (void*)hook_dlopen, (void**)&g_orig_dlopen);
        LI("L7b dlopen interceptor installed (DobbyHook fallback)");
    }

    // ── Layer 7c — AnoSDK missing exports ──────────────────────────────────
    if (ano) install_ano_missing(ano, ano_name);

    // ── Layer 8 — /proc/self/fd spoofing ───────────────────────────────────
    // opendir/closedir/readdir/readlink NOT in libanogs imports; DobbyHook safe
    for (int i = 0; i < MAX_FD_DIRS; i++) g_fd_dirs[i].store(0);
    if (libc) {
        hk_libc(libc, "opendir",  (void*)hook_opendir,  (void**)&g_orig_opendir);
        hk_libc(libc, "closedir", (void*)hook_closedir, (void**)&g_orig_closedir);
        hk_libc(libc, "readdir",  (void*)hook_readdir,  (void**)&g_orig_readdir);
        hk_libc(libc, "readlink", (void*)hook_readlink, (void**)&g_orig_readlink);
        LI("L8 /proc/self/fd spoof installed");
    }

    // ── Layer 9 — inotify nullifier ─────────────────────────────────────────
    // inotify_init + inotify_add_watch ARE in libanogs imports.
    // DobbyHook on bionic puts trampolines in their bodies which libanogs's
    // inline_hook_opcode_dismatch scanner detects immediately → process kill.
    // GOT patch redirects only libanogs's calls; bionic bodies stay pristine.
    g_orig_inotify_init = (FnInotifyInit)dlsym(libc, "inotify_init");
    g_orig_inotify_add  = (FnInotifyAddWatch)dlsym(libc, "inotify_add_watch");
    if (ano_base) {
        anogs_patch_got_import(ano_base, "inotify_init",     (void*)hook_inotify_init);
        anogs_patch_got_import(ano_base, "inotify_add_watch",(void*)hook_inotify_add);
        LI("L9 inotify nullifier installed (GOT — no bionic trampoline)");
    } else if (libc) {
        hk_libc(libc, "inotify_init",     (void*)hook_inotify_init, (void**)&g_orig_inotify_init);
        hk_libc(libc, "inotify_add_watch",(void*)hook_inotify_add,  (void**)&g_orig_inotify_add);
        LI("L9 inotify nullifier installed (DobbyHook fallback — may trip scanner)");
    }

    // ── Layer 10 — popen gate + access filter ───────────────────────────────
    // mprotect intentionally NOT hooked: libanogs must be able to call
    // mprotect(PROT_NONE) on its own pages to set up crash-trap pages.
    // Without crash-traps, the scanner falls back to direct tgkill SVC
    // which bypasses our GOT kill stub → process dies. Let PROT_NONE go
    // through; our SIGSEGV handler catches the trap and re-executes.
    g_orig_popen    = (FnPopen)dlsym(libc, "popen");
    g_orig_access   = (FnAccess)dlsym(libc, "access");
    g_orig_mprotect = (FnMprotect)dlsym(libc, "mprotect");
    g_orig_fork     = (FnFork)dlsym(libc, "fork");
    g_orig_ptrace   = (FnPtrace)dlsym(libc, "ptrace");
    g_orig__exit    = (FnExit)dlsym(libc, "_exit");
    g_orig_abort    = (FnAbort)dlsym(libc, "abort");
    if (ano_base) {
        anogs_patch_got_import(ano_base, "popen",           (void*)hook_popen);
        anogs_patch_got_import(ano_base, "access",          (void*)hook_access);
        // fork: blocks fork-child path (CBZ W0 → 0x2586e8); byte==0 path still runs
        anogs_patch_got_import(ano_base, "fork",            (void*)hook_fork);
        // ptrace: PTRACE_TRACEME loop (0x258b10, 17 callers) always returns 0
        anogs_patch_got_import(ano_base, "ptrace",          (void*)hook_ptrace);
        // _exit/abort: final failsafe at 0x258700 — blocks process termination
        anogs_patch_got_import(ano_base, "_exit",           (void*)hook__exit);
        anogs_patch_got_import(ano_base, "abort",           (void*)hook_abort);
        // dl_iterate_phdr: bionic DobbyHook fails; must go through libanogs GOT
        // caller at 0x4fdaf4 scans all loaded ELFs for injected libs
        anogs_patch_got_import(ano_base, "dl_iterate_phdr", (void*)hook_dl_iterate_phdr);
        LI("L10 popen/access/fork/ptrace/_exit/abort/dl_iterate_phdr installed (GOT)");
    } else if (libc) {
        hk_libc(libc, "popen",  (void*)hook_popen,  (void**)&g_orig_popen);
        hk_libc(libc, "access", (void*)hook_access, (void**)&g_orig_access);
        hk_libc(libc, "fork",   (void*)hook_fork,   (void**)&g_orig_fork);
        hk_libc(libc, "ptrace", (void*)hook_ptrace, (void**)&g_orig_ptrace);
        LI("L10 popen/access/fork/ptrace installed (DobbyHook fallback — may trip scanner)");
    }

    // ── Layer 11 — MADV_DONTDUMP + prctl ────────────────────────────────────
    install_anti_dump();

    // ── Layer 12 — watchdog + trampoline rotation ───────────────────────────
    start_watchdog();

    LI("stealth_ext: Layers 7–12 active (6 extra layers beyond ZOLAM)");
}
