/*
 * stealth_ext2.cpp — Layers 13–17: Post-binary-analysis hardening
 *
 * Binary analysis of libanogs.so + libanort.so revealed:
 *  1. tp_syscall_imp (libanort.so@0x146940) — ARM64 raw SVC wrapper bypasses ALL libc hooks
 *  2. fork()+waitpid() — child process reads /proc/<ppid>/maps from outside
 *  3. mincore() — detects RWX trampoline pages by residency
 *  4. kill()/tgkill() — SIGKILL self-destruct on detection
 *  5. connect(127.0.0.1) — reports to local Tencent daemon
 *  6. __system_property_get — detects ro.debuggable / ro.build.type
 */

#include "stealth_ext2.hpp"
#include "dobby_stub.hpp"
#include "anti_detect.hpp"
#include <android/log.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cerrno>
#include <atomic>
#include <link.h>

#define TAG "ZX-STX2"
#ifndef ZX_RELEASE
#define LI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#else
#define LI(...) ((void)0)
#define LE(...) ((void)0)
#endif

// ARM64 syscall numbers
#ifndef __NR_ptrace
#define __NR_ptrace              117
#endif
#ifndef __NR_inotify_init
#define __NR_inotify_init        294
#endif
#ifndef __NR_inotify_init1
#define __NR_inotify_init1       26
#endif
#ifndef __NR_inotify_add_watch
#define __NR_inotify_add_watch   27
#endif
#ifndef __NR_kill
#define __NR_kill                129
#endif
#ifndef __NR_tkill
#define __NR_tkill               130
#endif
#ifndef __NR_tgkill
#define __NR_tgkill              131
#endif
#ifndef __NR_process_vm_readv
#define __NR_process_vm_readv    270
#endif
#ifndef __NR_mincore
#define __NR_mincore             232
#endif

// XOR obfuscation (same key as anti_detect.cpp / stealth_ext.cpp)
static constexpr uint8_t XK = 0x5Au;
template<size_t N> struct Obf2 {
    char data[N]{};
    constexpr explicit Obf2(const char (&s)[N]) {
        for (size_t i = 0; i < N; i++) data[i] = (char)(s[i] ^ XK);
    }
    void decode(char (&out)[N]) const {
        for (size_t i = 0; i < N; i++) out[i] = (char)(data[i] ^ XK);
    }
};
#define OBF2(var, lit) \
    char var[sizeof(lit)]; \
    do { static constexpr Obf2<sizeof(lit)> _o(lit); _o.decode(var); } while(0)

// ─────────────────────────────────────────────────────────────────────────────
// RWX page registry — populated by dobby_impl.cpp via zx_track_rwx_page()
// Used by mincore spoof + rotation WITHOUT reading /proc/self/maps
// ─────────────────────────────────────────────────────────────────────────────

static constexpr int MAX_RWX = 64;
struct RwxEntry { uintptr_t base; size_t size; };
static RwxEntry    g_rwx[MAX_RWX];
static int         g_rwx_n = 0;
static pthread_mutex_t g_rwx_mu = PTHREAD_MUTEX_INITIALIZER;

void stx2_register_rwx(void *p, size_t sz) {
    pthread_mutex_lock(&g_rwx_mu);
    if (g_rwx_n < MAX_RWX) g_rwx[g_rwx_n++] = { (uintptr_t)p, sz };
    pthread_mutex_unlock(&g_rwx_mu);
}

static bool rwx_contains(uintptr_t addr) {
    for (int i = 0; i < g_rwx_n; i++) {
        if (addr >= g_rwx[i].base && addr < g_rwx[i].base + g_rwx[i].size)
            return true;
    }
    return false;
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 13 — tp_syscall_imp raw SVC hook
//
// libanort.so tp_syscall_imp disassembly:
//   MOV X8, X0   ← syscall number
//   MOV X0, X1   ← arg1 … arg6
//   SVC #0
//   CMN X0, #1
//   RET
// Signature: long tp_syscall_imp(long nr, long a1..a6)
//
// Bug fix vs v1: tkill(130) sig is in a2 (3rd arg), not a2 position was
// wrongly compared against kill's a2. Now handled correctly per syscall ABI.
// ═════════════════════════════════════════════════════════════════════════════

using FnTpSyscall = long(*)(long, long, long, long, long, long, long);
static FnTpSyscall g_orig_tp_syscall = nullptr;

static inline bool is_lethal_sig(int s) {
    return s == SIGKILL || s == SIGABRT || s == SIGTERM;
}

static long hook_tp_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6) {
    switch ((int)nr) {
    // ptrace — block entirely
    case __NR_ptrace:
        errno = EPERM; return -1L;

    // inotify — nullify
    case __NR_inotify_init:
    case __NR_inotify_init1:
    case __NR_inotify_add_watch:
        errno = EPERM; return -1L;

    // kill(pid, sig) — a1=pid, a2=sig
    case __NR_kill:
        if (is_lethal_sig((int)a2) && ((pid_t)a1 == getpid() || (pid_t)a1 == 0))
            return 0L;
        break;

    // tkill(tid, sig) — a1=tid, a2=sig
    case __NR_tkill:
        if (is_lethal_sig((int)a2))
            return 0L;
        break;

    // tgkill(tgid, tid, sig) — a1=tgid, a2=tid, a3=sig
    case __NR_tgkill:
        if (is_lethal_sig((int)a3) && (pid_t)a1 == getpid())
            return 0L;
        break;

    // process_vm_readv — block external memory read
    case __NR_process_vm_readv:
        errno = EPERM; return -1L;

    // mincore(addr, len, vec) — a1=addr, a2=len, a3=vec
    // Return all-resident for our tracked RWX pages, passthrough rest
    case __NR_mincore: {
        uintptr_t q_s = (uintptr_t)a1;
        size_t    q_n = (size_t)a2;
        uint8_t  *vec = (uint8_t*)a3;
        if (!g_orig_tp_syscall) { errno = EFAULT; return -1L; }
        long r = g_orig_tp_syscall(nr, a1, a2, a3, a4, a5, a6);
        // Patch vec: mark any page in our RWX registry as resident
        if (r == 0 && vec) {
            size_t npages = (q_n + 4095) / 4096;
            pthread_mutex_lock(&g_rwx_mu);
            for (size_t pg = 0; pg < npages; pg++) {
                uintptr_t pa = q_s + pg * 4096;
                if (rwx_contains(pa)) vec[pg] = 0x01;
            }
            pthread_mutex_unlock(&g_rwx_mu);
        }
        return r;
    }

    default: break;
    }

    if (!g_orig_tp_syscall) return -1L;
    return g_orig_tp_syscall(nr, a1, a2, a3, a4, a5, a6);
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 14 — fork() nullifier
//
// Bug fix vs v1: ranges populated at install time may be empty if libanogs
// hasn't loaded yet (we install in __constructor, very early).
// Fix: lazy re-populate inside hook_fork using atomic flag + double-check.
// ═════════════════════════════════════════════════════════════════════════════

using FnFork = pid_t(*)();
static FnFork g_orig_fork = nullptr;

struct LibRange { uintptr_t lo; uintptr_t hi; };
static LibRange      g_ano_range{};
static LibRange      g_anort_range{};
static std::atomic<bool> g_ranges_ready{false};
static pthread_mutex_t   g_range_mu = PTHREAD_MUTEX_INITIALIZER;

// Reads /proc/self/maps via direct syscall to bypass our own proc hider
// (Layer 2 hooks open() at libc level; we use __NR_openat directly here)
static void populate_lib_range_direct(const char *libname, LibRange &out) {
    // Use raw syscall so Layer 2 proc hider doesn't filter this read
    int fd = (int)syscall(__NR_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return;

    char buf[4096];
    char line[512];
    int  line_len = 0;
    ssize_t n;

    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            char c = buf[i];
            if (c != '\n' && line_len < (int)sizeof(line) - 1) {
                line[line_len++] = c;
                continue;
            }
            line[line_len] = '\0';
            line_len = 0;
            if (!strstr(line, libname)) continue;
            uintptr_t s = 0, e = 0;
            if (sscanf(line, "%lx-%lx", &s, &e) == 2 && s && e > s) {
                if (!out.lo || s < out.lo) out.lo = s;
                if (e > out.hi) out.hi = e;
            }
        }
    }
    close(fd);
}

static void ensure_ranges() {
    if (g_ranges_ready.load(std::memory_order_acquire)) return;
    pthread_mutex_lock(&g_range_mu);
    if (!g_ranges_ready.load(std::memory_order_relaxed)) {
        OBF2(ano_s,   "libanogs.so");
        OBF2(anort_s, "libanort.so");
        populate_lib_range_direct(ano_s,   g_ano_range);
        populate_lib_range_direct(anort_s, g_anort_range);
        if (g_ano_range.lo || g_anort_range.lo)
            g_ranges_ready.store(true, std::memory_order_release);
    }
    pthread_mutex_unlock(&g_range_mu);
}

static bool caller_in_ano(uintptr_t ra) {
    return (g_ano_range.lo   && ra >= g_ano_range.lo   && ra < g_ano_range.hi) ||
           (g_anort_range.lo && ra >= g_anort_range.lo && ra < g_anort_range.hi);
}

// __attribute__((noinline)) prevents the compiler from inlining hook_fork,
// which would make __builtin_return_address(0) point into our own code
// instead of the AnoSDK caller's code.
__attribute__((noinline))
static pid_t hook_fork() {
    ensure_ranges();
    uintptr_t ra = (uintptr_t)__builtin_return_address(0);
    if (caller_in_ano(ra)) {
        errno = EPERM;
        return (pid_t)-1;
    }
    pid_t pid = g_orig_fork ? g_orig_fork() : (pid_t)-1;
    if (pid > 0) {
        extern void track_fork(pid_t);
        track_fork(pid);
    }
    return pid;
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 15 — mincore() libc hook (complements L13 tp_syscall path)
//
// Bug fix vs v1: v1 read /proc/self/maps which is filtered by Layer 2
// (our trampoline pages are stripped from the filtered view).
// Fix: use g_rwx registry (populated by dobby_impl via stx2_register_rwx)
// which contains exact page addresses — no /proc/maps reading needed.
// ═════════════════════════════════════════════════════════════════════════════

// libanogs.so load range — forward-declared so hook_mincore can reference them
static uintptr_t s_stx2_ano_base = 0;
static uintptr_t s_stx2_ano_end  = 0;

using FnMincore = int(*)(void*, size_t, unsigned char*);
static FnMincore g_orig_mincore = nullptr;

// Reentrancy guard — mincore hook must not call mincore itself
static thread_local bool g_in_mincore = false;

static int hook_mincore(void *addr, size_t length, unsigned char *vec) {
    if (g_in_mincore) return g_orig_mincore ? g_orig_mincore(addr, length, vec) : -1;
    g_in_mincore = true;

    int r = g_orig_mincore ? g_orig_mincore(addr, length, vec) : -1;

    if (r == 0 && vec && length > 0) {
        uintptr_t q_s = (uintptr_t)addr;
        size_t npages = (length + 4095) / 4096;
        pthread_mutex_lock(&g_rwx_mu);
        for (size_t pg = 0; pg < npages; pg++) {
            uintptr_t pa = q_s + pg * 4096;
            if (rwx_contains(pa)) vec[pg] = 0x01;
        }
        pthread_mutex_unlock(&g_rwx_mu);
    }

    // Layer 52 merged: if caller is libanogs, force ALL pages in-core
    if (s_stx2_ano_base) {
        uintptr_t lr15 = (uintptr_t)__builtin_return_address(0);
        if (lr15 >= s_stx2_ano_base && lr15 < s_stx2_ano_end && vec && length > 0) {
            size_t np = (length + 4095) / 4096;
            for (size_t pg = 0; pg < np; pg++)
                vec[pg] = 1;
        }
    }

    g_in_mincore = false;
    return r;
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 16 — kill() + tgkill() gate
//
// Bug fix vs v1: tkill(tid, sig) — sig is a2 (second arg), not a3.
// Fixed the per-syscall argument offsets to match Linux ABI exactly.
// ═════════════════════════════════════════════════════════════════════════════

using FnKill    = int(*)(pid_t, int);
using FnTgkill  = int(*)(pid_t, pid_t, int);
static FnKill   g_orig_kill   = nullptr;
static FnTgkill g_orig_tgkill = nullptr;

static int hook_kill(pid_t pid, int sig) {
    if (is_lethal_sig(sig) && (pid == getpid() || pid == 0 || pid == -1)) {
        LI("L16 blocked kill(%d, %d)", (int)pid, sig);
        return 0;
    }
    return g_orig_kill ? g_orig_kill(pid, sig) : -1;
}

static int hook_tgkill(pid_t tgid, pid_t tid, int sig) {
    if (is_lethal_sig(sig) && tgid == getpid()) {
        LI("L16 blocked tgkill(%d, %d, %d)", (int)tgid, (int)tid, sig);
        return 0;
    }
    return g_orig_tgkill ? g_orig_tgkill(tgid, tid, sig) : -1;
}

static int phdr_find_ano_stx2(struct dl_phdr_info *info, size_t, void*) {
    if (!info->dlpi_name || !strstr(info->dlpi_name, "libanogs.so")) return 0;
    uintptr_t base = (uintptr_t)info->dlpi_addr, end = base;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_LOAD) {
            uintptr_t se = base + info->dlpi_phdr[i].p_vaddr + info->dlpi_phdr[i].p_memsz;
            if (se > end) end = se;
        }
    }
    s_stx2_ano_base = base; s_stx2_ano_end = end; return 1;
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 17a — connect() gate
//
// Bug fix vs v1: AF_UNIX abstract sockets start with '\0' — strstr on
// sa_data[0] == '\0' finds nothing. Cast to sockaddr_un and skip abstract
// (sun_path[0] == 0) to avoid reading garbage bytes as a C string.
// ═════════════════════════════════════════════════════════════════════════════

using FnConnect = int(*)(int, const struct sockaddr*, socklen_t);
static FnConnect g_orig_connect = nullptr;

static int hook_connect(int fd, const struct sockaddr *addr, socklen_t addrlen) {
    uintptr_t lr17 = (uintptr_t)__builtin_return_address(0);
    if (s_stx2_ano_base && lr17 >= s_stx2_ano_base && lr17 < s_stx2_ano_end) {
        errno = ECONNREFUSED;
        return -1;
    }

    if (!addr) goto pass;

    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in*)addr;
        uint32_t ip = ntohl(sin->sin_addr.s_addr);
        if ((ip >> 24) == 127) {
            LI("L17 blocked connect(127.x:%d)", ntohs(sin->sin_port));
            errno = ECONNREFUSED;
            return -1;
        }
    } else if (addr->sa_family == AF_UNIX && addrlen >= sizeof(sa_family_t) + 2) {
        const struct sockaddr_un *sun = (const struct sockaddr_un*)addr;
        // Skip abstract sockets (sun_path[0]=='\0') — path is in [1..107]
        const char *path = sun->sun_path;
        if (path[0] != '\0' &&
            (strstr(path, "ano") || strstr(path, "tencent") || strstr(path, "tp_"))) {
            LI("L17 blocked AF_UNIX: %s", path);
            errno = ECONNREFUSED;
            return -1;
        }
    }

pass:
    return g_orig_connect ? g_orig_connect(fd, addr, addrlen) : -1;
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 17b — __system_property_get spoof
// ═════════════════════════════════════════════════════════════════════════════

using FnSysPropGet = int(*)(const char*, char*);
static FnSysPropGet g_orig_prop_get = nullptr;

static int hook_system_property_get(const char *name, char *value) {
    if (!name || !value) return 0;
    // Harden build/security properties to look like locked production device
    if (strcmp(name, "ro.debuggable") == 0) { strcpy(value, "0");            return 1;  }
    if (strcmp(name, "ro.build.type") == 0)  { strcpy(value, "user");        return 4;  }
    if (strcmp(name, "ro.secure")     == 0)  { strcpy(value, "1");            return 1;  }
    if (strcmp(name, "ro.build.tags") == 0)  { strcpy(value, "release-keys"); return 12; }
    if (strcmp(name, "ro.kernel.qemu") == 0) { strcpy(value, "0");            return 1;  }
    if (strstr(name,  "debug") || strstr(name, "eng"))
        { strcpy(value, "0"); return 1; }
    return g_orig_prop_get ? g_orig_prop_get(name, value) : 0;
}

// ═════════════════════════════════════════════════════════════════════════════
// Thread name mask — hides ZX threads from AnoSDK's ps -T scan
// ═════════════════════════════════════════════════════════════════════════════

void stx2_mask_thread_name() {
    prctl(PR_SET_NAME, "kworker/0:1H", 0, 0, 0);
}

// ═════════════════════════════════════════════════════════════════════════════
// Helper: hook a symbol in a loaded library
// ═════════════════════════════════════════════════════════════════════════════

static bool hk2(void *lib, const char *sym, void *rep, void **orig) {
    void *a = dlsym(lib, sym);
    if (!a) return false;
    if (DobbyHook(a, rep, orig) == 0) { LI("hooked %s", sym); return true; }
    LE("hook FAILED: %s", sym);
    return false;
}

// ═════════════════════════════════════════════════════════════════════════════
// Public install
// ═════════════════════════════════════════════════════════════════════════════

void install_stealth_ext2() {
    OBF2(libc_s,  "libc.so");
    OBF2(anort_s, "libanort.so");

    void *libc  = dlopen(libc_s,  RTLD_LAZY | RTLD_NOLOAD);
    if (!libc)  libc = dlopen(libc_s, RTLD_LAZY);
    void *anort = dlopen(anort_s, RTLD_LAZY | RTLD_NOLOAD);

    // ── Layer 13 — tp_syscall_imp (libanort.so direct SVC) ──────────────────
    if (anort) {
        void *tp = dlsym(anort, "tp_syscall_imp");
        if (tp) {
            if (DobbyHook(tp, (void*)hook_tp_syscall, (void**)&g_orig_tp_syscall) == 0)
                LI("L13 tp_syscall_imp hooked @ %p", tp);
            else
                LE("L13 tp_syscall_imp hook FAILED");
        } else {
            LE("L13 tp_syscall_imp not found — libanort loaded? handle=%p", anort);
        }
    } else {
        LE("L13 libanort.so not loaded yet — tp_syscall_imp unprotected");
    }

    // ── Layer 14 — fork() gate (lazy range init on first call) ──────────────
    // Attempt initial populate — may be empty if libs not loaded yet
    // hook_fork() calls ensure_ranges() on each invocation as fallback
    {
        OBF2(ano_s2,   "libanogs.so");
        OBF2(anort_s2, "libanort.so");
        populate_lib_range_direct(ano_s2,   g_ano_range);
        populate_lib_range_direct(anort_s2, g_anort_range);
        if (g_ano_range.lo || g_anort_range.lo)
            g_ranges_ready.store(true, std::memory_order_release);
    }
    if (libc) hk2(libc, "fork", (void*)hook_fork, (void**)&g_orig_fork);
    LI("L14 fork gate active (ano=[%p-%p])",
        (void*)g_ano_range.lo, (void*)g_ano_range.hi);

    // ── Layer 15 — mincore() spoof ──────────────────────────────────────────
    if (libc) hk2(libc, "mincore", (void*)hook_mincore, (void**)&g_orig_mincore);

    // ── Layer 16 — kill() + tgkill() gate ───────────────────────────────────
    if (libc) {
        hk2(libc, "kill",   (void*)hook_kill,   (void**)&g_orig_kill);
        hk2(libc, "tgkill", (void*)hook_tgkill, (void**)&g_orig_tgkill);
    }

    // ── Layer 17a — connect() gate ──────────────────────────────────────────
    if (libc) hk2(libc, "connect", (void*)hook_connect, (void**)&g_orig_connect);

    // ── Layer 17b — __system_property_get spoof ─────────────────────────────
    if (libc) hk2(libc, "__system_property_get",
        (void*)hook_system_property_get, (void**)&g_orig_prop_get);

    // Populate libanogs range for caller-aware connect/mincore checks
    dl_iterate_phdr(phdr_find_ano_stx2, nullptr);
    if (s_stx2_ano_base)
        LI("L17a/L15 ano range: [%p-%p]", (void*)s_stx2_ano_base, (void*)s_stx2_ano_end);

    stx2_mask_thread_name();

    LI("stealth_ext2: Layers 13-17 active");
}
