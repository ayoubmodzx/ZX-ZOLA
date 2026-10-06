/*
 * stealth_ext2.cpp — Layers 13–17: Post-binary-analysis hardening
 *
 * New threats discovered from deep analysis of libanogs.so + libanort.so:
 *
 *  1. tp_syscall_imp (libanort.so@0x146940) — ARM64 raw SVC wrapper.
 *     Calls syscall(nr, ...) via inline SVC instruction — bypasses ALL
 *     libc hooks: our inotify, ptrace, mprotect hooks are invisible to it.
 *
 *  2. fork() + waitpid() — AnoSDK spawns a child process.
 *     Child inherits the address space but NOT our hook pointers.
 *     Child reads /proc/<parent_pid>/maps, /proc/<parent_pid>/mem from
 *     outside — our in-process hooks can't intercept it.
 *
 *  3. mincore() — detects hook pages by residency pattern.
 *     RX page that became RWX (our Dobby hook) has a changed mincore
 *     residency vector. AnoSDK looks for anonymous RWX pages.
 *
 *  4. kill() / tgkill() — AnoSDK calls kill(own_pid, SIGKILL) as
 *     a self-destruct on detection. We block it so the game stays alive
 *     even if AnoSDK is convinced it caught us.
 *
 *  5. socket(AF_INET, ...) + connect(127.0.0.1) — AnoSDK reports to a
 *     local Tencent daemon. We block outbound localhost connections from
 *     the AnoSDK thread so reports never reach the daemon.
 *
 *  6. __system_property_get — reads ro.debuggable, ro.build.type,
 *     ro.secure to detect dev/eng builds and debug mode.
 *     We intercept and return hardened production values.
 *
 * Layer 13: tp_syscall_imp hook — intercept raw SVC calls by nr
 * Layer 14: fork() nullifier — child scanner prevented from spawning
 * Layer 15: mincore() spoof — return resident=1 for all our RWX pages
 * Layer 16: kill() + tgkill() gate — block SIGKILL/SIGABRT self-destruct
 * Layer 17: socket/connect gate + system_property spoof
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
#include <sys/syscall.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cerrno>
#include <atomic>

#define TAG "ZX-STX2"
#define LI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

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
#ifndef __NR_openat
#define __NR_openat              56
#endif
#ifndef __NR_kill
#define __NR_kill                129
#endif
#ifndef __NR_tgkill
#define __NR_tgkill              131
#endif
#ifndef __NR_tkill
#define __NR_tkill               130
#endif
#ifndef __NR_process_vm_readv
#define __NR_process_vm_readv    270
#endif
#ifndef __NR_process_vm_writev
#define __NR_process_vm_writev   271
#endif
#ifndef __NR_mincore
#define __NR_mincore             232
#endif

// XOR obfuscation (same key as anti_detect.cpp)
static constexpr uint8_t XK = 0x5Au;
template<size_t N>
struct Obf2 {
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

// ═════════════════════════════════════════════════════════════════════════════
// Layer 13 — tp_syscall_imp raw SVC hook
//
// libanort.so exports tp_syscall_imp — an ARM64 SVC wrapper that directly
// issues syscalls without going through libc. Our libc hooks on inotify,
// ptrace, kill etc. are completely bypassed by it.
//
// We hook tp_syscall_imp itself and filter dangerous syscall numbers.
// The function signature: long tp_syscall_imp(long nr, ...)
// ═════════════════════════════════════════════════════════════════════════════

using FnTpSyscall = long(*)(long nr, long a1, long a2, long a3, long a4, long a5, long a6);
static FnTpSyscall g_orig_tp_syscall = nullptr;

static long hook_tp_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6) {
    // Block ptrace (117) — AnoSDK tries to ptrace itself and child
    if (nr == __NR_ptrace) {
        LI("L13 blocked tp_syscall ptrace");
        errno = EPERM;
        return -1;
    }
    // Block inotify_init (294) / inotify_init1 (26)
    if (nr == __NR_inotify_init || nr == __NR_inotify_init1) {
        errno = EPERM; return -1;
    }
    // Block inotify_add_watch (27)
    if (nr == __NR_inotify_add_watch) {
        errno = EPERM; return -1;
    }
    // Block SIGKILL/SIGABRT via kill() (129)
    if (nr == __NR_kill || nr == __NR_tkill) {
        int sig = (int)a2;
        if (sig == SIGKILL || sig == SIGABRT || sig == SIGTERM) {
            LI("L13 blocked tp_syscall kill(sig=%d)", sig);
            return 0;
        }
    }
    // Block tgkill (131) with lethal signals
    if (nr == __NR_tgkill) {
        int sig = (int)a3;
        if (sig == SIGKILL || sig == SIGABRT || sig == SIGTERM) {
            LI("L13 blocked tp_syscall tgkill(sig=%d)", sig);
            return 0;
        }
    }
    // Block process_vm_readv (270) — reads another process's memory
    if (nr == __NR_process_vm_readv) {
        errno = EPERM; return -1;
    }
    // Block mincore (232) — hand off to our spoof (L15)
    if (nr == __NR_mincore) {
        // Fill the vec with 0x01 (all resident) — page looks normal
        uint8_t *vec = (uint8_t*)a3;
        size_t  len  = (size_t)a2;
        size_t  pages = (len + 4095) / 4096;
        if (vec) memset(vec, 0x01, pages);
        return 0;
    }

    if (!g_orig_tp_syscall) return -1;
    return g_orig_tp_syscall(nr, a1, a2, a3, a4, a5, a6);
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 14 — fork() nullifier
//
// AnoSDK calls fork() to spawn a child process that scans the parent from
// outside (reads /proc/<parent>/maps and /proc/<parent>/mem without hooks).
// We make fork() return -1 so the child scanner never spawns.
//
// Risk: fork() is also used by legitimate app code. We only block it when
// called from within libanogs.so / libanort.so address ranges.
// ═════════════════════════════════════════════════════════════════════════════

using FnFork = pid_t(*)();
static FnFork g_orig_fork = nullptr;

struct LibRange { uintptr_t lo; uintptr_t hi; };
static LibRange g_ano_range{};
static LibRange g_anort_range{};

static void populate_lib_range(const char *libname, LibRange &out) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, libname)) continue;
        uintptr_t s = 0, e = 0;
        if (sscanf(line, "%lx-%lx", &s, &e) == 2) {
            if (!out.lo || s < out.lo) out.lo = s;
            if (e > out.hi) out.hi = e;
        }
    }
    fclose(f);
}

static bool caller_in_ano(uintptr_t ra) {
    return (g_ano_range.lo  && ra >= g_ano_range.lo  && ra < g_ano_range.hi) ||
           (g_anort_range.lo && ra >= g_anort_range.lo && ra < g_anort_range.hi);
}

static pid_t hook_fork() {
    uintptr_t ra = (uintptr_t)__builtin_return_address(0);
    if (caller_in_ano(ra)) {
        LI("L14 blocked fork() from AnoSDK (ra=%p)", (void*)ra);
        errno = EPERM;
        return -1;
    }
    return g_orig_fork ? g_orig_fork() : (pid_t)-1;
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 15 — mincore() spoof
//
// AnoSDK calls mincore() to check page residency. An anonymous RWX page
// that we use for trampolines has a different residency pattern than the
// original read-execute code page. We return "all resident" for our pages.
// ═════════════════════════════════════════════════════════════════════════════

using FnMincore = int(*)(void*, size_t, unsigned char*);
static FnMincore g_orig_mincore = nullptr;

static int hook_mincore(void *addr, size_t length, unsigned char *vec) {
    if (!g_orig_mincore) return -1;
    int r = g_orig_mincore(addr, length, vec);
    if (r == 0 && vec) {
        // Check if this range overlaps any of our anonymous rwxp pages
        uintptr_t q_s = (uintptr_t)addr;
        uintptr_t q_e = q_s + length;
        FILE *f = fopen("/proc/self/maps", "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (!strstr(line, "rwxp")) continue;
                if (strchr(line, '/')) continue; // skip named mappings
                uintptr_t s = 0, e = 0;
                if (sscanf(line, "%lx-%lx", &s, &e) != 2) continue;
                // Overlap check
                if (e <= q_s || s >= q_e) continue;
                // Mark all pages in overlap as resident (0x01)
                uintptr_t os = (s > q_s ? s : q_s);
                uintptr_t oe = (e < q_e ? e : q_e);
                size_t page_off = (os - q_s) / 4096;
                size_t page_cnt = (oe - os + 4095) / 4096;
                memset(vec + page_off, 0x01, page_cnt);
            }
            fclose(f);
        }
    }
    return r;
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 16 — kill() + tgkill() gate
//
// AnoSDK calls kill(getpid(), SIGKILL) or tgkill() as a self-destruct
// mechanism when it detects tampering. We intercept and block lethal signals
// directed at our own process. Non-lethal signals pass through unchanged.
// ═════════════════════════════════════════════════════════════════════════════

using FnKill   = int(*)(pid_t, int);
using FnTgkill = int(*)(pid_t, pid_t, int);
static FnKill   g_orig_kill   = nullptr;
static FnTgkill g_orig_tgkill = nullptr;

static inline bool is_lethal(int sig) {
    return sig == SIGKILL || sig == SIGABRT || sig == SIGTERM || sig == SIGSEGV;
}

static int hook_kill(pid_t pid, int sig) {
    if (is_lethal(sig) && (pid == getpid() || pid == 0 || pid == -1)) {
        LI("L16 blocked kill(pid=%d, sig=%d)", (int)pid, sig);
        return 0;
    }
    return g_orig_kill ? g_orig_kill(pid, sig) : -1;
}

static int hook_tgkill(pid_t tgid, pid_t tid, int sig) {
    if (is_lethal(sig) && (tgid == getpid() || tid == gettid())) {
        LI("L16 blocked tgkill(tgid=%d, tid=%d, sig=%d)", (int)tgid, (int)tid, sig);
        return 0;
    }
    return g_orig_tgkill ? g_orig_tgkill(tgid, tid, sig) : -1;
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 17a — socket/connect gate
//
// AnoSDK opens a TCP connection to 127.0.0.1 (local Tencent daemon) to
// report detection results. We block connect() calls targeting localhost.
// ═════════════════════════════════════════════════════════════════════════════

using FnConnect = int(*)(int, const struct sockaddr*, socklen_t);
static FnConnect g_orig_connect = nullptr;

static int hook_connect(int fd, const struct sockaddr *addr, socklen_t addrlen) {
    if (addr && addr->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in*)addr;
        uint32_t ip = ntohl(sin->sin_addr.s_addr);
        // Block 127.x.x.x — local Tencent daemon
        if ((ip >> 24) == 127) {
            LI("L17 blocked connect(127.x.x.x:%d)", ntohs(sin->sin_port));
            errno = ECONNREFUSED;
            return -1;
        }
    }
    // Block AF_UNIX connections to AnoSDK socket paths
    if (addr && addr->sa_family == AF_UNIX) {
        const char *path = addr->sa_data;
        if (strstr(path, "ano") || strstr(path, "tencent") || strstr(path, "tp_")) {
            LI("L17 blocked AF_UNIX connect: %s", path);
            errno = ECONNREFUSED;
            return -1;
        }
    }
    return g_orig_connect ? g_orig_connect(fd, addr, addrlen) : -1;
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 17b — __system_property_get spoof
//
// AnoSDK reads system properties to detect dev/debug builds:
//   ro.debuggable     → should be "0" on production
//   ro.build.type     → should be "user" not "eng"/"userdebug"
//   ro.secure         → should be "1"
//   ro.build.tags     → should be "release-keys"
// On rooted devices these often have dev values — we spoof them.
// ═════════════════════════════════════════════════════════════════════════════

using FnSysPropGet = int(*)(const char*, char*);
static FnSysPropGet g_orig_prop_get = nullptr;

static int hook_system_property_get(const char *name, char *value) {
    if (!name || !value) return 0;

    // Harden security-sensitive properties
    if (strcmp(name, "ro.debuggable") == 0) {
        strcpy(value, "0"); return 1;
    }
    if (strcmp(name, "ro.build.type") == 0) {
        strcpy(value, "user"); return 4;
    }
    if (strcmp(name, "ro.secure") == 0) {
        strcpy(value, "1"); return 1;
    }
    if (strcmp(name, "ro.build.tags") == 0) {
        strcpy(value, "release-keys"); return 12;
    }
    if (strcmp(name, "ro.kernel.qemu") == 0) {
        strcpy(value, "0"); return 1;
    }
    if (strcmp(name, "ro.build.fingerprint") != 0 && strstr(name, "debug")) {
        strcpy(value, "0"); return 1;
    }

    return g_orig_prop_get ? g_orig_prop_get(name, value) : 0;
}

// ═════════════════════════════════════════════════════════════════════════════
// Thread name masking — watchdog + our threads appear as kernel workers
// Prevents AnoSDK's "ps -T" scan from finding our threads by name
// ═════════════════════════════════════════════════════════════════════════════

void stx2_mask_thread_name() {
    prctl(PR_SET_NAME, "kworker/0:1H", 0, 0, 0);
}

// ═════════════════════════════════════════════════════════════════════════════
// Helper
// ═════════════════════════════════════════════════════════════════════════════

static bool hk2(void *lib, const char *sym, void *rep, void **orig) {
    void *a = dlsym(lib, sym);
    if (!a) return false;
    if (DobbyHook(a, rep, orig) == 0) {
        LI("L2-hooked %s", sym);
        return true;
    }
    return false;
}

// ═════════════════════════════════════════════════════════════════════════════
// Public install
// ═════════════════════════════════════════════════════════════════════════════

void install_stealth_ext2() {
    OBF2(libc_s,  "libc.so");
    OBF2(anort_s, "libanort.so");
    OBF2(ano_s,   "libanogs.so");

    void *libc  = dlopen(libc_s,  RTLD_LAZY | RTLD_NOLOAD);
    if (!libc)   libc = dlopen(libc_s, RTLD_LAZY);
    void *anort = dlopen(anort_s, RTLD_LAZY | RTLD_NOLOAD);

    // ── Layer 13 — tp_syscall_imp (libanort direct SVC) ─────────────────────
    if (anort) {
        void *tp = dlsym(anort, "tp_syscall_imp");
        if (tp) {
            if (DobbyHook(tp, (void*)hook_tp_syscall, (void**)&g_orig_tp_syscall) == 0)
                LI("L13 tp_syscall_imp hooked @ %p", tp);
            else
                LE("L13 tp_syscall_imp hook FAILED");
        } else {
            // Fallback: scan libanort's .text for the SVC pattern
            // SVC 0 = 0xD4000001 — find it and hook the wrapper
            LE("L13 tp_syscall_imp not found by dlsym — scan fallback not impl");
        }
    } else {
        LE("L13 libanort.so not loaded");
    }

    // ── Layer 14 — fork() nullifier ─────────────────────────────────────────
    // Populate AnoSDK address ranges first
    populate_lib_range(ano_s,   g_ano_range);
    populate_lib_range(anort_s, g_anort_range);
    if (libc) hk2(libc, "fork", (void*)hook_fork, (void**)&g_orig_fork);
    LI("L14 fork gate: ano=[%p-%p] anort=[%p-%p]",
        (void*)g_ano_range.lo, (void*)g_ano_range.hi,
        (void*)g_anort_range.lo, (void*)g_anort_range.hi);

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

    // Mask this thread name
    stx2_mask_thread_name();

    LI("stealth_ext2: Layers 13-17 active (5 layers: tp_syscall+fork+mincore+kill+net)");
}
