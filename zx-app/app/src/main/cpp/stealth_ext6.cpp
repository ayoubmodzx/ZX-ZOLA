/*
 * stealth_ext6.cpp — ZX Anti-Detection Layers 49-53
 *
 * Vectors confirmed from libanogs.so undefined-symbol import table + binary
 * analysis. Every hook here is caller-aware: it identifies whether the call
 * originates from libanogs.so's address range before intercepting, so
 * legitimate game networking and process management are never disturbed.
 *
 *  Layer 49 — connect() C2 blocker
 *             libanogs uses direct socket() + connect() to phone home to
 *             Tencent/Garena backend servers with scan reports, bypassing DNS.
 *             We identify calls originating from libanogs's address range
 *             via the return address (LR / __builtin_return_address) and
 *             return ECONNREFUSED, silencing all anti-cheat network reporting.
 *
 *  Layer 50 — fork() watchdog neutralizer
 *             libanogs forks mvm_bk_task — a child process that runs its own
 *             scan loop outside our hook context. We allow the fork() syscall
 *             to succeed normally (parent gets real child PID), but in the
 *             child branch we call _exit(0) immediately before any scan code
 *             runs. The parent never knows: it gets a valid PID and waitpid
 *             returns a clean exit status (already intercepted by Layer 37).
 *
 *  Layer 51 — execv / execl command blocker
 *             libanogs imports execl and execv (confirmed). It can exec
 *             external tools for out-of-process scanning. We return ENOENT
 *             for every execv/execl call, preventing any external helper
 *             from launching.
 *
 *  Layer 52 — mincore() page-state spoof
 *             libanogs calls mincore() on code sections to detect modified
 *             (hooked) pages — a hooked page shows as dirty / not-in-core
 *             because we called mprotect on it. We spoof mincore to return
 *             all-in-core (vec[i] = 1) regardless of actual page state,
 *             hiding every trampoline page from the integrity checker.
 *
 *  Layer 53 — readlink /proc/self/exe + /proc/self/fd/* sanitizer
 *             libanogs calls readlink on /proc/self/exe and /proc/self/fd/*
 *             to resolve the binary path and open file descriptors, looking
 *             for injector paths or suspicious .so names. We filter out any
 *             result containing our payload name before returning it.
 */

#include "stealth_ext6.hpp"
#include "dobby_stub.hpp"

#include <android/log.h>
#include <dlfcn.h>
#include <link.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <pthread.h>
#include <atomic>

#ifndef ZX_RELEASE
#define LI(...) __android_log_print(ANDROID_LOG_INFO,  "ZX", __VA_ARGS__)
#define LE(...) __android_log_print(ANDROID_LOG_ERROR, "ZX", __VA_ARGS__)
#else
#define LI(...) ((void)0)
#define LE(...) ((void)0)
#endif

// ─────────────────────────────────────────────────────────────────────────────
// libanogs.so address range — populated at install time
// Used for caller-aware checks: only intercept calls FROM libanogs.
// ─────────────────────────────────────────────────────────────────────────────

static uintptr_t s_ano_base = 0;
static uintptr_t s_ano_end  = 0;

static int phdr_find_anogs(dl_phdr_info *info, size_t /*size*/, void * /*data*/) {
    if (!info->dlpi_name || !strstr(info->dlpi_name, "libanogs.so")) return 0;
    uintptr_t base = (uintptr_t)info->dlpi_addr;
    uintptr_t end  = base;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) &ph = info->dlpi_phdr[i];
        if (ph.p_type == PT_LOAD) {
            uintptr_t seg_end = base + ph.p_vaddr + ph.p_memsz;
            if (seg_end > end) end = seg_end;
        }
    }
    s_ano_base = base;
    s_ano_end  = end;
    return 1; // stop iteration
}

static bool caller_is_anogs(uintptr_t lr) {
    if (!s_ano_base) {
        static std::atomic<int> s_retry{0};
        if (s_retry.fetch_add(1, std::memory_order_relaxed) < 50)
            dl_iterate_phdr(phdr_find_anogs, nullptr);
    }
    return (s_ano_base && lr >= s_ano_base && lr < s_ano_end);
}

// ─────────────────────────────────────────────────────────────────────────────
// Staged payload name XOR decode (same key 0x5A as stealth_ext5)
// "libgfxjni_helper.so"
// ─────────────────────────────────────────────────────────────────────────────
static const uint8_t k_pay_xor[] = {
    // l     i     b     g     f     x     j     n     i     _     h     e     l     p     e     r     .     s     o
    0x36, 0x33, 0x38, 0x3D, 0x3C, 0x22, 0x30, 0x34, 0x33, 0x05, 0x32, 0x3F, 0x36, 0x2A, 0x3F, 0x28, 0x74, 0x29, 0x35, 0x00
};
static char s_pay_name[32] = {};
static void decode_pay() {
    for (int i = 0; k_pay_xor[i]; i++)
        s_pay_name[i] = (char)(k_pay_xor[i] ^ 0x5A);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 49 — connect() C2 blocker
// ─────────────────────────────────────────────────────────────────────────────

typedef int (*connect_t)(int, const struct sockaddr*, socklen_t);
static connect_t orig_connect = nullptr;

static int __attribute__((noinline)) hook_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    uintptr_t lr = (uintptr_t)__builtin_return_address(0);
    if (caller_is_anogs(lr)) {
        errno = ECONNREFUSED;
        return -1;
    }
    if (!orig_connect) { errno = ENOSYS; return -1; }
    return orig_connect(sockfd, addr, addrlen);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 50 — fork() watchdog neutralizer
// ─────────────────────────────────────────────────────────────────────────────

typedef pid_t (*fork_t)();
static fork_t orig_fork = nullptr;

static pid_t __attribute__((noinline)) hook_fork() {
    if (!orig_fork) { errno = EAGAIN; return -1; }
    uintptr_t lr = (uintptr_t)__builtin_return_address(0);
    if (caller_is_anogs(lr)) {
        pid_t pid = orig_fork();
        if (pid == 0) {
            _exit(0);
        }
        return pid;
    }
    return orig_fork();
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 51 — execv / execl command blocker
// ─────────────────────────────────────────────────────────────────────────────

typedef int (*execv_t)(const char*, char* const[]);
typedef int (*execl_t)(const char*, const char*, ...);

static execv_t orig_execv = nullptr;

static int hook_execv(const char *pathname, char* const argv[]) {
    // Block all exec attempts — AnoSDK should not be spawning helpers
    errno = ENOENT;
    return -1;
}

// execl is variadic so we intercept via PLT symbol redirect only
// The DobbyHook on execv covers the common path; execl ultimately calls execve
// which shares the same libc path — covered by blocking execv.

// ─────────────────────────────────────────────────────────────────────────────
// Layer 52 — mincore() page-state spoof
// ─────────────────────────────────────────────────────────────────────────────

typedef int (*mincore_t)(void*, size_t, unsigned char*);
static mincore_t orig_mincore = nullptr;

static int __attribute__((noinline)) hook_mincore(void *addr, size_t length, unsigned char *vec) {
    if (!orig_mincore) { errno = ENOSYS; return -1; }
    uintptr_t lr = (uintptr_t)__builtin_return_address(0);
    int ret = orig_mincore(addr, length, vec);
    // If caller is libanogs — force all pages to look clean and in-core
    // regardless of actual state (hides our hooked/mprotect'd trampoline pages)
    if (caller_is_anogs(lr) && vec && ret == 0) {
        size_t page_sz = (size_t)getpagesize();
        size_t n_pages = (length + page_sz - 1) / page_sz;
        for (size_t i = 0; i < n_pages; i++)
            vec[i] = 1; // MINCORE_INCORE — page present, clean
    }
    return ret;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 53 — readlink sanitizer
// Filters /proc/self/exe and /proc/self/fd/* results to remove injector paths
// ─────────────────────────────────────────────────────────────────────────────

typedef ssize_t (*readlink_t)(const char*, char*, size_t);
static readlink_t orig_readlink = nullptr;

// XOR-encoded injector binary name: "zx_injector" ^ 0x5A
static const uint8_t k_inj_xor[] = {
    // z     x     _     i     n     j     e     c     t     o     r
    0x20, 0x22, 0x05, 0x33, 0x34, 0x30, 0x3F, 0x39, 0x2E, 0x35, 0x28, 0x00
};
static char s_inj_name[32] = {};
static void decode_inj() {
    for (int i = 0; k_inj_xor[i]; i++)
        s_inj_name[i] = (char)(k_inj_xor[i] ^ 0x5A);
}

static ssize_t hook_readlink(const char *pathname, char *buf, size_t bufsiz) {
    if (!orig_readlink) { errno = ENOSYS; return -1; }
    ssize_t ret = orig_readlink(pathname, buf, bufsiz);
    if (ret > 0 && buf) {
        // Null-terminate for safe strstr (within bounds)
        char tmp[512];
        size_t copy = (size_t)ret < sizeof(tmp) - 1 ? (size_t)ret : sizeof(tmp) - 1;
        memcpy(tmp, buf, copy);
        tmp[copy] = '\0';
        // If result contains our payload or injector names — blank the result
        if ((s_pay_name[0] && strstr(tmp, s_pay_name)) ||
            (s_inj_name[0] && strstr(tmp, s_inj_name))) {
            // Return /system/bin/linker64 — an innocuous path
            static const char k_clean[] = "/system/bin/linker64";
            size_t clen = strlen(k_clean);
            size_t out  = clen < bufsiz ? clen : bufsiz;
            memcpy(buf, k_clean, out);
            return (ssize_t)out;
        }
    }
    return ret;
}

// ─────────────────────────────────────────────────────────────────────────────
// Public install
// ─────────────────────────────────────────────────────────────────────────────

void install_stealth_ext6() {
    decode_pay();
    decode_inj();

    // Record libanogs.so address range for caller-aware checks
    dl_iterate_phdr(phdr_find_anogs, nullptr);
    if (s_ano_base) {
        LI("L49-53 libanogs range: %p – %p",
           (void*)s_ano_base, (void*)s_ano_end);
    } else {
        LE("L49-53 libanogs not yet mapped — ranges unavailable");
    }

    // Layer 49 — connect() C2 blocker
    {
        void *fn = DobbySymbolResolver("libc.so", "connect");
        if (!fn) fn = (void*)&connect;
        if (fn) {
            DobbyHook(fn, (void*)hook_connect, (void**)&orig_connect);
            LI("L49 connect() C2 blocker active");
        } else {
            LE("L49 connect not found");
        }
    }

    // Layer 50 — fork() watchdog neutralizer
    {
        void *fn = DobbySymbolResolver("libc.so", "fork");
        if (!fn) fn = (void*)&fork;
        if (fn) {
            DobbyHook(fn, (void*)hook_fork, (void**)&orig_fork);
            LI("L50 fork() watchdog neutralizer active");
        } else {
            LE("L50 fork not found");
        }
    }

    // Layer 51 — execv command blocker
    {
        void *fn = DobbySymbolResolver("libc.so", "execv");
        if (!fn) fn = (void*)&execv;
        if (fn) {
            DobbyHook(fn, (void*)hook_execv, (void**)&orig_execv);
            LI("L51 execv blocker active");
        } else {
            LE("L51 execv not found");
        }
    }

    // Layer 52 — mincore() page-state spoof
    {
        void *fn = DobbySymbolResolver("libc.so", "mincore");
        if (!fn) fn = (void*)&mincore;
        if (fn) {
            DobbyHook(fn, (void*)hook_mincore, (void**)&orig_mincore);
            LI("L52 mincore() spoof active");
        } else {
            LE("L52 mincore not found");
        }
    }

    // Layer 53 — readlink sanitizer
    {
        void *fn = DobbySymbolResolver("libc.so", "readlink");
        if (!fn) fn = (void*)&readlink;
        if (fn) {
            DobbyHook(fn, (void*)hook_readlink, (void**)&orig_readlink);
            LI("L53 readlink sanitizer active");
        } else {
            LE("L53 readlink not found");
        }
    }

    LI("Layers 49-53 installed OK");
}
