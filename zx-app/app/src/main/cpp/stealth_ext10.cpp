/*
 * stealth_ext10.cpp — ZX Anti-Detection Layers 71-75
 *
 * Target: libanort.so — tertiary AnoSDK component
 *         Exports: tp_syscall_imp (direct-syscall bridge bypassing libc hooks),
 *                  unwind_xx_info_query / unwind_xx_ioctl (inline hook scanner).
 *         Imports: kill, access, prctl, ptrace, ptrace via tp_syscall_imp.
 *
 * Layer 71 — tp_syscall_imp ptrace neutralizer
 *            libanort.so calls ptrace through its tp_syscall_imp raw-syscall
 *            bridge, bypassing the libc ptrace hook in anosdk_bypass.cpp.
 *            We hook tp_syscall_imp directly and intercept PTRACE_TRACEME and
 *            PTRACE_ATTACH / PTRACE_SEIZE the same way as the libc-level hook.
 *
 * Layer 72 — unwind_xx_info_query / unwind_xx_ioctl nullifier
 *            These two exported APIs are libanort's hook-detection surface:
 *            unwind_xx_info_query scans a code address for inline hook patterns,
 *            unwind_xx_ioctl acts as a control interface for the hook scanner.
 *            Returning 0 makes every probe report "no hooks found".
 *
 * Layer 73 — kill() libanort interceptor
 *            libanort calls kill(getpid(), SIGKILL / SIGTERM) when cheat
 *            detection fires. We intercept kill() from libanort targeting
 *            our own PID and return EPERM silently.
 *
 * Layer 74 — access() payload path hider
 *            libanort uses access() to check if known payload filenames exist
 *            on disk. Return ENOENT for any path matching our payload name.
 *
 * Layer 75 — prctl PR_SET_DUMPABLE=0 block
 *            libanort calls prctl(PR_SET_DUMPABLE, 0) to mark the process
 *            non-dumpable, preventing future debugger attachment and interfering
 *            with our injector. We absorb the call when it comes from libanort
 *            so the process remains dumpable for re-injection if needed.
 */

#include "stealth_ext10.hpp"
#include "dobby_stub.hpp"

#include <android/log.h>
#include <dlfcn.h>
#include <link.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <signal.h>
#include <cerrno>
#include <cstring>
#include <cstdio>
#include <cstdint>
#include <pthread.h>

#ifndef ZX_RELEASE
#define LI(...) __android_log_print(ANDROID_LOG_INFO,  "ZX-S10", __VA_ARGS__)
#define LE(...) __android_log_print(ANDROID_LOG_ERROR, "ZX-S10", __VA_ARGS__)
#else
#define LI(...) ((void)0)
#define LE(...) ((void)0)
#endif

static constexpr uint8_t STX10_XK = 0x5Au;
template<size_t N> struct ObfS10 {
    char data[N]{};
    constexpr explicit ObfS10(const char (&s)[N]) {
        for (size_t i = 0; i < N; i++) data[i] = (char)(s[i] ^ STX10_XK);
    }
    void decode(char (&out)[N]) const {
        for (size_t i = 0; i < N; i++) out[i] = (char)(data[i] ^ STX10_XK);
    }
};
#define OBF10(var, lit) \
    char var[sizeof(lit)]; \
    do { static constexpr ObfS10<sizeof(lit)> _o10(lit); _o10.decode(var); } while(0)

// ─────────────────────────────────────────────────────────────────────────────
// libanort.so range — caller-aware checks
// ─────────────────────────────────────────────────────────────────────────────
static uintptr_t s_anort_base10 = 0;
static uintptr_t s_anort_end10  = 0;
static pthread_once_t s_anort_once10 = PTHREAD_ONCE_INIT;

static int phdr_find_anort10(struct dl_phdr_info *info, size_t, void*) {
    if (!info->dlpi_name) return 0;
    OBF10(nm, "libanort.so");
    if (!strstr(info->dlpi_name, nm)) return 0;
    uintptr_t base = (uintptr_t)info->dlpi_addr, end = base;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) &ph = info->dlpi_phdr[i];
        if (ph.p_type == PT_LOAD) {
            uintptr_t se = base + ph.p_vaddr + ph.p_memsz;
            if (se > end) end = se;
        }
    }
    s_anort_base10 = base; s_anort_end10 = end; return 1;
}

static void init_anort10() { dl_iterate_phdr(phdr_find_anort10, nullptr); }

static inline bool caller_is_anort10() {
    pthread_once(&s_anort_once10, init_anort10);
    uintptr_t lr = (uintptr_t)__builtin_return_address(0);
    return s_anort_base10 && lr >= s_anort_base10 && lr < s_anort_end10;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 71 — tp_syscall_imp ptrace neutralizer
// libanort uses tp_syscall_imp as a raw syscall() bypass around libc.
// We intercept ptrace requests; everything else passes through to the real fn.
// ─────────────────────────────────────────────────────────────────────────────
typedef long (*tp_syscall_fn)(long, long, long, long, long, long, long);
static tp_syscall_fn orig_tp_syscall10 = nullptr;

static long hook_tp_syscall10(long nr, long a1, long a2, long a3,
                               long a4, long a5, long a6) {
    if (nr == __NR_ptrace) {
        int request = (int)a1;
        if (request == PTRACE_TRACEME) { errno = 0;     return  0; }
        if (request == PTRACE_ATTACH || request == PTRACE_SEIZE) {
            errno = EPERM; return -1;
        }
    }
    if (!orig_tp_syscall10) return 0;
    return orig_tp_syscall10(nr, a1, a2, a3, a4, a5, a6);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 72 — unwind_xx_info_query / unwind_xx_ioctl nullifier
// ─────────────────────────────────────────────────────────────────────────────
typedef long (*unwind_xx_fn)(void*, void*, void*, void*);
static unwind_xx_fn orig_unwind_info10  = nullptr;
static unwind_xx_fn orig_unwind_ioctl10 = nullptr;

static long hook_unwind_info10(void*, void*, void*, void*)  { return 0; }
static long hook_unwind_ioctl10(void*, void*, void*, void*) { return 0; }

// ─────────────────────────────────────────────────────────────────────────────
// Layer 73 — kill() libanort interceptor
// ─────────────────────────────────────────────────────────────────────────────
typedef int (*kill_fn10)(pid_t, int);
static kill_fn10 orig_kill10 = nullptr;

static int hook_kill10(pid_t pid, int sig) {
    if (caller_is_anort10() && pid == getpid()) {
        errno = EPERM;
        return -1;
    }
    if (!orig_kill10) { errno = ENOSYS; return -1; }
    return orig_kill10(pid, sig);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 74 — access() payload path hider
// ─────────────────────────────────────────────────────────────────────────────
static char s_pay10[48] = {};
static char s_inj10[48] = {};

typedef int (*access_fn10)(const char*, int);
static access_fn10 orig_access10 = nullptr;

static bool path_is_payload10(const char *p) {
    if (!p) return false;
    return (s_pay10[0] && strstr(p, s_pay10)) ||
           (s_inj10[0] && strstr(p, s_inj10));
}

static int hook_access10(const char *path, int mode) {
    if (path_is_payload10(path)) { errno = ENOENT; return -1; }
    if (!orig_access10) { errno = ENOSYS; return -1; }
    return orig_access10(path, mode);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 75 — prctl PR_SET_DUMPABLE=0 block (from libanort only)
// ─────────────────────────────────────────────────────────────────────────────
typedef int (*prctl_fn10)(int, unsigned long, unsigned long,
                          unsigned long, unsigned long);
static prctl_fn10 orig_prctl10 = nullptr;

static int hook_prctl10(int op, unsigned long a1, unsigned long a2,
                         unsigned long a3, unsigned long a4) {
    if (op == PR_SET_DUMPABLE && a1 == 0 && caller_is_anort10()) {
        return 0;
    }
    if (!orig_prctl10) { errno = ENOSYS; return -1; }
    return orig_prctl10(op, a1, a2, a3, a4);
}

// ─────────────────────────────────────────────────────────────────────────────
// Public install
// ─────────────────────────────────────────────────────────────────────────────
void install_stealth_ext10() {
    // Decode payload / injector names for Layer 74
    {
        // "libunity_gc.so" XOR 0x5A
        static const uint8_t kp[] = {0x36,0x33,0x38,0x2F,0x34,0x33,0x2E,0x23,
                                     0x05,0x3D,0x39,0x74,0x29,0x35,0x00};
        for (int i = 0; kp[i]; i++) s_pay10[i] = (char)(kp[i] ^ 0x5A);
        // "libunity_ndk.so" XOR 0x5A
        static const uint8_t ki[] = {0x36,0x33,0x38,0x2F,0x34,0x33,0x2E,0x23,
                                     0x05,0x34,0x30,0x38,0x74,0x29,0x35,0x00};
        for (int i = 0; ki[i]; i++) s_inj10[i] = (char)(ki[i] ^ 0x5A);
    }

    dl_iterate_phdr(phdr_find_anort10, nullptr);

    OBF10(anort_lib, "libanort.so");
    void *h = dlopen(anort_lib, RTLD_LAZY | RTLD_NOLOAD);
    if (!h) h = dlopen(anort_lib, RTLD_LAZY);

    // Layer 71 — tp_syscall_imp
    if (h) {
        void *fn = dlsym(h, "tp_syscall_imp");
        if (!fn) fn = DobbySymbolResolver(anort_lib, "tp_syscall_imp");
        if (fn) {
            DobbyHook(fn, (void*)hook_tp_syscall10, (void**)&orig_tp_syscall10);
            LI("L71 tp_syscall_imp ptrace neutralizer active");
        } else {
            LE("L71 tp_syscall_imp not found");
        }
    }

    // Layer 72 — unwind_xx_info_query / unwind_xx_ioctl
    if (h) {
        void *fn_info  = dlsym(h, "unwind_xx_info_query");
        void *fn_ioctl = dlsym(h, "unwind_xx_ioctl");
        if (!fn_info)  fn_info  = DobbySymbolResolver(anort_lib, "unwind_xx_info_query");
        if (!fn_ioctl) fn_ioctl = DobbySymbolResolver(anort_lib, "unwind_xx_ioctl");
        if (fn_info) {
            DobbyHook(fn_info, (void*)hook_unwind_info10, (void**)&orig_unwind_info10);
            LI("L72 unwind_xx_info_query nullified");
        } else {
            LE("L72 unwind_xx_info_query not found");
        }
        if (fn_ioctl) {
            DobbyHook(fn_ioctl, (void*)hook_unwind_ioctl10, (void**)&orig_unwind_ioctl10);
            LI("L72 unwind_xx_ioctl nullified");
        } else {
            LE("L72 unwind_xx_ioctl not found");
        }
    }

    // Layer 73 — kill() interceptor
    {
        void *fn = DobbySymbolResolver("libc.so", "kill");
        if (!fn) fn = dlsym(RTLD_DEFAULT, "kill");
        if (fn) {
            DobbyHook(fn, (void*)hook_kill10, (void**)&orig_kill10);
            LI("L73 kill() libanort intercept active");
        } else {
            LE("L73 kill not found");
        }
    }

    // Layer 74 — access() hider
    {
        void *fn = DobbySymbolResolver("libc.so", "access");
        if (!fn) fn = dlsym(RTLD_DEFAULT, "access");
        if (fn) {
            DobbyHook(fn, (void*)hook_access10, (void**)&orig_access10);
            LI("L74 access() payload hider active");
        } else {
            LE("L74 access not found");
        }
    }

    // Layer 75 — prctl PR_SET_DUMPABLE=0 block
    {
        void *fn = DobbySymbolResolver("libc.so", "prctl");
        if (!fn) fn = dlsym(RTLD_DEFAULT, "prctl");
        if (fn) {
            DobbyHook(fn, (void*)hook_prctl10, (void**)&orig_prctl10);
            LI("L75 prctl dumpable block active");
        } else {
            LE("L75 prctl not found");
        }
    }

    LI("Layers 71-75 installed OK");
}
