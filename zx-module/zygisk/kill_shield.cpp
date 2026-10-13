/*
 * kill_shield.cpp — Zygisk-resident kill-path neutraliser
 *
 * Intercepts libanogs.so and libanort.so at load time (via android_dlopen_ext
 * hook) and immediately patches every known direct-SVC kill stub before the
 * scanner threads run their first check:
 *
 *   libanogs  kill stub       base+0x3f0270  → MOV W0,#0; RET
 *   libanogs  openat stub     base+0x3f02b0  → MOV W0,#0; RET
 *   libanogs  read stub       base+0x3f02d0  → MOV W0,#0; RET
 *   libanogs  MVM dispatcher  base+0x4e0140  → MOV W0,#0; RET
 *   libanort  tp_syscall_imp  base+0x146940  → MOV X0,XZR; RET
 *
 * Seccomp BPF (25 instructions) — blocks:
 *   exit_group(94)  unconditionally
 *   kill(129)       fatal sigs {9,6,15} to our PID
 *   tgkill(131)     fatal sigs {9,6,15} to our PID
 *
 * Delivered via pthread_create hook (every new thread gets the filter before
 * its body runs) + installed on the calling thread in install().
 *
 * Fallback: background watcher polls /proc/self/maps every 1 ms in case
 * android_dlopen_ext is not the entry point used by the Java class loader.
 */

#include "kill_shield.hpp"
#include "hook_engine.hpp"
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cerrno>
#include <atomic>
#include <android/log.h>
#include <android/dlext.h>

#define TAG "ZX-KS"
#define LI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ── Patch constants ───────────────────────────────────────────────────────────
static constexpr uint32_t kMovW0Zero = 0x52800000u; // MOV W0, #0
static constexpr uint32_t kMovX0XZR = 0xAA1F03E0u; // MOV X0, XZR
static constexpr uint32_t kRet      = 0xD65F03C0u; // RET

// libanogs.so ELF offsets (confirmed via binary analysis)
static constexpr uintptr_t kKillStub   = 0x3f0270UL;
static constexpr uintptr_t kOpenatStub = 0x3f02b0UL;
static constexpr uintptr_t kReadStub   = 0x3f02d0UL;
static constexpr uintptr_t kMVMDisp    = 0x4e0140UL;

// libanort.so ELF offset
static constexpr uintptr_t kTpSyscall  = 0x146940UL;

// ── Seccomp constants ─────────────────────────────────────────────────────────
#ifndef SECCOMP_SET_MODE_FILTER
#  define SECCOMP_SET_MODE_FILTER 1
#endif
#ifndef SECCOMP_RET_ALLOW
#  define SECCOMP_RET_ALLOW 0x7fff0000U
#endif
#ifndef SECCOMP_RET_ERRNO
#  define SECCOMP_RET_ERRNO 0x00050000U
#endif
#ifndef __NR_seccomp
#  define __NR_seccomp 277
#endif

static struct sock_filter g_sc_filter[25];
static struct sock_fprog  g_sc_prog = {25, g_sc_filter};

static void build_seccomp(pid_t pid) {
    struct sock_filter f[] = {
        /* 0  */ BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 0),
        /* 1  */ BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 94, 0, 1),
        /* 2  */ BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|EPERM),
        /* 3  */ BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 0),
        /* 4  */ BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 129, 0, 9),
        /* 5  */ BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 16),
        /* 6  */ BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, (uint32_t)pid, 2, 0),
        /* 7  */ BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 1, 0),
        /* 8  */ BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0xffffffffu, 0, 15),
        /* 9  */ BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 24),
        /* 10 */ BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 9, 2, 0),
        /* 11 */ BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 6, 1, 0),
        /* 12 */ BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 15, 0, 11),
        /* 13 */ BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|EPERM),
        /* 14 */ BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 0),
        /* 15 */ BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 131, 0, 8),
        /* 16 */ BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 16),
        /* 17 */ BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, (uint32_t)pid, 1, 0),
        /* 18 */ BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 0, 5),
        /* 19 */ BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 32),
        /* 20 */ BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 9, 2, 0),
        /* 21 */ BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 6, 1, 0),
        /* 22 */ BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 15, 0, 1),
        /* 23 */ BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|EPERM),
        /* 24 */ BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
    };
    static_assert(sizeof(f)/sizeof(f[0]) == 25, "seccomp filter count");
    memcpy(g_sc_filter, f, sizeof(f));
}

static void install_seccomp_self() {
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    int r = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &g_sc_prog, 0, 0);
    if (r != 0) LE("seccomp errno=%d tid=%d", errno, (int)syscall(SYS_gettid));
    else        LI("seccomp tid=%d", (int)syscall(SYS_gettid));
}

// ── pthread_create hook — seccomp delivered before thread body runs ───────────
using PthreadFn = int(*)(pthread_t*, const pthread_attr_t*, void*(*)(void*), void*);
static PthreadFn orig_pthread_create = nullptr;

struct ThreadCtx { void*(*fn)(void*); void* arg; };

static void* thread_seccomp_wrapper(void* raw) {
    auto* c = static_cast<ThreadCtx*>(raw);
    auto fn  = c->fn;
    auto arg = c->arg;
    delete c;
    install_seccomp_self();
    return fn(arg);
}

static int hook_pthread_create(pthread_t* t, const pthread_attr_t* attr,
                                void*(*fn)(void*), void* arg) {
    return orig_pthread_create(t, attr, thread_seccomp_wrapper,
                               new ThreadCtx{fn, arg});
}

// ── Memory patch helpers ──────────────────────────────────────────────────────
static bool patch2(uintptr_t addr, uint32_t i0, uint32_t i1) {
    uintptr_t page = addr & ~(uintptr_t)0xFFF;
    if (mprotect((void*)page, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC) != 0)
        return false;
    uint32_t* p = (uint32_t*)addr;
    p[0] = i0; p[1] = i1;
    __builtin___clear_cache((char*)addr, (char*)(addr + 8));
    mprotect((void*)page, 0x1000, PROT_READ|PROT_EXEC);
    return true;
}

// ── Patch entry points ────────────────────────────────────────────────────────
static std::atomic<bool> g_anogs_done{false};
static std::atomic<bool> g_anort_done{false};

static void apply_anogs(void* handle) {
    if (g_anogs_done.exchange(true)) return;
    struct link_map* lm = nullptr;
    dlinfo(handle, RTLD_DI_LINKMAP, &lm);
    if (!lm) { LE("anogs: no linkmap"); return; }
    uintptr_t b = (uintptr_t)lm->l_addr;
    LI("anogs base=0x%lx", (unsigned long)b);
    int r1 = patch2(b + kKillStub,   kMovW0Zero, kRet);
    int r2 = patch2(b + kOpenatStub, kMovW0Zero, kRet);
    int r3 = patch2(b + kReadStub,   kMovW0Zero, kRet);
    int r4 = patch2(b + kMVMDisp,    kMovW0Zero, kRet);
    LI("kill=%d openat=%d read=%d MVM=%d", r1, r2, r3, r4);
}

static void apply_anort(void* handle) {
    if (g_anort_done.exchange(true)) return;
    struct link_map* lm = nullptr;
    dlinfo(handle, RTLD_DI_LINKMAP, &lm);
    if (!lm) { LE("anort: no linkmap"); return; }
    uintptr_t b = (uintptr_t)lm->l_addr;
    LI("anort base=0x%lx", (unsigned long)b);
    LI("tp_syscall=%d", patch2(b + kTpSyscall, kMovX0XZR, kRet));
}

// ── android_dlopen_ext hook ───────────────────────────────────────────────────
using DlopenExtFn = void*(*)(const char*, int, const android_dlextinfo*);
static DlopenExtFn orig_dlopen_ext = nullptr;

static void* hook_dlopen_ext(const char* path, int flags,
                              const android_dlextinfo* info) {
    void* h = orig_dlopen_ext(path, flags, info);
    if (h && path) {
        if (!g_anogs_done.load() && strstr(path, "libanogs")) apply_anogs(h);
        if (!g_anort_done.load() && strstr(path, "libanort")) apply_anort(h);
    }
    return h;
}

// ── Fallback watcher thread ───────────────────────────────────────────────────
// Polls /proc/self/maps every 1 ms in case the Java class loader doesn't route
// through android_dlopen_ext (e.g. uses __loader_dlopen_nslist directly).

static void* watcher_thread(void*) {
    for (int i = 0; i < 30000; i++) {
        if (g_anogs_done.load() && g_anort_done.load()) break;
        usleep(1000);

        auto try_patch = [](const char* name, std::atomic<bool>& done,
                            void (*apply)(void*)) {
            if (done.load()) return;
            void* h = dlopen(name, RTLD_NOLOAD | RTLD_LAZY);
            if (h) { apply(h); dlclose(h); }
        };

        try_patch("libanogs.so", g_anogs_done, apply_anogs);
        try_patch("libanort.so", g_anort_done, apply_anort);
    }
    LI("watcher exit anogs=%d anort=%d",
       g_anogs_done.load(), g_anort_done.load());
    return nullptr;
}

// ── Public install ────────────────────────────────────────────────────────────
bool KillShield::install() {
    build_seccomp(getpid());
    install_seccomp_self();

    auto& e = HookEngine::get();

    bool dlo = e.hookSym("libdl.so", "android_dlopen_ext",
                         (void*)hook_dlopen_ext,
                         (void**)&orig_dlopen_ext, "DlopenExt");
    LI("android_dlopen_ext hook: %d", dlo);

    bool ptc = e.hookSym("libc.so", "pthread_create",
                         (void*)hook_pthread_create,
                         (void**)&orig_pthread_create, "PthreadCreate");
    LI("pthread_create hook: %d", ptc);

    // Patch if already loaded (defensive — unlikely in Zygisk context)
    void* ah = dlopen("libanogs.so", RTLD_NOLOAD | RTLD_LAZY);
    if (ah) { apply_anogs(ah); dlclose(ah); }
    void* nh = dlopen("libanort.so", RTLD_NOLOAD | RTLD_LAZY);
    if (nh) { apply_anort(nh); dlclose(nh); }

    // Start fallback watcher (thread body installs seccomp via our pthread hook)
    pthread_t wt;
    pthread_create(&wt, nullptr, watcher_thread, nullptr);
    pthread_detach(wt);

    bool ok = dlo && ptc;

    // Write marker so the ZX-ZOLA app can detect whether the module is active
    if (ok) {
        int fd = open("/data/local/tmp/.zx_ks_ok", O_WRONLY|O_CREAT|O_TRUNC, 0644);
        if (fd >= 0) close(fd);
    }

    return ok;
}
