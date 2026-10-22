// Two-phase AnoSDK bypass
// Phase 1: Hook libc.so kill/exit/abort — fires BEFORE libanogs.so loads
// Phase 2: Watcher thread waits for libanogs.so, then hooks its API layer
//
// CONSTRAINT: Never block AnoSDK heartbeat/init commands — only null out
// scanner triggers and kill mechanisms to avoid server-side bans.

#include "anosdk_bypass.hpp"
#include "hook_engine.hpp"
#include <dlfcn.h>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/types.h>
#include <android/log.h>
#include <sys/syscall.h>
#include <atomic>

#define TAG "ZX-ANO"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ── Original pointers — Phase 1 (libc.so) ────────────────────────────────────
static void (*orig_exit)(int)                    = nullptr;
static void (*orig__exit)(int)                   = nullptr;
static void (*orig_abort)()                      = nullptr;
static int  (*orig_kill)(pid_t, int)             = nullptr;
static int  (*orig_tgkill)(int, int, int)        = nullptr;
static int  (*orig_pthread_kill)(pthread_t, int) = nullptr;

// ── Original pointers — Phase 2 (libanogs.so) ────────────────────────────────
static int   (*orig_AnoSDKIoctl)(int, void *, int)               = nullptr;
static int   (*orig_AnoSDKIoctlOld)(int, void *, int)            = nullptr;
static void* (*orig_AnoSDKGetReportData)(int *)                  = nullptr;
static void* (*orig_AnoSDKGetReportData2)(int, int *)            = nullptr;
static void* (*orig_AnoSDKGetReportData3)(int, int *, int)       = nullptr;
static void* (*orig_AnoSDKGetReportData4)(int, int *, int, int)  = nullptr;
static void  (*orig_AnoSDKDelReportData)(void *)                 = nullptr;
static void  (*orig_AnoSDKDelReportData3)(void *, int)           = nullptr;
static void  (*orig_AnoSDKDelReportData4)(void *, int, int)      = nullptr;

// ── Phase 1 hooks ─────────────────────────────────────────────────────────────

// AnoSDK calls exit(1) or exit(127) to terminate the process.
// Two detection criteria, either is enough to block:
//   • code != 0  — normal game shutdown is always exit(0)
//   • gettid() != getpid() — AnoSDK runs on its own background thread;
//     the main thread has tid == pid in Android.
[[noreturn]] static void hook_exit(int code) {
    bool from_bg_thread = (gettid() != getpid());
    if (code != 0 || from_bg_thread) {
        LOGE("BLOCKED exit(%d) tid=%d pid=%d — AnoSDK kill suppressed",
             code, gettid(), getpid());
        for (;;) usleep(2000000);
    }
    // Legitimate clean shutdown from main thread
    if (orig_exit) { orig_exit(0); __builtin_unreachable(); }
    ::_Exit(0);
}

[[noreturn]] static void hook__exit(int code) {
    bool from_bg_thread = (gettid() != getpid());
    if (code != 0 || from_bg_thread) {
        LOGE("BLOCKED _exit(%d) tid=%d pid=%d — AnoSDK kill suppressed",
             code, gettid(), getpid());
        for (;;) usleep(2000000);
    }
    if (orig__exit) { orig__exit(0); __builtin_unreachable(); }
    ::_Exit(0);
}

// abort() is [[noreturn]] — returning causes UB and detectable crashes.
// Spin forever like hook_exit so the calling thread stalls harmlessly.
[[noreturn]] static void hook_abort() {
    LOGE("BLOCKED abort() — AnoSDK kill suppressed");
    for (;;) usleep(2000000);
}

// Block SIGABRT / SIGKILL / SIGTERM sent to self — AnoSDK's kill(getpid(), sig) path
static int hook_kill(pid_t pid, int sig) {
    pid_t self = getpid();
    if ((pid == self || pid == 0) &&
        (sig == SIGABRT || sig == SIGKILL || sig == SIGTERM)) {
        LOGE("BLOCKED kill(%d, %d) to self — AnoSDK kill suppressed", pid, sig);
        return 0;
    }
    // Pass through all other kill() calls via syscall to avoid PLT re-entrance
    if (orig_kill) return orig_kill(pid, sig);
    return (int)syscall(SYS_kill, pid, sig);
}

// AnoSDK also uses tgkill(pid, tid, sig) to kill specific threads
static int hook_tgkill(int tgid, int tid, int sig) {
    int self = (int)getpid();
    if (tgid == self &&
        (sig == SIGABRT || sig == SIGKILL || sig == SIGTERM)) {
        LOGE("BLOCKED tgkill(%d, %d, %d) — AnoSDK kill suppressed", tgid, tid, sig);
        return 0;
    }
    // Use raw syscall to avoid infinite recursion through our own hook
    return (int)syscall(SYS_tgkill, tgid, tid, sig);
}

// pthread_kill(thread, sig) — explicit hook so libanogs.so can't bypass tgkill hook
// via a different Bionic entry point. We mirror the tgkill logic.
static int hook_pthread_kill(pthread_t thread, int sig) {
    // Check if the target thread belongs to our process
    if (sig == SIGABRT || sig == SIGKILL || sig == SIGTERM) {
        LOGE("BLOCKED pthread_kill(tid, %d) — AnoSDK kill suppressed", sig);
        return 0;
    }
    if (orig_pthread_kill) return orig_pthread_kill(thread, sig);
    return 0;
}

// ── Phase 2 hooks ─────────────────────────────────────────────────────────────

// Allow init/heartbeat Ioctl (cmd < 0x10) — server must receive heartbeats
// or the account gets soft-banned. Drop active-scan trigger commands only.
static int hook_AnoSDKIoctl(int cmd, void *data, int len) {
    if (cmd < 0x10 && orig_AnoSDKIoctl)
        return orig_AnoSDKIoctl(cmd, data, len);
    return 0;
}

// AnoSDKIoctlOld — legacy API present in this build; same policy as Ioctl.
static int hook_AnoSDKIoctlOld(int cmd, void *data, int len) {
    if (cmd < 0x10 && orig_AnoSDKIoctlOld)
        return orig_AnoSDKIoctlOld(cmd, data, len);
    return 0;
}

// GetReportData — consume real scan data and discard it so detection reports
// never reach the game caller (which would forward them to the server).
// Dobby patches in libil2cpp.so ARE detected by AnoSDK code integrity scans;
// passing real reports through would immediately trigger a server-side ban.
static void *hook_AnoSDKGetReportData(int *len) {
    if (orig_AnoSDKGetReportData) {
        int real_len = 0;
        void *real_data = orig_AnoSDKGetReportData(&real_len);
        if (real_data && orig_AnoSDKDelReportData)
            orig_AnoSDKDelReportData(real_data);
    }
    if (len) *len = 0;
    return nullptr;
}
static void *hook_AnoSDKGetReportData2(int type, int *len) {
    if (orig_AnoSDKGetReportData2) {
        int real_len = 0;
        void *real_data = orig_AnoSDKGetReportData2(type, &real_len);
        if (real_data && orig_AnoSDKDelReportData)
            orig_AnoSDKDelReportData(real_data);
    }
    if (len) *len = 0;
    return nullptr;
}
static void *hook_AnoSDKGetReportData3(int type, int *len, int flag) {
    if (orig_AnoSDKGetReportData3) {
        int real_len = 0;
        void *real_data = orig_AnoSDKGetReportData3(type, &real_len, flag);
        if (real_data && orig_AnoSDKDelReportData3)
            orig_AnoSDKDelReportData3(real_data, flag);
    }
    if (len) *len = 0;
    return nullptr;
}
static void *hook_AnoSDKGetReportData4(int type, int *len, int flag, int extra) {
    if (orig_AnoSDKGetReportData4) {
        int real_len = 0;
        void *real_data = orig_AnoSDKGetReportData4(type, &real_len, flag, extra);
        if (real_data && orig_AnoSDKDelReportData4)
            orig_AnoSDKDelReportData4(real_data, flag, extra);
    }
    if (len) *len = 0;
    return nullptr;
}

// DelReportData — complements GetReportData; pass through to avoid leaks.
static void hook_AnoSDKDelReportData(void *data) {
    if (orig_AnoSDKDelReportData) orig_AnoSDKDelReportData(data);
}
static void hook_AnoSDKDelReportData3(void *data, int flag) {
    if (orig_AnoSDKDelReportData3) orig_AnoSDKDelReportData3(data, flag);
}
static void hook_AnoSDKDelReportData4(void *data, int flag, int extra) {
    if (orig_AnoSDKDelReportData4) orig_AnoSDKDelReportData4(data, flag, extra);
}

// ── /proc/self/maps helper — finds full path of a loaded library ──────────────
// Android 11+ linker namespace isolation makes dlopen("libanogs.so", RTLD_NOLOAD)
// return NULL from Zygisk's namespace even when the library is loaded in the app's
// namespace. Parsing /proc/self/maps gives us the real on-disk path which can then
// be dlopen'd with RTLD_LAZY to obtain a valid handle for dlsym lookups.
static bool getMapsLibPath(const char *libname, char *path_out, size_t plen) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, libname)) continue;
        char *slash = strchr(line, '/');
        if (!slash) continue;
        size_t slen = strlen(slash);
        if (slen > 0 && slash[slen - 1] == '\n') slash[slen - 1] = '\0';
        // Skip anonymous or deleted mappings
        if (strstr(slash, " (deleted)")) continue;
        if (path_out) { strncpy(path_out, slash, plen - 1); path_out[plen - 1] = '\0'; }
        found = true;
        break;
    }
    fclose(fp);
    return found;
}

// ── Phase 2 installer — called from watcher thread once libanogs.so loads ────
// Accepts the already-open handle so dlsym resolves into the correct namespace.
static void installAnogsApiHooks(void *h) {
    auto &e = HookEngine::get();

    auto resolve = [&](const char *sym_name, void *hook_fn, void **orig_out, const char *tag) {
        void *sym = dlsym(h, sym_name);
        if (!sym) {
            LOGE("[%s] %s not found in handle", tag, sym_name);
            return;
        }
        e.hookAddr(sym, hook_fn, orig_out, tag);
    };

    // Ioctl variants — heartbeats (cmd < 0x10) pass through; scan triggers blocked
    resolve("AnoSDKIoctl",    (void *)hook_AnoSDKIoctl,    (void **)&orig_AnoSDKIoctl,    "AnoIoctl");
    resolve("AnoSDKIoctlOld", (void *)hook_AnoSDKIoctlOld, (void **)&orig_AnoSDKIoctlOld, "AnoIoctlOld");

    // GetReportData — consume real scan reports; return nullptr so caller sends nothing
    resolve("AnoSDKGetReportData",  (void *)hook_AnoSDKGetReportData,  (void **)&orig_AnoSDKGetReportData,  "AnoRep1");
    resolve("AnoSDKGetReportData2", (void *)hook_AnoSDKGetReportData2, (void **)&orig_AnoSDKGetReportData2, "AnoRep2");
    resolve("AnoSDKGetReportData3", (void *)hook_AnoSDKGetReportData3, (void **)&orig_AnoSDKGetReportData3, "AnoRep3");
    resolve("AnoSDKGetReportData4", (void *)hook_AnoSDKGetReportData4, (void **)&orig_AnoSDKGetReportData4, "AnoRep4");

    // DelReportData — pass through; needed by GetReportData hooks to free memory
    resolve("AnoSDKDelReportData",  (void *)hook_AnoSDKDelReportData,  (void **)&orig_AnoSDKDelReportData,  "AnoDel1");
    resolve("AnoSDKDelReportData3", (void *)hook_AnoSDKDelReportData3, (void **)&orig_AnoSDKDelReportData3, "AnoDel3");
    resolve("AnoSDKDelReportData4", (void *)hook_AnoSDKDelReportData4, (void **)&orig_AnoSDKDelReportData4, "AnoDel4");

    LOGI("Phase 2: API hooks installed on libanogs.so (Ioctl blocked, reports consumed+discarded)");
}

// ── Watcher thread ────────────────────────────────────────────────────────────
static std::atomic<bool> g_watcher_stop{false};

static void *libanos_watcher(void *) {
    // Poll every 100ms for up to 60 seconds
    for (int i = 0; i < 600 && !g_watcher_stop.load(std::memory_order_acquire); ++i) {
        usleep(100000);

        // Try /proc/self/maps first — works across Android 11+ namespace boundaries
        char full_path[512] = {};
        bool in_maps = getMapsLibPath("libanogs.so", full_path, sizeof(full_path));
        if (!in_maps) continue;

        // dlopen via full path bypasses the linker namespace restriction
        void *h = dlopen(full_path, RTLD_LAZY);
        if (!h) {
            // Rare: maps entry exists but dlopen fails — try bare name as fallback
            h = dlopen("libanogs.so", RTLD_LAZY);
        }
        if (!h) {
            LOGE("Watcher: libanogs.so in maps but dlopen failed: %s", dlerror());
            continue;
        }

        LOGI("Watcher: libanogs.so appeared at %dms (path=%s) — hooking API",
             (i + 1) * 100, full_path);
        installAnogsApiHooks(h);
        dlclose(h);
        return nullptr;
    }
    LOGE("Watcher: libanogs.so never appeared in 60s");
    return nullptr;
}

// ── Public API ────────────────────────────────────────────────────────────────

void AnoBypass::installEarly() {
    auto &e = HookEngine::get();

    bool e1 = e.hookSym("libc.so", "exit",
                         (void *)hook_exit,  (void **)&orig_exit,   "ExitBlock");
    bool e2 = e.hookSym("libc.so", "_exit",
                         (void *)hook__exit, (void **)&orig__exit,  "_ExitBlock");
    bool e3 = e.hookSym("libc.so", "abort",
                         (void *)hook_abort, nullptr,               "AbortBlock");
    bool e4 = e.hookSym("libc.so", "kill",
                         (void *)hook_kill,    (void **)&orig_kill,    "KillBlock");
    bool e5 = e.hookSym("libc.so", "tgkill",
                         (void *)hook_tgkill,  (void **)&orig_tgkill,  "TgkillBlock");
    bool e6 = e.hookSym("libc.so", "pthread_kill",
                         (void *)hook_pthread_kill,
                         (void **)&orig_pthread_kill, "PthreadKillBlock");

    // Belt-and-suspenders: ignore SIGABRT + SIGTERM at the signal delivery level.
    // This catches signals delivered before our kill/tgkill hooks are hit,
    // and covers any delivery path that bypasses those hooks.
    struct sigaction sa{};
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGABRT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    LOGI("Phase 1 early hooks: exit=%d _exit=%d abort=%d kill=%d tgkill=%d pthread_kill=%d",
         e1, e2, e3, e4, e5, e6);
}

void AnoBypass::startWatcher() {
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&tid, &attr, libanos_watcher, nullptr) == 0) {
        LOGI("Phase 2: libanogs.so watcher thread started");
    } else {
        LOGE("Phase 2: failed to create watcher thread — trying inline install");
        char full_path[512] = {};
        if (getMapsLibPath("libanogs.so", full_path, sizeof(full_path))) {
            void *h = dlopen(full_path, RTLD_LAZY);
            if (!h) h = dlopen("libanogs.so", RTLD_LAZY);
            if (h) { installAnogsApiHooks(h); dlclose(h); }
            else LOGE("Phase 2 inline: dlopen failed: %s", dlerror());
        } else {
            LOGE("Phase 2 inline: libanogs.so not in maps yet");
        }
    }
    pthread_attr_destroy(&attr);
}

bool AnoBypass::install() {
    installEarly();
    startWatcher();
    return true;
}

void AnoBypass::remove() {
    g_watcher_stop.store(true, std::memory_order_release);
    LOGI("AnoSDK bypass removed");
}
