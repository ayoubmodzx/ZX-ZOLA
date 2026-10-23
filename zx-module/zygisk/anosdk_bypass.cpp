// AnoSDK bypass — two layers:
//
//   Layer 1 (kill prevention): hook libc exit/abort/kill so AnoSDK cannot
//   terminate the process even if it detects something.
//
//   Layer 2 (visibility): hook openat to serve a filtered /proc/self/maps
//   that strips our module lines.  AnoSDK scans maps on startup and on every
//   heartbeat; if it cannot see our .so it skips the "foreign library" report.
//
// CONSTRAINT: AnoSDKIoctl cmd < 0x10 (init / heartbeat) must ALWAYS reach
// the original — server-side heartbeat loss causes a soft-ban.  We no longer
// hook AnoSDK's own exported symbols because Dobby inline patches on
// libanogs.so are detected by AnoSDK's own code-integrity scanner (the
// result is included in the heartbeat payload → immediate server-side ban).

#include "anosdk_bypass.hpp"
#include "hook_engine.hpp"
#include <dlfcn.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <android/log.h>
#include <atomic>

#define TAG "ZX-ANO"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ── Original pointers — Phase 1 (libc.so kill prevention) ────────────────────
static void (*orig_exit)(int)                    = nullptr;
static void (*orig__exit)(int)                   = nullptr;
static void (*orig_abort)()                      = nullptr;
static int  (*orig_kill)(pid_t, int)             = nullptr;
static int  (*orig_tgkill)(int, int, int)        = nullptr;
static int  (*orig_pthread_kill)(pthread_t, int) = nullptr;

// ── Original pointer — openat (maps filter) ───────────────────────────────────
static int (*orig_openat)(int, const char *, int, mode_t) = nullptr;

// ── /proc/self/maps filter ────────────────────────────────────────────────────
// Reads the real maps via raw syscalls (no libc, no hook re-entrance) and writes
// a filtered copy into a memfd.  Returns the memfd fd, or -1 on failure.
static int make_filtered_maps() {
    // Raw openat — bypasses our own hook
    int real_fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY, 0);
    if (real_fd < 0) return -1;

    // memfd_create: anonymous file, no O_TMPFILE hassle
    int mem_fd = (int)syscall(SYS_memfd_create, "maps", 0U);
    if (mem_fd < 0) {
        syscall(SYS_close, real_fd);
        return -1;
    }

    char buf[4096];
    char line[512];
    int  llen = 0;

    for (;;) {
        ssize_t n = (ssize_t)syscall(SYS_read, real_fd, buf, sizeof(buf));
        if (n <= 0) break;
        for (ssize_t i = 0; i < n; i++) {
            char c = buf[i];
            if (llen < (int)sizeof(line) - 1) line[llen++] = c;
            if (c == '\n' || llen >= (int)sizeof(line) - 1) {
                line[llen] = '\0';
                // Strip lines that expose our module or companion app
                bool hide = strstr(line, "arm64-v8a.so")  != nullptr
                         || strstr(line, "zx_zola")       != nullptr
                         || strstr(line, "zx-zola")       != nullptr
                         || strstr(line, "com.zx.zola")   != nullptr;
                if (!hide)
                    syscall(SYS_write, mem_fd, line, (size_t)llen);
                llen = 0;
            }
        }
    }
    // Flush partial last line (no trailing newline)
    if (llen > 0) {
        line[llen] = '\0';
        bool hide = strstr(line, "arm64-v8a.so") || strstr(line, "zx_zola");
        if (!hide) syscall(SYS_write, mem_fd, line, (size_t)llen);
    }

    syscall(SYS_close, real_fd);
    // Rewind so the caller can read from the start
    syscall(SYS_lseek, mem_fd, 0, SEEK_SET);
    return mem_fd;
}

// Returns true if path is a /proc maps file for our process
static bool is_self_maps(const char *path) {
    if (!path) return false;
    if (strcmp(path, "/proc/self/maps")  == 0) return true;
    if (strcmp(path, "/proc/self/smaps") == 0) return true;
    // /proc/<pid>/maps — match our own pid
    char buf[64];
    int  pid = (int)getpid();
    snprintf(buf, sizeof(buf), "/proc/%d/maps",  pid);
    if (strcmp(path, buf) == 0) return true;
    snprintf(buf, sizeof(buf), "/proc/%d/smaps", pid);
    if (strcmp(path, buf) == 0) return true;
    return false;
}

static int hook_openat(int dirfd, const char *path, int flags, mode_t mode) {
    if (is_self_maps(path)) {
        int fd = make_filtered_maps();
        if (fd >= 0) {
            LOGI("Served filtered maps to caller (path=%s)", path);
            return fd;
        }
    }
    if (orig_openat) return orig_openat(dirfd, path, flags, mode);
    return (int)syscall(SYS_openat, dirfd, path, flags, mode);
}

// ── Phase 1: kill / exit hooks ────────────────────────────────────────────────
// AnoSDK kills the process via exit(non-zero) or kill(self, SIGABRT).
// We block those calls from background threads (AnoSDK runs off-main-thread).

[[noreturn]] static void hook_exit(int code) {
    if (code != 0 || gettid() != getpid()) {
        LOGE("BLOCKED exit(%d) tid=%d — AnoSDK kill suppressed", code, gettid());
        for (;;) usleep(2000000);
    }
    if (orig_exit) { orig_exit(0); __builtin_unreachable(); }
    ::_Exit(0);
}

[[noreturn]] static void hook__exit(int code) {
    if (code != 0 || gettid() != getpid()) {
        LOGE("BLOCKED _exit(%d) tid=%d — AnoSDK kill suppressed", code, gettid());
        for (;;) usleep(2000000);
    }
    if (orig__exit) { orig__exit(0); __builtin_unreachable(); }
    ::_Exit(0);
}

[[noreturn]] static void hook_abort() {
    LOGE("BLOCKED abort() — AnoSDK kill suppressed");
    for (;;) usleep(2000000);
}

static int hook_kill(pid_t pid, int sig) {
    pid_t self = getpid();
    if ((pid == self || pid == 0) &&
        (sig == SIGABRT || sig == SIGKILL || sig == SIGTERM)) {
        LOGE("BLOCKED kill(%d,%d) — AnoSDK kill suppressed", pid, sig);
        return 0;
    }
    if (orig_kill) return orig_kill(pid, sig);
    return (int)syscall(SYS_kill, pid, sig);
}

static int hook_tgkill(int tgid, int tid, int sig) {
    if (tgid == (int)getpid() &&
        (sig == SIGABRT || sig == SIGKILL || sig == SIGTERM)) {
        LOGE("BLOCKED tgkill(%d,%d,%d) — AnoSDK kill suppressed", tgid, tid, sig);
        return 0;
    }
    return (int)syscall(SYS_tgkill, tgid, tid, sig);
}

static int hook_pthread_kill(pthread_t t, int sig) {
    if (sig == SIGABRT || sig == SIGKILL || sig == SIGTERM) {
        LOGE("BLOCKED pthread_kill(%d) — AnoSDK kill suppressed", sig);
        return 0;
    }
    if (orig_pthread_kill) return orig_pthread_kill(t, sig);
    return 0;
}

// ── Public API ────────────────────────────────────────────────────────────────

void AnoBypass::installEarly() {
    auto &e = HookEngine::get();

    // Layer 2: /proc/self/maps filter
    // Must come first so it is active before AnoSDK even starts scanning.
    bool fm = e.hookSym("libc.so", "openat",
                         (void *)hook_openat, (void **)&orig_openat, "MapsFilter");

    // Layer 1: kill-prevention hooks on libc
    bool h1 = e.hookSym("libc.so", "exit",
                          (void *)hook_exit,         (void **)&orig_exit,         "Exit");
    bool h2 = e.hookSym("libc.so", "_exit",
                          (void *)hook__exit,        (void **)&orig__exit,        "_Exit");
    bool h3 = e.hookSym("libc.so", "abort",
                          (void *)hook_abort,        nullptr,                     "Abort");
    bool h4 = e.hookSym("libc.so", "kill",
                          (void *)hook_kill,         (void **)&orig_kill,         "Kill");
    bool h5 = e.hookSym("libc.so", "tgkill",
                          (void *)hook_tgkill,       (void **)&orig_tgkill,       "Tgkill");
    bool h6 = e.hookSym("libc.so", "pthread_kill",
                          (void *)hook_pthread_kill, (void **)&orig_pthread_kill, "PtkKill");

    // Ignore SIGABRT/SIGTERM at signal-delivery level as belt-and-suspenders
    struct sigaction sa{};
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGABRT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    LOGI("AnoBypass early: maps_filter=%d  exit=%d _exit=%d abort=%d kill=%d tgkill=%d ptk_kill=%d",
         fm, h1, h2, h3, h4, h5, h6);
}

// Phase 2 (Dobby inline hooks on libanogs.so exported functions) is intentionally
// removed.  AnoSDK's code-integrity scanner checks the first bytes of its own
// exports on every heartbeat; a Dobby trampoline there is included verbatim in
// the heartbeat report → server-side ban within seconds.
// AnoSDK also sends scan results directly over its own network stack, bypassing
// the GetReportData game API, so those hooks had zero effect on what the server
// receives.

void AnoBypass::startWatcher() {
    // No-op: Phase 2 AnoSDK API hooks removed (see comment above).
}

bool AnoBypass::install() {
    installEarly();
    return true;
}

void AnoBypass::remove() {
    LOGI("AnoSDK bypass removed");
}
