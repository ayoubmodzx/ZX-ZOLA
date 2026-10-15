/*
 * stealth_ext8.cpp — ZX Anti-Detection Layers 58–62
 *
 * Layer 58 — process_vm_readv / process_vm_writev libc-level block
 *            Layer 13 (tp_syscall_imp) already blocks these via libanort's SVC
 *            path. Layer 58 adds Dobby hooks on the libc symbols directly so
 *            any code path that calls process_vm_readv through the PLT is also
 *            blocked, closing the gap between the libanort SVC path and direct
 *            libc calls from libanogs or any injected scanner helper.
 *
 * Layer 59 — io_uring setup nullifier
 *            AnoSDK 3.7+ uses io_uring to perform async I/O (openat, read) on
 *            /proc files without touching the libc PLT, bypassing our
 *            Layers 2/3/8/18 openat/read hooks. We intercept io_uring_setup via
 *            the libc syscall() wrapper and return ENOSYS, preventing ring
 *            creation and forcing AnoSDK back to synchronous libc paths our
 *            hooks already cover. Also blocks io_uring_enter / io_uring_register
 *            so a ring set up before our hooks loaded cannot be used either.
 *
 * Layer 60 — /proc/net/tcp + tcp6 + udp read sanitizer
 *            libanogs reads /proc/net/tcp{,6} and /proc/net/udp to detect
 *            connections to known C2 endpoints. connect() blocker (L49)
 *            prevents NEW connections but existing state remains visible. We
 *            hook read() on fds backed by these paths and emit a header-only
 *            response, hiding all TCP/UDP state from AnoSDK's network scanner.
 *
 * Layer 61 — pidfd_open / pidfd_send_signal blocker
 *            Android 12+ exposes pidfd_open (syscall 434). AnoSDK can use it
 *            to obtain a stable process reference and then call
 *            pidfd_send_signal to send SIGKILL/SIGABRT, bypassing kill/tgkill
 *            hooks. We intercept via syscall() and return ENOSYS.
 *
 * Layer 62 — sendfile / sendfile64 /proc cloning blocker
 *            AnoSDK can clone /proc/self/maps into a socket or pipe via
 *            sendfile(), bypassing our read() hook — the kernel transfers
 *            data directly with no userspace buffer. We hook sendfile and
 *            block any transfer whose source fd resolves to a /proc path
 *            we sanitize, falling through for all other transfers.
 */

#include "stealth_ext8.hpp"
#include "dobby_stub.hpp"

#include <android/log.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <pthread.h>
#include <atomic>

#ifndef ZX_RELEASE
#define LI(...) __android_log_print(ANDROID_LOG_INFO,  "ZX-S8", __VA_ARGS__)
#define LE(...) __android_log_print(ANDROID_LOG_ERROR, "ZX-S8", __VA_ARGS__)
#else
#define LI(...) ((void)0)
#define LE(...) ((void)0)
#endif

// ─────────────────────────────────────────────────────────────────────────────
// Syscall numbers (arm64) for features not always in NDK headers
// ─────────────────────────────────────────────────────────────────────────────

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup      425
#endif
#ifndef __NR_io_uring_enter
#define __NR_io_uring_enter      426
#endif
#ifndef __NR_io_uring_register
#define __NR_io_uring_register   427
#endif
#ifndef __NR_pidfd_open
#define __NR_pidfd_open          434
#endif
#ifndef __NR_pidfd_send_signal
#define __NR_pidfd_send_signal   424
#endif
#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd         438
#endif
#ifndef __NR_process_vm_readv
#define __NR_process_vm_readv    270
#endif
#ifndef __NR_process_vm_writev
#define __NR_process_vm_writev   271
#endif

// ─────────────────────────────────────────────────────────────────────────────
// /proc/net fd tracking (Layer 60)
// Maps a small set of open fds to their proc/net path types.
// ─────────────────────────────────────────────────────────────────────────────

static constexpr int MAX_NET_FDS = 32;

struct NetFdEntry {
    int  fd;
    bool active;
};

static NetFdEntry        g_net_fds[MAX_NET_FDS];
static pthread_mutex_t   g_net_mu = PTHREAD_MUTEX_INITIALIZER;

static void net_fd_register(int fd) {
    pthread_mutex_lock(&g_net_mu);
    for (int i = 0; i < MAX_NET_FDS; i++) {
        if (!g_net_fds[i].active) {
            g_net_fds[i] = { fd, true };
            break;
        }
    }
    pthread_mutex_unlock(&g_net_mu);
}

static void net_fd_unregister(int fd) {
    pthread_mutex_lock(&g_net_mu);
    for (int i = 0; i < MAX_NET_FDS; i++) {
        if (g_net_fds[i].active && g_net_fds[i].fd == fd) {
            g_net_fds[i].active = false;
            break;
        }
    }
    pthread_mutex_unlock(&g_net_mu);
}

static bool net_fd_is_tracked(int fd) {
    if (fd < 0) return false;
    pthread_mutex_lock(&g_net_mu);
    bool found = false;
    for (int i = 0; i < MAX_NET_FDS && !found; i++)
        if (g_net_fds[i].active && g_net_fds[i].fd == fd) found = true;
    pthread_mutex_unlock(&g_net_mu);
    return found;
}

// Check if a path is a /proc/net TCP/UDP table we sanitize
static bool is_net_tcp_path(const char *path) {
    if (!path) return false;
    return (strstr(path, "/proc/net/tcp")  != nullptr ||
            strstr(path, "/proc/net/udp")  != nullptr ||
            strstr(path, "/proc/net/raw")  != nullptr ||
            strstr(path, "/proc/net/unix") != nullptr);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 58 — process_vm_readv / process_vm_writev libc PLT hook
// ─────────────────────────────────────────────────────────────────────────────

typedef ssize_t (*pvm_readv_t)(pid_t, const struct iovec*, unsigned long,
                               const struct iovec*, unsigned long, unsigned long);
typedef ssize_t (*pvm_writev_t)(pid_t, const struct iovec*, unsigned long,
                                const struct iovec*, unsigned long, unsigned long);

static pvm_readv_t  orig_pvm_readv  = nullptr;
static pvm_writev_t orig_pvm_writev = nullptr;

static ssize_t hook_pvm_readv(pid_t pid, const struct iovec *lvec,
                              unsigned long liovcnt, const struct iovec *rvec,
                              unsigned long riovcnt, unsigned long flags) {
    (void)pid; (void)lvec; (void)liovcnt;
    (void)rvec; (void)riovcnt; (void)flags;
    errno = EPERM;
    return -1;
}

static ssize_t hook_pvm_writev(pid_t pid, const struct iovec *lvec,
                               unsigned long liovcnt, const struct iovec *rvec,
                               unsigned long riovcnt, unsigned long flags) {
    (void)pid; (void)lvec; (void)liovcnt;
    (void)rvec; (void)riovcnt; (void)flags;
    errno = EPERM;
    return -1;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 59 — io_uring / pidfd syscall() intercept (extends Layer 34)
// Layer 61 — pidfd_open / pidfd_send_signal / pidfd_getfd
// These are injected into the existing libc syscall() hook via a chain.
// ─────────────────────────────────────────────────────────────────────────────

typedef long (*syscall_t)(long, long, long, long, long, long, long);
static syscall_t orig_syscall8 = nullptr;

static long hook_syscall8(long nr, long a1, long a2, long a3,
                          long a4, long a5, long a6) {
    switch ((int)nr) {
    // Layer 59 — io_uring: deny ring creation; any in-flight ring setup dies
    case __NR_io_uring_setup:
    case __NR_io_uring_enter:
    case __NR_io_uring_register:
        errno = ENOSYS;
        return -1L;

    // Layer 61 — pidfd: deny all pidfd-based process handle creation/signaling
    case __NR_pidfd_open:
    case __NR_pidfd_send_signal:
    case __NR_pidfd_getfd:
        errno = ENOSYS;
        return -1L;

    // Layer 58 (raw SVC path) — block process_vm_readv / writev
    case __NR_process_vm_readv:
    case __NR_process_vm_writev:
        errno = EPERM;
        return -1L;

    default:
        break;
    }
    if (!orig_syscall8) { errno = ENOSYS; return -1L; }
    return orig_syscall8(nr, a1, a2, a3, a4, a5, a6);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 60 — openat hook: register /proc/net/* fds
// Chained onto an existing openat hook; only tracks; the read hook below
// returns the sanitized response for tracked fds.
// ─────────────────────────────────────────────────────────────────────────────

typedef int (*openat_fn8)(int, const char*, int, ...);
static openat_fn8 orig_openat8 = nullptr;

static int hook_openat8(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        __builtin_va_list ap;
        __builtin_va_start(ap, flags);
        mode = __builtin_va_arg(ap, mode_t);
        __builtin_va_end(ap);
    }

    int ret;
    if (!orig_openat8) { errno = ENOSYS; return -1; }
    if (flags & O_CREAT) ret = orig_openat8(dirfd, path, flags, mode);
    else                  ret = orig_openat8(dirfd, path, flags);

    // Track fds opened on /proc/net TCP/UDP tables
    if (ret >= 0 && is_net_tcp_path(path))
        net_fd_register(ret);

    return ret;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 60 — close hook: untrack /proc/net fds
// ─────────────────────────────────────────────────────────────────────────────

typedef int (*close_fn8)(int);
static close_fn8 orig_close8 = nullptr;

static int hook_close8(int fd) {
    net_fd_unregister(fd);
    if (!orig_close8) { errno = ENOSYS; return -1; }
    return orig_close8(fd);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 60 — read hook: emit header-only for /proc/net TCP/UDP fds
//
// /proc/net/tcp  format:  sl  local_address  rem_address  st  tx/rx …
// We return just the header line so the parser finds zero socket rows.
// ─────────────────────────────────────────────────────────────────────────────

typedef ssize_t (*read_fn8)(int, void*, size_t);
static read_fn8 orig_read8 = nullptr;

// Per-thread "already spoofed" flag: pread/lseek-based multi-read gets header once
static thread_local bool t_net_header_sent = false;

static ssize_t hook_read8(int fd, void *buf, size_t count) {
    if (net_fd_is_tracked(fd) && buf && count > 0) {
        if (!t_net_header_sent) {
            // Emit column header then EOF on subsequent reads
            static const char hdr[] =
                "  sl  local_address rem_address   st tx_queue rx_queue"
                " tr tm->when retrnsmt   uid  timeout inode\n";
            size_t hlen = strlen(hdr);
            size_t out  = hlen < count ? hlen : count;
            memcpy(buf, hdr, out);
            t_net_header_sent = true;
            return (ssize_t)out;
        }
        // Subsequent reads return EOF (0)
        t_net_header_sent = false; // reset for next open-read cycle
        return 0;
    }
    if (!orig_read8) { errno = ENOSYS; return -1; }
    return orig_read8(fd, buf, count);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 62 — sendfile / sendfile64 /proc clone blocker
// ─────────────────────────────────────────────────────────────────────────────

typedef ssize_t (*sendfile_t)(int, int, off_t*, size_t);
static sendfile_t orig_sendfile = nullptr;

// Resolve fd to a path using /proc/self/fd symlink
static bool fd_is_proc_path(int fd) {
    char link[32], path[128];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t r = readlink(link, path, sizeof(path) - 1);
    if (r <= 0) return false;
    path[r] = '\0';
    return (strncmp(path, "/proc/", 6) == 0 ||
            strncmp(path, "/sys/",  5) == 0);
}

static ssize_t hook_sendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
    if (fd_is_proc_path(in_fd)) {
        // Block sendfile clone of any /proc or /sys file
        errno = EPERM;
        return -1;
    }
    if (!orig_sendfile) { errno = ENOSYS; return -1; }
    return orig_sendfile(out_fd, in_fd, offset, count);
}

// ─────────────────────────────────────────────────────────────────────────────
// Public install
// ─────────────────────────────────────────────────────────────────────────────

void install_stealth_ext8() {
    // Layer 58 — process_vm_readv / process_vm_writev libc PLT hooks
    {
        void *fn_rv = DobbySymbolResolver("libc.so", "process_vm_readv");
        if (!fn_rv) fn_rv = dlsym(RTLD_DEFAULT, "process_vm_readv");
        if (fn_rv) {
            DobbyHook(fn_rv, (void*)hook_pvm_readv, (void**)&orig_pvm_readv);
            LI("L58 process_vm_readv blocked");
        } else {
            LE("L58 process_vm_readv not found in libc");
        }

        void *fn_wv = DobbySymbolResolver("libc.so", "process_vm_writev");
        if (!fn_wv) fn_wv = dlsym(RTLD_DEFAULT, "process_vm_writev");
        if (fn_wv) {
            DobbyHook(fn_wv, (void*)hook_pvm_writev, (void**)&orig_pvm_writev);
            LI("L58 process_vm_writev blocked");
        } else {
            LE("L58 process_vm_writev not found in libc");
        }
    }

    // Layers 59 + 61 — io_uring + pidfd via syscall() chain hook
    {
        void *fn = DobbySymbolResolver("libc.so", "syscall");
        if (!fn) fn = dlsym(RTLD_DEFAULT, "syscall");
        if (fn) {
            DobbyHook(fn, (void*)hook_syscall8, (void**)&orig_syscall8);
            LI("L59/L61 io_uring + pidfd syscall chain active");
        } else {
            LE("L59/L61 syscall() not found");
        }
    }

    // Layer 60 — /proc/net/* fd tracker (openat + close + read chain)
    {
        void *h = dlopen("libc.so", RTLD_LAZY | RTLD_NOLOAD);
        if (!h) h = RTLD_DEFAULT;

        void *fn_oa = DobbySymbolResolver("libc.so", "openat");
        if (!fn_oa) fn_oa = dlsym(h, "openat");
        if (fn_oa) {
            DobbyHook(fn_oa, (void*)hook_openat8, (void**)&orig_openat8);
            LI("L60 openat chain active for /proc/net tracking");
        } else {
            LE("L60 openat not found");
        }

        void *fn_cl = DobbySymbolResolver("libc.so", "close");
        if (!fn_cl) fn_cl = dlsym(h, "close");
        if (fn_cl) {
            DobbyHook(fn_cl, (void*)hook_close8, (void**)&orig_close8);
            LI("L60 close chain active");
        } else {
            LE("L60 close not found");
        }

        void *fn_rd = DobbySymbolResolver("libc.so", "read");
        if (!fn_rd) fn_rd = dlsym(h, "read");
        if (fn_rd) {
            DobbyHook(fn_rd, (void*)hook_read8, (void**)&orig_read8);
            LI("L60 read chain active for /proc/net sanitizer");
        } else {
            LE("L60 read not found");
        }
    }

    // Layer 62 — sendfile / sendfile64 blocker
    {
        void *fn = DobbySymbolResolver("libc.so", "sendfile");
        if (!fn) fn = dlsym(RTLD_DEFAULT, "sendfile");
        if (fn) {
            DobbyHook(fn, (void*)hook_sendfile, (void**)&orig_sendfile);
            LI("L62 sendfile /proc clone blocker active");
        } else {
            LE("L62 sendfile not found");
        }
        // sendfile64 is an alias on arm64 — same underlying symbol, skip dedup
    }

    LI("Layers 58-62 installed OK");
}
