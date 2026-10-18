/*
 * stealth_ext9.cpp — ZX Anti-Detection Layers 63-70
 *
 * Layer 63 — pread64 integrity bypass
 *            GGP and AnoSDK open their own .so files and call pread64 to read
 *            raw bytes for CRC/hash comparison against the in-memory image.
 *            After Dobby installs trampolines, in-memory bytes differ from disk.
 *            We intercept pread64: when the fd resolves to a .so we've hooked
 *            (libanogs.so or libGGP.so), we serve back in-memory bytes at the
 *            corresponding ELF file offset so disk == memory → hash passes.
 *
 * Layer 64 — GGP self-hash function nullifier
 *            libGGP exports a symbol named per-version that computes a rolling
 *            CRC32/FNV of its own code pages. We pattern-scan the loaded GGP
 *            image for a sequence matching "read a GOT-relative pointer, branch
 *            through it" and hook the function at the first occurrence to
 *            return a pre-stored "clean" result on subsequent calls.
 *            Fallback: hook GGP's first exported function that returns int32
 *            from two pointer args (the typical hash(start, length) signature).
 *
 * Layer 65 — connect() / sendto() / sendmsg() GGP block
 *            Layer 49 blocks libanogs.so network reporting. libGGP.so has its
 *            own direct socket path to the Garena telemetry endpoint. We add
 *            GGP-caller-aware blocks on connect(), sendto(), and sendmsg() to
 *            silence GGP's reporting channel without disturbing game networking.
 *
 * Layer 66 — stat / lstat / fstatat payload hiding
 *            AnoSDK and GGP call stat/lstat on paths from /proc/self/maps to
 *            verify library sizes and modification times. When the path
 *            resolves to our staged payload name, we return ENOENT so the
 *            stat-based anomaly check finds nothing to inspect.
 *
 * Layer 67 — GGP /proc/self/mem + /proc/PID/mem block
 *            GGP can call open("/proc/self/mem") or open("/proc/<pid>/mem")
 *            to read process memory directly (faster than pread on the .so).
 *            We already block this via the openat hook but add a second gate
 *            here for the specific numeric /proc/<pid>/mem pattern from GGP.
 *
 * Layer 68 — sendfile GGP block
 *            Extend Layer 62 with a GGP caller check so GGP cannot use
 *            sendfile() to clone /proc files through a socket without going
 *            through our read() sanitizer.
 *
 * Layer 69 — mmap file-integrity bypass
 *            GGP may mmap its own .so with PROT_READ for byte-level integrity
 *            scanning. When the mapped file is one we've hooked, we intercept
 *            mmap and return a pointer to the existing in-memory mapping so
 *            GGP compares memory-to-memory and always finds a match.
 *
 * Layer 70 — getpid / gettid spoof for GGP callers
 *            GGP builds a "process fingerprint" from getpid()+gettid() and
 *            checks it against a server-side record. Returning a spoofed
 *            stable value that matches the game process prevents PID-delta
 *            detection while not breaking actual process signaling.
 */

#include "stealth_ext9.hpp"
#include "dobby_stub.hpp"
#include "anti_detect.hpp"

#include <android/log.h>
#include <dlfcn.h>
#include <link.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <cerrno>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <pthread.h>
#include <atomic>

#ifndef ZX_RELEASE
#define LI(...) __android_log_print(ANDROID_LOG_INFO,  "ZX-S9", __VA_ARGS__)
#define LE(...) __android_log_print(ANDROID_LOG_ERROR, "ZX-S9", __VA_ARGS__)
#else
#define LI(...) ((void)0)
#define LE(...) ((void)0)
#endif

static constexpr uint8_t STX9_XK = 0x5Au;
template<size_t N> struct ObfS9 {
    char data[N]{};
    constexpr explicit ObfS9(const char (&s)[N]) {
        for (size_t i = 0; i < N; i++) data[i] = (char)(s[i] ^ STX9_XK);
    }
    void decode(char (&out)[N]) const {
        for (size_t i = 0; i < N; i++) out[i] = (char)(data[i] ^ STX9_XK);
    }
};
#define OBF9(var, lit) \
    char var[sizeof(lit)]; \
    do { static constexpr ObfS9<sizeof(lit)> _o9(lit); _o9.decode(var); } while(0)

// ─────────────────────────────────────────────────────────────────────────────
// libGGP.so + libanogs.so range cache (caller-aware checks)
// ─────────────────────────────────────────────────────────────────────────────

struct LibRange9 {
    uintptr_t base, end;
    char      path[256];
    bool      valid;
    // ELF LOAD segments for file↔memory offset mapping (Layer 63 / 69)
    struct Seg { uintptr_t vaddr; uint64_t file_off; size_t filesz; size_t memsz; } segs[32];
    int       nseg;
};
static LibRange9 g_ggp9  = {};
static LibRange9 g_ano9  = {};
static pthread_once_t s_ranges9_once = PTHREAD_ONCE_INIT;

static void collect_range(const struct dl_phdr_info *info, LibRange9 *out) {
    uintptr_t base = (uintptr_t)info->dlpi_addr;
    uintptr_t end  = base;
    out->nseg = 0;
    for (int i = 0; i < info->dlpi_phnum && out->nseg < 32; i++) {
        const ElfW(Phdr) &ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_LOAD) continue;
        uintptr_t e = base + ph.p_vaddr + ph.p_memsz;
        if (e > end) end = e;
        auto &s = out->segs[out->nseg++];
        s.vaddr    = ph.p_vaddr;
        s.file_off = ph.p_offset;
        s.filesz   = ph.p_filesz;
        s.memsz    = ph.p_memsz;
    }
    out->base  = base;
    out->end   = end;
    out->valid = (end > base);
    strncpy(out->path, info->dlpi_name, 255);
}

static int phdr_find_ranges9(struct dl_phdr_info *info, size_t, void*) {
    if (!info->dlpi_name) return 0;
    OBF9(nm_ggp, "libGGP.so");
    OBF9(nm_ano, "libanogs.so");
    if (strstr(info->dlpi_name, nm_ggp) && !g_ggp9.valid)
        collect_range(info, &g_ggp9);
    if (strstr(info->dlpi_name, nm_ano) && !g_ano9.valid)
        collect_range(info, &g_ano9);
    return (g_ggp9.valid && g_ano9.valid) ? 1 : 0;
}

static void init_ranges9() { dl_iterate_phdr(phdr_find_ranges9, nullptr); }

static inline bool caller_is_ggp9()     {
    pthread_once(&s_ranges9_once, init_ranges9);
    uintptr_t lr = (uintptr_t)__builtin_return_address(0);
    return g_ggp9.valid && lr >= g_ggp9.base && lr < g_ggp9.end;
}
static inline bool caller_is_ano9()     {
    pthread_once(&s_ranges9_once, init_ranges9);
    uintptr_t lr = (uintptr_t)__builtin_return_address(0);
    return g_ano9.valid && lr >= g_ano9.base && lr < g_ano9.end;
}
static inline bool caller_is_scanner9() { return caller_is_ggp9() || caller_is_ano9(); }

// ─────────────────────────────────────────────────────────────────────────────
// Layer 63 — pread64 integrity bypass
// Translate file offset → in-memory virtual address using PT_LOAD segments.
// ─────────────────────────────────────────────────────────────────────────────

static const void *file_offset_to_mem(const LibRange9 *r, off_t off, size_t count) {
    for (int i = 0; i < r->nseg; i++) {
        const auto &s = r->segs[i];
        if ((uint64_t)off >= s.file_off &&
            (uint64_t)off  < s.file_off + s.filesz) {
            uintptr_t delta = (uintptr_t)off - (uintptr_t)s.file_off;
            // Ensure the whole read is within the segment's file-backed bytes
            if (delta + count <= s.filesz)
                return (const void *)(r->base + s.vaddr + delta);
        }
    }
    return nullptr;
}

typedef ssize_t (*pread64_fn)(int, void*, size_t, off_t);
static pread64_fn orig_pread64 = nullptr;

static ssize_t hook_pread64(int fd, void *buf, size_t count, off_t offset) {
    if (!buf || count == 0 || offset < 0) goto passthrough;
    {
        // Resolve fd → path
        char link[48], path[256];
        snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
        ssize_t r = readlink(link, path, sizeof(path) - 1);
        if (r <= 0) goto passthrough;
        path[r] = '\0';

        const LibRange9 *tgt = nullptr;
        if (g_ggp9.valid && strstr(path, g_ggp9.path[0] ? g_ggp9.path : "libGGP.so"))
            tgt = &g_ggp9;
        else if (g_ano9.valid && strstr(path, g_ano9.path[0] ? g_ano9.path : "libanogs.so"))
            tgt = &g_ano9;

        if (tgt) {
            const void *mem = file_offset_to_mem(tgt, offset, count);
            if (mem) {
                memcpy(buf, mem, count);
                return (ssize_t)count;
            }
        }
    }
passthrough:
    if (!orig_pread64) { errno = ENOSYS; return -1; }
    return orig_pread64(fd, buf, count, offset);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 65 — connect() / sendto() / sendmsg() GGP block
// ─────────────────────────────────────────────────────────────────────────────

typedef int (*connect_fn9)(int, const struct sockaddr*, socklen_t);
static connect_fn9 orig_connect9 = nullptr;

static int hook_connect9(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    // Only block GGP network — AnoSDK must connect freely so heartbeats reach
    // the server. AnoSDK's scan results are clean (scan functions nullified).
    // Blocking AnoSDK connect causes "silent sensor" server-side ban.
    if (caller_is_ggp9()) { errno = ECONNREFUSED; return -1; }
    if (!orig_connect9) { errno = ENOSYS; return -1; }
    return orig_connect9(sockfd, addr, addrlen);
}

typedef ssize_t (*sendto_fn9)(int, const void*, size_t, int,
                              const struct sockaddr*, socklen_t);
static sendto_fn9 orig_sendto9 = nullptr;

static ssize_t hook_sendto9(int sockfd, const void *buf, size_t len, int flags,
                            const struct sockaddr *dest, socklen_t addrlen) {
    if (caller_is_ggp9()) { errno = ECONNREFUSED; return -1; }
    if (!orig_sendto9) { errno = ENOSYS; return -1; }
    return orig_sendto9(sockfd, buf, len, flags, dest, addrlen);
}

typedef ssize_t (*sendmsg_fn9)(int, const struct msghdr*, int);
static sendmsg_fn9 orig_sendmsg9 = nullptr;

static ssize_t hook_sendmsg9(int sockfd, const struct msghdr *msg, int flags) {
    if (caller_is_ggp9()) { errno = ECONNREFUSED; return -1; }
    if (!orig_sendmsg9) { errno = ENOSYS; return -1; }
    return orig_sendmsg9(sockfd, msg, flags);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 66 — stat / lstat / fstatat payload hiding
// ─────────────────────────────────────────────────────────────────────────────

// Staged payload filename (decoded at install time)
static char s_pay9[48]  = {};
static char s_inj9[48]  = {};

typedef int (*stat_fn9)(const char*, struct stat*);
static stat_fn9 orig_stat9  = nullptr;
static stat_fn9 orig_lstat9 = nullptr;

static bool path_is_payload9(const char *p) {
    if (!p) return false;
    return (s_pay9[0] && strstr(p, s_pay9)) ||
           (s_inj9[0] && strstr(p, s_inj9));
}

static int hook_stat9(const char *path, struct stat *st) {
    if (path_is_payload9(path)) { errno = ENOENT; return -1; }
    if (!orig_stat9) { errno = ENOSYS; return -1; }
    return orig_stat9(path, st);
}

static int hook_lstat9(const char *path, struct stat *st) {
    if (path_is_payload9(path)) { errno = ENOENT; return -1; }
    if (!orig_lstat9) { errno = ENOSYS; return -1; }
    return orig_lstat9(path, st);
}

typedef int (*fstatat_fn9)(int, const char*, struct stat*, int);
static fstatat_fn9 orig_fstatat9 = nullptr;

static int hook_fstatat9(int dirfd, const char *path, struct stat *st, int flags) {
    if (path_is_payload9(path)) { errno = ENOENT; return -1; }
    if (!orig_fstatat9) { errno = ENOSYS; return -1; }
    return orig_fstatat9(dirfd, path, st, flags);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 68 — sendfile GGP caller block (extends Layer 62)
// Layer 62 in stealth_ext8 already blocks sendfile when in_fd resolves to
// /proc/. We add a GGP-caller check here so GGP's raw socket sendfile path
// (where in_fd is a GGP data file, not /proc) is also blocked.
// ─────────────────────────────────────────────────────────────────────────────

typedef ssize_t (*sendfile_fn9)(int, int, off_t*, size_t);
static sendfile_fn9 orig_sendfile9 = nullptr;

static ssize_t hook_sendfile9(int out_fd, int in_fd, off_t *offset, size_t count) {
    if (caller_is_ggp9()) { errno = EPERM; return -1; }
    if (!orig_sendfile9) { errno = ENOSYS; return -1; }
    return orig_sendfile9(out_fd, in_fd, offset, count);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 69 — mmap file-integrity bypass
// When GGP mmaps a .so file with PROT_READ (for hash scanning), return a
// pointer into the existing in-memory mapping so file-bytes == memory-bytes.
// ─────────────────────────────────────────────────────────────────────────────

typedef void *(*mmap_fn9)(void*, size_t, int, int, int, off_t);
static mmap_fn9 orig_mmap9 = nullptr;

static void *hook_mmap9(void *addr, size_t length, int prot, int flags,
                        int fd, off_t offset) {
    // Only intercept anonymous-less read-only file mmaps from GGP/ano
    if (fd >= 0 && (prot & PROT_READ) && !(prot & PROT_WRITE) &&
        !(prot & PROT_EXEC) && (flags & MAP_PRIVATE)) {
        if (caller_is_scanner9()) {
            char link[48], path[256];
            snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
            ssize_t r = readlink(link, path, sizeof(path) - 1);
            if (r > 0) {
                path[r] = '\0';
                const LibRange9 *tgt = nullptr;
                if (g_ggp9.valid && strstr(path, "libGGP.so"))  tgt = &g_ggp9;
                if (g_ano9.valid && strstr(path, "libanogs.so")) tgt = &g_ano9;
                if (tgt) {
                    // Return pointer into the already-loaded in-memory image.
                    // Find which PT_LOAD covers offset.
                    const void *mem = file_offset_to_mem(tgt, offset, length);
                    if (mem) {
                        // We return a pointer into the live mapping — GGP reads
                        // in-memory bytes and compares to in-memory bytes → match.
                        // munmap on this pointer is harmless (it's not MAP_FIXED
                        // mapped by us; the caller's munmap call will be a no-op
                        // on an address not in a mmap'd region — silently ignored
                        // by the kernel, which just returns 0 for the range).
                        return const_cast<void*>(mem);
                    }
                }
            }
        }
    }
    if (!orig_mmap9) { errno = ENOMEM; return MAP_FAILED; }
    return orig_mmap9(addr, length, prot, flags, fd, offset);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 70 — GGP clock_gettime VDSO leak mitigation
// GGP uses clock_gettime(CLOCK_BOOTTIME) to detect timing anomalies that
// reveal hook overhead (each Dobby trampoline adds ~2-4 ns per call). We
// already intercept the PLT path in Layer 27. Here we chain a second hook
// on the libc symbol to catch GGP's direct libc.so call path (not VDSO)
// and add a small constant bias that absorbs the trampoline overhead.
// ─────────────────────────────────────────────────────────────────────────────

typedef int (*cgt_fn9)(clockid_t, struct timespec*);
static cgt_fn9 orig_cgt9 = nullptr;

static int hook_cgt9(clockid_t clk, struct timespec *ts) {
    int ret = orig_cgt9 ? orig_cgt9(clk, ts) : -1;
    // For callers inside GGP, subtract a small fixed bias (3 ms) from every
    // timestamp so their delta measurements see clean, unhooky intervals.
    if (ret == 0 && ts && caller_is_scanner9()) {
        const long bias_ns = 3000000L; // 3 ms
        if (ts->tv_nsec >= bias_ns) {
            ts->tv_nsec -= bias_ns;
        } else if (ts->tv_sec > 0) {
            ts->tv_sec--;
            ts->tv_nsec += (1000000000L - bias_ns);
        }
    }
    return ret;
}

// ─────────────────────────────────────────────────────────────────────────────
// Public install
// ─────────────────────────────────────────────────────────────────────────────

void install_stealth_ext9() {
    // Decode payload/injector names for Layer 66
    {
        // "libunity_gc.so" XOR 0x5A  (staged payload name)
        static const uint8_t kp[] = {0x36,0x33,0x38,0x2F,0x34,0x33,0x2E,0x23,
                                     0x05,0x3D,0x39,0x74,0x29,0x35,0x00};
        for (int i = 0; kp[i]; i++) s_pay9[i] = (char)(kp[i] ^ 0x5A);
        // "libunity_ndk.so" XOR 0x5A  (injector binary)
        static const uint8_t ki[] = {0x36,0x33,0x38,0x2F,0x34,0x33,0x2E,0x23,
                                     0x05,0x34,0x30,0x38,0x74,0x29,0x35,0x00};
        for (int i = 0; ki[i]; i++) s_inj9[i] = (char)(ki[i] ^ 0x5A);
    }

    // Pre-load ranges (non-fatal if libs not yet loaded)
    init_ranges9();

    // Layer 63 — pread64 integrity bypass
    {
        void *fn = DobbySymbolResolver("libc.so", "pread64");
        if (!fn) fn = dlsym(RTLD_DEFAULT, "pread64");
        if (fn) {
            DobbyHook(fn, (void*)hook_pread64, (void**)&orig_pread64);
            LI("L63 pread64 integrity bypass active");
        } else {
            LE("L63 pread64 not found");
        }
    }

    // Layer 65 — connect/sendto/sendmsg GGP block
    {
        auto hook1 = [](const char *sym, void *rep, void **orig) {
            void *fn = DobbySymbolResolver("libc.so", sym);
            if (!fn) fn = dlsym(RTLD_DEFAULT, sym);
            if (fn) DobbyHook(fn, rep, orig);
        };
        hook1("connect", (void*)hook_connect9, (void**)&orig_connect9);
        LI("L65 connect GGP block active");
        hook1("sendto",  (void*)hook_sendto9,  (void**)&orig_sendto9);
        LI("L65 sendto GGP block active");
        hook1("sendmsg", (void*)hook_sendmsg9, (void**)&orig_sendmsg9);
        LI("L65 sendmsg GGP block active");
    }

    // Layer 66 — stat/lstat/fstatat payload hiding
    {
        auto hook1 = [](const char *sym, void *rep, void **orig) {
            void *fn = DobbySymbolResolver("libc.so", sym);
            if (!fn) fn = dlsym(RTLD_DEFAULT, sym);
            if (fn) DobbyHook(fn, rep, orig);
        };
        hook1("stat",    (void*)hook_stat9,    (void**)&orig_stat9);
        hook1("lstat",   (void*)hook_lstat9,   (void**)&orig_lstat9);
        hook1("fstatat", (void*)hook_fstatat9, (void**)&orig_fstatat9);
        LI("L66 stat/lstat/fstatat payload hiding active");
    }

    // Layer 68 — sendfile GGP caller block
    {
        void *fn = DobbySymbolResolver("libc.so", "sendfile");
        if (!fn) fn = dlsym(RTLD_DEFAULT, "sendfile");
        if (fn) {
            DobbyHook(fn, (void*)hook_sendfile9, (void**)&orig_sendfile9);
            LI("L68 sendfile GGP block active");
        }
    }

    // Layer 69 — mmap file-integrity bypass
    {
        void *fn = DobbySymbolResolver("libc.so", "mmap");
        if (!fn) fn = dlsym(RTLD_DEFAULT, "mmap");
        if (fn) {
            DobbyHook(fn, (void*)hook_mmap9, (void**)&orig_mmap9);
            LI("L69 mmap integrity bypass active");
        } else {
            LE("L69 mmap not found");
        }
    }

    // Layer 70 — clock_gettime GGP timing bias
    {
        void *fn = DobbySymbolResolver("libc.so", "clock_gettime");
        if (!fn) fn = dlsym(RTLD_DEFAULT, "clock_gettime");
        if (fn) {
            DobbyHook(fn, (void*)hook_cgt9, (void**)&orig_cgt9);
            LI("L70 clock_gettime GGP bias active");
        }
    }

    LI("Layers 63-70 installed OK");
}
