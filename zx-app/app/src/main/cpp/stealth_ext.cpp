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
#include "dobby_stub.hpp"
#include "anti_detect.hpp"
#include <android/log.h>
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
#ifndef __NR_openat
#define __NR_openat 56
#endif
#include <pthread.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cerrno>
#include <atomic>

#define TAG "ZX-STX"
#ifndef ZX_RELEASE
#define LI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#else
#define LI(...) ((void)0)
#define LE(...) ((void)0)
#endif

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

struct PhdrWrap { FnPhdrCb real_cb; void *real_data; };

static int zx_phdr_filter(dl_phdr_info *info, size_t sz, void *data) {
    auto *w = static_cast<PhdrWrap*>(data);
    if (info && info->dlpi_name) {
        const char *n = info->dlpi_name;
        // Hide our modules — short prefix check avoids OBF_DECODE in callback
        if (strstr(n, "zx_") || strstr(n, "ZX_"))
            return 0;
    }
    return w->real_cb(info, sz, w->real_data);
}

static int hook_dl_iterate_phdr(FnPhdrCb cb, void *data) {
    if (!g_orig_iter_phdr || !cb) return 0;
    PhdrWrap w{ cb, data };
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
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return;

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
            __builtin___clear_cache(p, p + 8);
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

    // ── Layer 7a — dl_iterate_phdr ──────────────────────────────────────────
    if (libc) hk_libc(libc, "dl_iterate_phdr",
        (void*)hook_dl_iterate_phdr, (void**)&g_orig_iter_phdr);

    // ── Layer 7b — dlopen ───────────────────────────────────────────────────
    if (libc) hk_libc(libc, "dlopen",
        (void*)hook_dlopen, (void**)&g_orig_dlopen);

    // ── Layer 7c — AnoSDK missing exports ──────────────────────────────────
    if (ano) install_ano_missing(ano, ano_name);

    // ── Layer 8 — /proc/self/fd spoofing ───────────────────────────────────
    for (int i = 0; i < MAX_FD_DIRS; i++) g_fd_dirs[i].store(0);
    if (libc) {
        hk_libc(libc, "opendir",  (void*)hook_opendir,  (void**)&g_orig_opendir);
        hk_libc(libc, "closedir", (void*)hook_closedir, (void**)&g_orig_closedir);
        hk_libc(libc, "readdir",  (void*)hook_readdir,  (void**)&g_orig_readdir);
        hk_libc(libc, "readlink", (void*)hook_readlink, (void**)&g_orig_readlink);
        LI("L8 /proc/self/fd spoof installed");
    }

    // ── Layer 9 — inotify nullifier ─────────────────────────────────────────
    if (libc) {
        hk_libc(libc, "inotify_init",     (void*)hook_inotify_init, (void**)&g_orig_inotify_init);
        hk_libc(libc, "inotify_add_watch",(void*)hook_inotify_add,  (void**)&g_orig_inotify_add);
        LI("L9 inotify nullifier installed");
    }

    // ── Layer 10 — popen gate + access filter ───────────────────────────────
    if (libc) {
        hk_libc(libc, "popen",  (void*)hook_popen,  (void**)&g_orig_popen);
        hk_libc(libc, "access", (void*)hook_access, (void**)&g_orig_access);
        LI("L10 popen gate + access filter installed");
    }

    // ── Layer 11 — MADV_DONTDUMP + prctl ────────────────────────────────────
    install_anti_dump();

    // ── Layer 12 — watchdog + trampoline rotation ───────────────────────────
    start_watchdog();

    LI("stealth_ext: Layers 7–12 active (6 extra layers beyond ZOLAM)");
}
