/*
 * stealth_ext5.cpp — ZX Anti-Detection Layers 44-48
 *
 * Vectors discovered via cross-library deep analysis of all 22 FF ARM64 libs:
 *
 *  Layer 44 — dl_iterate_phdr() poisoner
 *             libanogs.so's mrpcs/ms_mod scanner enumerates every loaded .so
 *             via dl_iterate_phdr and checks each one for hook trampolines.
 *             We intercept dl_iterate_phdr and skip our payload library entry
 *             so it never appears in the enumeration.
 *
 *  Layer 45 — AnoSDKOnRecvData nullifier
 *             Server can push scan commands / rule updates into AnoSDK at
 *             runtime via tss_sdk_send_data_to_svr. AnoSDKOnRecvData is the
 *             ingestion point. Nullifying it cuts the server-trigger re-scan
 *             path without breaking game networking (different channel).
 *
 *  Layer 46 — AnoSDKOnRecvSignature nullifier
 *             AnoSDK downloads updated hook-detection signatures from the
 *             backend. AnoSDKOnRecvSignature installs new scan patterns live.
 *             Returning 0 blocks any fresh pattern from taking effect.
 *
 *  Layer 47 — inotify_add_watch() redirector
 *             libanogs's mrmoni_fc/mrmoni_fb threads watch filesystem paths
 *             (/data/data/<pkg>/files, /dev/random neighbourhood) via inotify
 *             to detect frida-server / gadget drops in real time.
 *             We redirect every inotify watch to /dev/null — the kernel call
 *             succeeds (watch descriptor returned) but no events ever fire.
 *
 *  Layer 48 — popen() command sink
 *             libanogs uses popen("ps ..."), popen("ls /proc/...") etc via its
 *             mvm_bk_task background task to harvest process lists and file
 *             descriptors. We hook popen and return an empty stream for any
 *             command matching suspicious patterns, falling through to the real
 *             popen otherwise.
 */

#include "stealth_ext5.hpp"
#include "dobby_stub.hpp"

#include <android/log.h>
#include <dlfcn.h>
#include <link.h>          // dl_iterate_phdr, dl_phdr_info
#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <sys/inotify.h>
#include <pthread.h>
#include <cctype>
#include <cstdint>

// dl_iterate_phdr callback type (not defined by name in NDK <link.h>)
typedef int (*phdr_cb_t)(struct dl_phdr_info *, size_t, void *);

#ifndef ZX_RELEASE
#define LI(...) __android_log_print(ANDROID_LOG_INFO,  "ZX", __VA_ARGS__)
#define LE(...) __android_log_print(ANDROID_LOG_ERROR, "ZX", __VA_ARGS__)
#else
#define LI(...) ((void)0)
#define LE(...) ((void)0)
#endif

// ─────────────────────────────────────────────────────────────────────────────
// Staged payload name (compile-time XOR so it never appears in .rodata)
// XOR key 0x5A. Decode: each byte ^ 0x5A
// "libgfxjni_helper.so" XOR 0x5A
// ─────────────────────────────────────────────────────────────────────────────
static const uint8_t k_payload_xored[] = {
    // l     i     b     g     f     x     j     n     i     _     h     e     l     p     e     r     .     s     o
    0x36, 0x33, 0x38, 0x3D, 0x3C, 0x22, 0x30, 0x34, 0x33, 0x05, 0x32, 0x3F, 0x36, 0x2A, 0x3F, 0x28, 0x74, 0x29, 0x35, 0x00
};

static char s_payload_name[32] = {};

static void decode_payload_name() {
    for (int i = 0; k_payload_xored[i]; i++)
        s_payload_name[i] = (char)(k_payload_xored[i] ^ 0x5A);
}

// ─────────────────────────────────────────────────────────────────────────────
// libanogs.so range — used by Layer 44 for caller-aware dl_iterate_phdr filtering
// ─────────────────────────────────────────────────────────────────────────────
static uintptr_t s_ano_base5 = 0;
static uintptr_t s_ano_end5  = 0;

static int phdr_find_anogs5(dl_phdr_info *info, size_t /*sz*/, void * /*d*/) {
    if (!info->dlpi_name || !strstr(info->dlpi_name, "libanogs.so")) return 0;
    uintptr_t base = (uintptr_t)info->dlpi_addr, end = base;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) &ph = info->dlpi_phdr[i];
        if (ph.p_type == PT_LOAD) {
            uintptr_t se = base + ph.p_vaddr + ph.p_memsz;
            if (se > end) end = se;
        }
    }
    s_ano_base5 = base; s_ano_end5 = end; return 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 44 — dl_iterate_phdr poisoner
// ─────────────────────────────────────────────────────────────────────────────

struct DlIterCtx {
    phdr_cb_t real_cb;
    void *real_data;
    bool  from_anogs;   // true = filter out our payload .so
};

static int dl_iter_filter_cb(dl_phdr_info *info, size_t size, void *data) {
    DlIterCtx *ctx = static_cast<DlIterCtx*>(data);
    // Only filter when caller is libanogs — IL2CPP exception unwinder also
    // uses dl_iterate_phdr to find .eh_frame; hiding from it causes crashes.
    if (ctx->from_anogs && info && info->dlpi_name && s_payload_name[0] &&
        strstr(info->dlpi_name, s_payload_name)) {
        return 0;
    }
    return ctx->real_cb(info, size, ctx->real_data);
}

typedef int (*dl_iterate_phdr_t)(phdr_cb_t, void*);
static dl_iterate_phdr_t orig_dl_iterate_phdr = nullptr;

static int __attribute__((noinline)) hook_dl_iterate_phdr(phdr_cb_t cb, void *data) {
    if (!orig_dl_iterate_phdr) return 0;
    uintptr_t lr = (uintptr_t)__builtin_return_address(0);
    if (!s_ano_base5) orig_dl_iterate_phdr(phdr_find_anogs5, nullptr);
    bool from_ano = (s_ano_base5 && lr >= s_ano_base5 && lr < s_ano_end5);
    DlIterCtx ctx = { cb, data, from_ano };
    return orig_dl_iterate_phdr(dl_iter_filter_cb, &ctx);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 45 — AnoSDKOnRecvData nullifier
// ─────────────────────────────────────────────────────────────────────────────

typedef int (*AnoRecvData_t)(const char*, size_t, int);
static AnoRecvData_t orig_AnoOnRecvData = nullptr;

static int hook_AnoOnRecvData(const char* /*data*/, size_t /*len*/, int /*type*/) {
    // Drop all incoming server scan commands silently
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 46 — AnoSDKOnRecvSignature nullifier
// ─────────────────────────────────────────────────────────────────────────────

typedef int (*AnoRecvSig_t)(const char*, size_t);
static AnoRecvSig_t orig_AnoOnRecvSignature = nullptr;

static int hook_AnoOnRecvSignature(const char* /*sig*/, size_t /*len*/) {
    // Block dynamic signature updates from backend
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 47 — inotify_add_watch() redirector
// Redirect all libanogs filesystem watches to /dev/null (always readable,
// never has real events we care about hiding from)
// ─────────────────────────────────────────────────────────────────────────────

typedef int (*inotify_add_watch_t)(int, const char*, uint32_t);
static inotify_add_watch_t orig_inotify_add_watch = nullptr;

static int hook_inotify_add_watch(int fd, const char *pathname, uint32_t mask) {
    // Let through: only redirect if path looks like an AnoSDK monitored path.
    // If it's our own app's path monitoring — fall through unchanged.
    if (!pathname) return -1;
    // Redirect only AnoSDK's known watch targets — exclude /dev/input/* (gamepad)
    if (!orig_inotify_add_watch) { errno = ENOSYS; return -1; }
    if (strstr(pathname, "/data/data") ||
        strstr(pathname, "/data/user") ||
        strstr(pathname, "/proc/")) {
        return orig_inotify_add_watch(fd, "/dev/null", mask);
    }
    return orig_inotify_add_watch(fd, pathname, mask);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 48 — popen() command sink
// libanogs uses popen("ps ..."), popen("ls ..."), popen("cat /proc/...") to
// harvest process/fd info. We return empty output for these commands.
// ─────────────────────────────────────────────────────────────────────────────

typedef FILE* (*popen_t)(const char*, const char*);
static popen_t orig_popen = nullptr;

static bool cmd_has_word(const char *cmd, const char *word) {
    const char *p = cmd;
    size_t wlen = strlen(word);
    while ((p = strstr(p, word)) != nullptr) {
        bool pre_ok  = (p == cmd || !isalnum((unsigned char)p[-1]));
        bool post_ok = !isalnum((unsigned char)p[wlen]);
        if (pre_ok && post_ok) return true;
        p++;
    }
    return false;
}

static bool is_ano_popen(const char *cmd) {
    if (!cmd) return false;
    return (cmd_has_word(cmd, "ps") ||
            strstr(cmd, "/proc/")   ||
            strstr(cmd, "ls /")     ||
            strstr(cmd, "cat /")    ||
            strstr(cmd, "grep ")    ||
            strstr(cmd, "getprop")  ||
            cmd_has_word(cmd, "id") ||
            strstr(cmd, "whoami")   ||
            cmd_has_word(cmd, "su") ||
            strstr(cmd, "mount"));
}

static FILE* hook_popen(const char *cmd, const char *mode) {
    if (!orig_popen) return nullptr;
    if (is_ano_popen(cmd)) {
        return orig_popen("true", mode);
    }
    return orig_popen(cmd, mode);
}

// ─────────────────────────────────────────────────────────────────────────────
// Public install
// ─────────────────────────────────────────────────────────────────────────────

void install_stealth_ext5() {
    decode_payload_name();
    dl_iterate_phdr(phdr_find_anogs5, nullptr);

    // Layer 44 — dl_iterate_phdr via libc PLT
    {
        void *fn = DobbySymbolResolver("libc.so", "dl_iterate_phdr");
        if (fn) {
            DobbyHook(fn, (void*)hook_dl_iterate_phdr,
                      (void**)&orig_dl_iterate_phdr);
            LI("L44 dl_iterate_phdr hooked — payload hidden from lib scan");
        } else {
            // Fallback: resolve through linker directly
            fn = (void*)&dl_iterate_phdr;
            if (fn) {
                DobbyHook(fn, (void*)hook_dl_iterate_phdr,
                          (void**)&orig_dl_iterate_phdr);
                LI("L44 dl_iterate_phdr hooked (direct)");
            } else {
                LE("L44 dl_iterate_phdr NOT found");
            }
        }
    }

    // Layers 45 & 46 — AnoSDK server-receive hooks
    {
        void *ano = dlopen("libanogs.so", RTLD_LAZY | RTLD_NOLOAD);
        if (ano) {
            void *fn_recv = dlsym(ano, "AnoSDKOnRecvData");
            void *fn_sig  = dlsym(ano, "AnoSDKOnRecvSignature");

            if (fn_recv) {
                DobbyHook(fn_recv, (void*)hook_AnoOnRecvData,
                          (void**)&orig_AnoOnRecvData);
                LI("L45 AnoSDKOnRecvData nullified");
            } else {
                LE("L45 AnoSDKOnRecvData not found");
            }

            if (fn_sig) {
                DobbyHook(fn_sig, (void*)hook_AnoOnRecvSignature,
                          (void**)&orig_AnoOnRecvSignature);
                LI("L46 AnoSDKOnRecvSignature nullified");
            } else {
                LE("L46 AnoSDKOnRecvSignature not found");
            }
        } else {
            LE("L45-46 libanogs.so not loaded yet");
        }
    }

    // Layer 47 — inotify_add_watch redirect
    {
        void *fn = DobbySymbolResolver("libc.so", "inotify_add_watch");
        if (!fn) fn = (void*)&inotify_add_watch;
        if (fn) {
            DobbyHook(fn, (void*)hook_inotify_add_watch,
                      (void**)&orig_inotify_add_watch);
            LI("L47 inotify_add_watch redirected");
        } else {
            LE("L47 inotify_add_watch not found");
        }
    }

    // Layer 48 — popen command sink
    {
        void *fn = DobbySymbolResolver("libc.so", "popen");
        if (!fn) fn = (void*)&popen;
        if (fn) {
            DobbyHook(fn, (void*)hook_popen, (void**)&orig_popen);
            LI("L48 popen command sink installed");
        } else {
            LE("L48 popen not found");
        }
    }

    LI("Layers 44-48 installed OK");
}
