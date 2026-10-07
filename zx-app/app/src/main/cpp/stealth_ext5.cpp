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
#include <sys/inotify.h>
#include <pthread.h>

#ifndef ZX_RELEASE
#define LI(...) __android_log_print(ANDROID_LOG_INFO,  "ZX", __VA_ARGS__)
#define LE(...) __android_log_print(ANDROID_LOG_ERROR, "ZX", __VA_ARGS__)
#else
#define LI(...) ((void)0)
#define LE(...) ((void)0)
#endif

// ─────────────────────────────────────────────────────────────────────────────
// Payload library name (compile-time XOR so it never appears in .rodata)
// XOR key 0x5A. Decode: each byte ^ 0x5A
// "libzx_payload.so" XOR 0x5A
// ─────────────────────────────────────────────────────────────────────────────
static const uint8_t k_payload_xored[] = {
    // l    i    b    z    x    _    p    a    y    l    o    a    d    .    s    o
    0x36,0x33,0x38,0x22,0x22,0x65,0x2A,0x3B,0x23,0x36,0x35,0x3B,0x3E,0x74,0x29,0x35,0x00
};

static char s_payload_name[32] = {};

static void decode_payload_name() {
    for (int i = 0; k_payload_xored[i]; i++)
        s_payload_name[i] = (char)(k_payload_xored[i] ^ 0x5A);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 44 — dl_iterate_phdr poisoner
// ─────────────────────────────────────────────────────────────────────────────

struct DlIterCtx {
    dl_iterate_phdr_callback real_cb;
    void *real_data;
};

static int dl_iter_filter_cb(dl_phdr_info *info, size_t size, void *data) {
    DlIterCtx *ctx = static_cast<DlIterCtx*>(data);
    // Hide our payload .so from any enumerating caller
    if (info && info->dlpi_name && s_payload_name[0] &&
        strstr(info->dlpi_name, s_payload_name)) {
        return 0; // silently skip — caller never sees it
    }
    return ctx->real_cb(info, size, ctx->real_data);
}

typedef int (*dl_iterate_phdr_t)(dl_iterate_phdr_callback, void*);
static dl_iterate_phdr_t orig_dl_iterate_phdr = nullptr;

static int hook_dl_iterate_phdr(dl_iterate_phdr_callback cb, void *data) {
    if (!orig_dl_iterate_phdr) return 0;
    DlIterCtx ctx = { cb, data };
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
    // Redirect AnoSDK's specific watch targets to /dev/null
    if (strstr(pathname, "/data/data") ||
        strstr(pathname, "/data/user") ||
        strstr(pathname, "/dev/")     ||
        strstr(pathname, "/proc/")) {
        // Redirect to /dev/null — watch is "installed" but fires nothing
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

static bool is_ano_popen(const char *cmd) {
    if (!cmd) return false;
    // Commands AnoSDK uses to gather process/memory info
    return (strstr(cmd, "ps")       ||
            strstr(cmd, "/proc/")   ||
            strstr(cmd, "ls /")     ||
            strstr(cmd, "cat /")    ||
            strstr(cmd, "grep ")    ||
            strstr(cmd, "getprop")  ||
            strstr(cmd, "id ")      ||
            strstr(cmd, "whoami")   ||
            strstr(cmd, "su ")      ||
            strstr(cmd, "mount"));
}

static FILE* hook_popen(const char *cmd, const char *mode) {
    if (is_ano_popen(cmd)) {
        // Return a valid FILE* that yields empty output
        // /dev/null opened for reading gives immediate EOF
        return orig_popen("true", mode);
    }
    return orig_popen(cmd, mode);
}

// ─────────────────────────────────────────────────────────────────────────────
// Public install
// ─────────────────────────────────────────────────────────────────────────────

void install_stealth_ext5() {
    decode_payload_name();

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
