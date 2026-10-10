/*
 * AnoSDK bypass — confirmed from real libanogs.so (5.3 MB, arm64)
 *
 * Real exports found via nm -D:
 *   AnoSDKIoctl@@ANO, AnoSDKGetReportData@@ANO, AnoSDKGetReportData2@@ANO,
 *   AnoSDKGetReportData3@@ANO, AnoSDKGetReportData4@@ANO
 *   AnoSDKInit@@ANO, AnoSDKSetUserInfo@@ANO, AnoSDKOnPause@@ANO, AnoSDKOnResume@@ANO
 *   AnoSDKDelReportData@@ANO (v3/v4 variants)
 *
 * ms_scan_start is NOT exported — it's an internal symbol (confirmed via strings).
 * We therefore hook inline_hook_opcode_dismatch (also internal) using DobbySymbolResolver.
 *
 * dlsym(h, "AnoSDKIoctl") resolves AnoSDKIoctl@@ANO correctly (default version).
 */
#include "dobby_stub.hpp"
#include <android/log.h>
#include <dlfcn.h>
#include <cstring>
#include <cstdio>

#define TAG "ZX-ANO"
#ifndef ZX_RELEASE
#define LOG(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define ERR(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#else
#define LOG(...) ((void)0)
#define ERR(...) ((void)0)
#endif

// Original function pointers
static int   (*orig_Ioctl)(int,void*,int)            = nullptr;
static void *(*orig_GetData)(int*)                   = nullptr;
static void *(*orig_GetData2)(int,int*)              = nullptr;
static void *(*orig_GetData3)(int,int*,int)          = nullptr;
static void *(*orig_GetData4)(int,int*,int,int)      = nullptr;
static void *(*orig_InlineCheck)(void*,void*,int)    = nullptr; // inline_hook_opcode_dismatch

// Hooks — silently discard all report data and scanning
static int   hook_Ioctl(int cmd, void *data, int len) {
    // Block ALL commands — no heartbeat, no init, no scan
    (void)cmd; (void)data; (void)len;
    return 0;
}
static void *hook_GetData (int *len)               { if(len)*len=0; return nullptr; }
static void *hook_GetData2(int,int *len)           { if(len)*len=0; return nullptr; }
static void *hook_GetData3(int,int *len,int)       { if(len)*len=0; return nullptr; }
static void *hook_GetData4(int,int *len,int,int)   { if(len)*len=0; return nullptr; }

// inline_hook_opcode_dismatch — AnoSDK's internal Dobby detector
// Returns non-zero to trigger alert; we return 0 (no mismatch seen)
static void *hook_InlineCheck(void *a, void *b, int c) {
    (void)a; (void)b; (void)c;
    return nullptr;
}

__attribute__((constructor(101)))
static void install_ano_bypass() {
    // Try both symbol names in case of version suffix variation
    // RTLD_NOLOAD only — libanogs.so lives in the game's classloader namespace.
    // A fresh RTLD_LAZY load into the payload namespace fails with
    // "undefined symbol: set_inline_hook_error@@ANO" because that namespace
    // cannot see libanogs.so's deps.  If RTLD_NOLOAD returns NULL the hook
    // lambda already falls through to DobbySymbolResolver (dl_iterate_phdr
    // + ELF scan) which finds symbols across namespace boundaries.
    void *h = dlopen("libanogs.so", RTLD_LAZY | RTLD_NOLOAD);

    // Helper: resolve sym, hook if found
    auto hook = [&](const char *sym, void *replacement, void **orig) {
        void *addr = nullptr;
        if (h) {
            addr = dlsym(h, sym);
            if (!addr) {
                char buf[128];
                snprintf(buf, sizeof(buf), "%s@@ANO", sym);
                addr = dlsym(h, buf);
            }
        }
        // Fallback: ELF scan via dl_iterate_phdr — crosses namespace boundaries
        if (!addr) addr = DobbySymbolResolver("libanogs.so", sym);
        if (addr) DobbyHook(addr, replacement, orig);
        else ERR("sym not found: %s", sym);
    };

    hook("AnoSDKIoctl",          (void*)hook_Ioctl,     (void**)&orig_Ioctl);
    hook("AnoSDKGetReportData",  (void*)hook_GetData,   (void**)&orig_GetData);
    hook("AnoSDKGetReportData2", (void*)hook_GetData2,  (void**)&orig_GetData2);
    hook("AnoSDKGetReportData3", (void*)hook_GetData3,  (void**)&orig_GetData3);
    hook("AnoSDKGetReportData4", (void*)hook_GetData4,  (void**)&orig_GetData4);

    // Hook internal Dobby-detection function (internal symbol, use DobbySymbolResolver)
    void *inlineCheck = DobbySymbolResolver("libanogs.so", "inline_hook_opcode_dismatch");
    if (!inlineCheck) inlineCheck = DobbySymbolResolver("libanogs.so", "set_inline_hook_error");
    if (inlineCheck) {
        DobbyHook(inlineCheck, (void*)hook_InlineCheck, (void**)&orig_InlineCheck);
        LOG("Hooked inline_hook detector");
    }

    LOG("AnoSDK bypass installed (libanogs.so @ %p)", h);
}
