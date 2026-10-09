#include "anosdk_bypass.hpp"
#include "hook_engine.hpp"
#include <dlfcn.h>
#include <cstring>
#include <android/log.h>

#define TAG "ZX-ANO"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ── Original function pointers ────────────────────────────────────────────────
static int   (*orig_AnoSDKIoctl)(int cmd, void *data, int len)              = nullptr;
static void* (*orig_AnoSDKGetReportData)(int *len)                          = nullptr;
static void* (*orig_AnoSDKGetReportData2)(int type, int *len)               = nullptr;
static void* (*orig_AnoSDKGetReportData3)(int type, int *len, int flag)     = nullptr;
static void* (*orig_AnoSDKGetReportData4)(int type, int *len, int flag, int extra) = nullptr;
static int   (*orig_ms_scan_start)(int type, void *param)                   = nullptr;

// ── Intercepts ────────────────────────────────────────────────────────────────

// Block all ioctl commands — commands 0x100+ are usually "report hack" signals
static int hook_AnoSDKIoctl(int cmd, void *data, int len) {
    // Allow init commands (< 0x10) to pass — blocking those causes crashes
    if (cmd < 0x10 && orig_AnoSDKIoctl)
        return orig_AnoSDKIoctl(cmd, data, len);
    // Drop all scan/report commands
    return 0;
}

// Return empty report buffers — no data = nothing to report to server
static void *hook_AnoSDKGetReportData(int *len) {
    if (len) *len = 0;
    return nullptr;
}

static void *hook_AnoSDKGetReportData2(int type, int *len) {
    (void)type;
    if (len) *len = 0;
    return nullptr;
}

static void *hook_AnoSDKGetReportData3(int type, int *len, int flag) {
    (void)type; (void)flag;
    if (len) *len = 0;
    return nullptr;
}

static void *hook_AnoSDKGetReportData4(int type, int *len, int flag, int extra) {
    (void)type; (void)flag; (void)extra;
    if (len) *len = 0;
    return nullptr;
}

// Delay all memory scans — ms_scan_start is the inline hook detector
static int hook_ms_scan_start(int type, void *param) {
    (void)type; (void)param;
    return 0;  // Pretend scan ran successfully but did nothing
}

// ── Install / Remove ─────────────────────────────────────────────────────────
bool AnoBypass::install() {
    auto &engine = HookEngine::get();
    bool ok = true;

    ok &= engine.hookSym("libanogs.so", "AnoSDKIoctl",
                         (void *)hook_AnoSDKIoctl,
                         (void **)&orig_AnoSDKIoctl, "AnoIoctl");

    ok &= engine.hookSym("libanogs.so", "AnoSDKGetReportData",
                         (void *)hook_AnoSDKGetReportData,
                         (void **)&orig_AnoSDKGetReportData, "AnoReport1");

    ok &= engine.hookSym("libanogs.so", "AnoSDKGetReportData2",
                         (void *)hook_AnoSDKGetReportData2,
                         (void **)&orig_AnoSDKGetReportData2, "AnoReport2");

    ok &= engine.hookSym("libanogs.so", "AnoSDKGetReportData3",
                         (void *)hook_AnoSDKGetReportData3,
                         (void **)&orig_AnoSDKGetReportData3, "AnoReport3");

    ok &= engine.hookSym("libanogs.so", "AnoSDKGetReportData4",
                         (void *)hook_AnoSDKGetReportData4,
                         (void **)&orig_AnoSDKGetReportData4, "AnoReport4");

    // ms_scan_start is NOT exported from libanogs.so (confirmed via nm -D on real binary).
    // It appears as an internal symbol — DobbySymbolResolver can find it.
    // inline_hook_opcode_dismatch is also confirmed as an internal symbol.
    // HookEngine::hookSym falls back to DobbySymbolResolver automatically.
    engine.hookSym("libanogs.so", "ms_scan_start",
                   (void *)hook_ms_scan_start,
                   (void **)&orig_ms_scan_start, "MsScan");

    // Also hook the inline-hook detector directly (confirmed internal sym)
    engine.hookSym("libanogs.so", "inline_hook_opcode_dismatch",
                   (void *)hook_ms_scan_start,   // same stub is fine — return 0
                   nullptr, "InlineHookDetect");
    engine.hookSym("libanogs.so", "set_inline_hook_error",
                   (void *)hook_ms_scan_start,
                   nullptr, "SetHookError");

    LOGI("AnoSDK bypass installed, hooks: %zu", engine.count());
    return ok;
}

void AnoBypass::remove() {
    // Let HookEngine::unhookAll() handle cleanup
    LOGI("AnoSDK bypass removed");
}
