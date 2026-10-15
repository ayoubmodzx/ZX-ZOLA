/*
 * AnoSDK bypass — confirmed from real libanogs.so (5.3 MB, arm64)
 *
 * Real exports found via nm -D:
 *   AnoSDKIoctl@@ANO, AnoSDKGetReportData@@ANO, AnoSDKGetReportData2@@ANO,
 *   AnoSDKGetReportData3@@ANO, AnoSDKGetReportData4@@ANO
 *   AnoSDKInit@@ANO, AnoSDKInitEx@@ANO, AnoSDKSetUserInfo@@ANO,
 *   AnoSDKOnPause@@ANO, AnoSDKOnResume@@ANO
 *   AnoSDKDelReportData@@ANO (v3/v4 variants)
 *
 * ms_scan_start is NOT exported — it's an internal symbol (confirmed via strings).
 * We therefore hook inline_hook_opcode_dismatch (also internal) using DobbySymbolResolver.
 *
 * ptrace hook: libanogs calls ptrace(PTRACE_TRACEME,0,0,0) to detect external debuggers
 * and ptrace(PTRACE_ATTACH, own_pid, ...) to detect external attachment.
 * We hook ptrace at libc level and return EPERM for PTRACE_ATTACH with foreign pids,
 * while passing PTRACE_TRACEME through with a fake EPERM (already traced = not debugged).
 */
#include "dobby_stub.hpp"
#include <android/log.h>
#include <dlfcn.h>
#include <cstring>
#include <cstdio>
#include <cerrno>
#include <unistd.h>
#include <sys/ptrace.h>
#include <link.h>
#include <cstdint>
#include <cstdarg>

#define TAG "ZX-ANO"
#ifndef ZX_RELEASE
#define LOG(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define ERR(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#else
#define LOG(...) ((void)0)
#define ERR(...) ((void)0)
#endif

// ─────────────────────────────────────────────────────────────────────────────
// libanogs.so load range — used for caller-aware ptrace hook
// ─────────────────────────────────────────────────────────────────────────────
static uintptr_t s_ano_base_bp = 0;
static uintptr_t s_ano_end_bp  = 0;

static int phdr_find_anogs_bp(dl_phdr_info *info, size_t, void*) {
    if (!info->dlpi_name || !strstr(info->dlpi_name, "libanogs.so")) return 0;
    uintptr_t base = (uintptr_t)info->dlpi_addr, end = base;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) &ph = info->dlpi_phdr[i];
        if (ph.p_type == PT_LOAD) {
            uintptr_t se = base + ph.p_vaddr + ph.p_memsz;
            if (se > end) end = se;
        }
    }
    s_ano_base_bp = base; s_ano_end_bp = end; return 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// Original function pointers
// ─────────────────────────────────────────────────────────────────────────────
static int   (*orig_Ioctl)(int,void*,int)            = nullptr;
static void *(*orig_GetData)(int*)                   = nullptr;
static void *(*orig_GetData2)(int,int*)              = nullptr;
static void *(*orig_GetData3)(int,int*,int)          = nullptr;
static void *(*orig_GetData4)(int,int*,int,int)      = nullptr;
static void *(*orig_InlineCheck)(void*,void*,int)    = nullptr;
static int   (*orig_InitEx)(void*,int,void*)         = nullptr;
static long  (*orig_ptrace)(int,pid_t,void*,void*)   = nullptr;

// ─────────────────────────────────────────────────────────────────────────────
// AnoSDK export hooks
// ─────────────────────────────────────────────────────────────────────────────
static int   hook_Ioctl(int,void*,int)    { return 0; }
static void *hook_GetData (int *len)      { if(len)*len=0; return nullptr; }
static void *hook_GetData2(int,int *len)  { if(len)*len=0; return nullptr; }
static void *hook_GetData3(int,int *len,int)     { if(len)*len=0; return nullptr; }
static void *hook_GetData4(int,int *len,int,int) { if(len)*len=0; return nullptr; }

static void *hook_InlineCheck(void *a, void *b, int c) { (void)a;(void)b;(void)c; return nullptr; }

// AnoSDKInitEx — extended init that passes extra config/channel info.
// Swallow it: return 0 (success) without actually initialising the scan subsystem.
static int hook_InitEx(void *cfg, int flags, void *extra) {
    (void)cfg; (void)flags; (void)extra;
    LOG("AnoSDKInitEx swallowed");
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer BP — ptrace neutralizer
//
// AnoSDK calls:
//   ptrace(PTRACE_TRACEME, 0, 0, 0)  → detects debugger (EBUSY if already traced)
//   ptrace(PTRACE_ATTACH, own_pid, …) → self-attach to detect external tracer
//
// Strategy:
//   PTRACE_TRACEME from libanogs → return 0 (fake success, hide real result)
//   PTRACE_ATTACH  with foreign pid from libanogs → return -1 / EPERM (deny perf)
//   All other requests → pass through to real ptrace
// ─────────────────────────────────────────────────────────────────────────────
static long hook_ptrace(int request, pid_t pid, void *addr, void *data) {
    uintptr_t lr = (uintptr_t)__builtin_return_address(0);
    bool from_ano = s_ano_base_bp && lr >= s_ano_base_bp && lr < s_ano_end_bp;

    if (from_ano) {
        if (request == PTRACE_TRACEME) {
            // Pretend success — "we are already being traced" is handled by
            // AnoSDK checking EBUSY; returning 0 means not traced → no alarm.
            errno = 0;
            return 0;
        }
        if (request == PTRACE_ATTACH || request == PTRACE_SEIZE) {
            // Deny self-attach probe — AnoSDK uses this to detect our tracer
            errno = EPERM;
            return -1;
        }
    }

    if (!orig_ptrace) { errno = ENOSYS; return -1; }
    return orig_ptrace(request, pid, addr, data);
}

// ─────────────────────────────────────────────────────────────────────────────
// install
// ─────────────────────────────────────────────────────────────────────────────
__attribute__((constructor(101)))
static void install_ano_bypass() {
    dl_iterate_phdr(phdr_find_anogs_bp, nullptr);

    // ── ptrace hook (libc, caller-aware) ────────────────────────────────────
    {
        void *fn = DobbySymbolResolver("libc.so", "ptrace");
        if (!fn) fn = (void*)&ptrace;
        if (fn) {
            DobbyHook(fn, (void*)hook_ptrace, (void**)&orig_ptrace);
            LOG("ptrace hook installed");
        } else {
            ERR("ptrace sym not found");
        }
    }

    void *h = dlopen("libanogs.so", RTLD_LAZY | RTLD_NOLOAD);
    if (!h) h = dlopen("libanogs.so", RTLD_LAZY);
    if (!h) { ERR("libanogs.so not found"); return; }

    auto hook = [&](const char *sym, void *replacement, void **orig) {
        void *addr = dlsym(h, sym);
        if (!addr) {
            char buf[128];
            snprintf(buf, sizeof(buf), "%s@@ANO", sym);
            addr = dlsym(h, buf);
        }
        if (!addr) addr = DobbySymbolResolver("libanogs.so", sym);
        if (addr) { DobbyHook(addr, replacement, orig); LOG("hooked: %s", sym); }
        else ERR("not found: %s", sym);
    };

    hook("AnoSDKIoctl",          (void*)hook_Ioctl,     (void**)&orig_Ioctl);
    hook("AnoSDKGetReportData",  (void*)hook_GetData,   (void**)&orig_GetData);
    hook("AnoSDKGetReportData2", (void*)hook_GetData2,  (void**)&orig_GetData2);
    hook("AnoSDKGetReportData3", (void*)hook_GetData3,  (void**)&orig_GetData3);
    hook("AnoSDKGetReportData4", (void*)hook_GetData4,  (void**)&orig_GetData4);
    hook("AnoSDKInitEx",         (void*)hook_InitEx,    (void**)&orig_InitEx);

    // Internal symbols — Dobby detector + scan trigger
    static const char *k_internal[] = {
        "inline_hook_opcode_dismatch",
        "set_inline_hook_error",
        "ms_hook_opcode",
        "ms_set_inlie_hook",  // typo is intentional — that's the real symbol name
        "ms_scan_start",
        nullptr
    };
    for (int i = 0; k_internal[i]; i++) {
        void *fn = DobbySymbolResolver("libanogs.so", k_internal[i]);
        if (fn) {
            DobbyHook(fn, (void*)hook_InlineCheck, (void**)&orig_InlineCheck);
            LOG("hooked internal: %s", k_internal[i]);
        }
    }

    LOG("AnoSDK bypass installed OK (libanogs.so @ %p)", h);
}
