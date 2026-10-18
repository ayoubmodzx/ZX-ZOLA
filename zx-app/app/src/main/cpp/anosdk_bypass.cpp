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

// Compile-time XOR obfuscation — sensitive strings never appear in .rodata
static constexpr uint8_t ANO_XK = 0x5Au;
template<size_t N>
struct ObfA {
    char data[N]{};
    constexpr explicit ObfA(const char (&s)[N]) {
        for (size_t i = 0; i < N; i++) data[i] = (char)(s[i] ^ ANO_XK);
    }
    void decode(char (&out)[N]) const {
        for (size_t i = 0; i < N; i++) out[i] = (char)(data[i] ^ ANO_XK);
    }
};
#define OBF_ANO(var, lit) \
    char var[sizeof(lit)]; \
    do { static constexpr ObfA<sizeof(lit)> _oa(lit); _oa.decode(var); } while(0)

// ─────────────────────────────────────────────────────────────────────────────
// libanogs.so load range — used for caller-aware ptrace hook
// ─────────────────────────────────────────────────────────────────────────────
static uintptr_t s_ano_base_bp   = 0;
static uintptr_t s_ano_end_bp    = 0;
static uintptr_t s_anort_base_bp = 0;
static uintptr_t s_anort_end_bp  = 0;

static int phdr_find_anogs_bp(dl_phdr_info *info, size_t, void*) {
    if (!info->dlpi_name) return 0;
    static char anobp_n[16]; static bool once_bp = false;
    if (__builtin_expect(!once_bp, 0)) {
        once_bp = true;
        static constexpr ObfA<12> o("libanogs.so"); o.decode(*(char(*)[12])anobp_n);
    }
    if (!strstr(info->dlpi_name, anobp_n)) return 0;
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

static int phdr_find_anort_bp(dl_phdr_info *info, size_t, void*) {
    if (!info->dlpi_name) return 0;
    static char anortbp_n[16]; static bool once_rt = false;
    if (__builtin_expect(!once_rt, 0)) {
        once_rt = true;
        static constexpr ObfA<12> o("libanort.so"); o.decode(*(char(*)[12])anortbp_n);
    }
    if (!strstr(info->dlpi_name, anortbp_n)) return 0;
    uintptr_t base = (uintptr_t)info->dlpi_addr, end = base;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) &ph = info->dlpi_phdr[i];
        if (ph.p_type == PT_LOAD) {
            uintptr_t se = base + ph.p_vaddr + ph.p_memsz;
            if (se > end) end = se;
        }
    }
    s_anort_base_bp = base; s_anort_end_bp = end; return 1;
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
// Ioctl: pass through — scan functions are nullified so any triggered scan
// returns clean results. Blocking all ioctl prevents heartbeat commands from
// reaching the server, causing a "silent sensor" server-side ban.
static int hook_Ioctl(int cmd, void *d, int l) {
    return orig_Ioctl ? orig_Ioctl(cmd, d, l) : 0;
}

// GetReportData: pass through — internal scan state is already clean because
// ms_scan_start / inline_hook_opcode_dismatch are nullified. Returning null
// makes the server see zero bytes every cycle which is an anomaly signal.
static void *hook_GetData (int *len)             { return orig_GetData  ? orig_GetData(len)         : nullptr; }
static void *hook_GetData2(int t, int *len)      { return orig_GetData2 ? orig_GetData2(t,len)      : nullptr; }
static void *hook_GetData3(int t, int *len,int f){ return orig_GetData3 ? orig_GetData3(t,len,f)    : nullptr; }
static void *hook_GetData4(int t, int *len,int f,int g){ return orig_GetData4 ? orig_GetData4(t,len,f,g) : nullptr; }

static void *hook_InlineCheck(void *a, void *b, int c) { (void)a;(void)b;(void)c; return nullptr; }

// AnoSDKInitEx — let real init run so SDK starts its heartbeat thread.
// Scan functions (ms_scan_start etc.) are already nullified so every scan
// the SDK performs reports "nothing found". Swallowing init causes a
// "silent sensor" state where the server receives zero heartbeats → ban.
static int hook_InitEx(void *cfg, int flags, void *extra) {
    LOG("AnoSDKInitEx pass-through (transparent mode)");
    return orig_InitEx ? orig_InitEx(cfg, flags, extra) : 0;
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
    bool from_ano = (s_ano_base_bp   && lr >= s_ano_base_bp   && lr < s_ano_end_bp)  ||
                    (s_anort_base_bp && lr >= s_anort_base_bp && lr < s_anort_end_bp);

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
void install_ano_bypass() {
    dl_iterate_phdr(phdr_find_anogs_bp,  nullptr);
    dl_iterate_phdr(phdr_find_anort_bp,  nullptr);

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

    OBF_ANO(anolib, "libanogs.so");
    void *h = dlopen(anolib, RTLD_LAZY | RTLD_NOLOAD);
    if (!h) h = dlopen(anolib, RTLD_LAZY);
    if (!h) { ERR("ano lib not found"); return; }

    auto hook = [&](const char *sym, void *replacement, void **orig) {
        void *addr = dlsym(h, sym);
        if (!addr) {
            char buf[128];
            snprintf(buf, sizeof(buf), "%s@@ANO", sym);
            addr = dlsym(h, buf);
        }
        if (!addr) addr = DobbySymbolResolver(anolib, sym);
        if (addr) { DobbyHook(addr, replacement, orig); LOG("hooked: %s", sym); }
        else ERR("not found: %s", sym);
    };

    OBF_ANO(s_ioctl, "AnoSDKIoctl");
    OBF_ANO(s_gd1,   "AnoSDKGetReportData");
    OBF_ANO(s_gd2,   "AnoSDKGetReportData2");
    OBF_ANO(s_gd3,   "AnoSDKGetReportData3");
    OBF_ANO(s_gd4,   "AnoSDKGetReportData4");
    OBF_ANO(s_inex,  "AnoSDKInitEx");
    hook(s_ioctl, (void*)hook_Ioctl,    (void**)&orig_Ioctl);
    hook(s_gd1,   (void*)hook_GetData,  (void**)&orig_GetData);
    hook(s_gd2,   (void*)hook_GetData2, (void**)&orig_GetData2);
    hook(s_gd3,   (void*)hook_GetData3, (void**)&orig_GetData3);
    hook(s_gd4,   (void*)hook_GetData4, (void**)&orig_GetData4);
    hook(s_inex,  (void*)hook_InitEx,   (void**)&orig_InitEx);

    // Internal symbols — Dobby detector + scan trigger (encoded, never plain .rodata)
    OBF_ANO(ki0, "inline_hook_opcode_dismatch");
    OBF_ANO(ki1, "set_inline_hook_error");
    OBF_ANO(ki2, "ms_hook_opcode");
    OBF_ANO(ki3, "ms_set_inlie_hook"); // intentional typo — real symbol name
    OBF_ANO(ki4, "ms_scan_start");
    const char *k_internal[] = {ki0, ki1, ki2, ki3, ki4, nullptr};
    for (int i = 0; k_internal[i]; i++) {
        void *fn = DobbySymbolResolver(anolib, k_internal[i]);
        if (fn) {
            DobbyHook(fn, (void*)hook_InlineCheck, (void**)&orig_InlineCheck);
            LOG("hooked internal: %s", k_internal[i]);
        }
    }

    LOG("AnoSDK bypass installed OK");
}
