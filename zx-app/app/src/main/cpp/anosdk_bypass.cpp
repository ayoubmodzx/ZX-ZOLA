// AnoSDK bypass — inside the payload, kills reporting from within FF process
#include "dobby_stub.hpp"
#include <android/log.h>
#include <dlfcn.h>
#include <cstring>

#define TAG "ZX-ANO"
#define LOG(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

static int   (*orig_AnoSDKIoctl)(int cmd, void *data, int len)       = nullptr;
static void *(*orig_AnoSDKGetReportData)(int *len)                   = nullptr;
static void *(*orig_AnoSDKGetReportData2)(int t, int *len)           = nullptr;
static void *(*orig_AnoSDKGetReportData3)(int t, int *len, int f)    = nullptr;
static void *(*orig_AnoSDKGetReportData4)(int t, int *len, int f, int e) = nullptr;
static int   (*orig_ms_scan_start)(int type, void *p)                = nullptr;

static int   hook_AnoSDKIoctl(int cmd, void *data, int len) {
    if (cmd < 0x10 && orig_AnoSDKIoctl) return orig_AnoSDKIoctl(cmd, data, len);
    return 0;
}
static void *hook_GetReport(int *len)              { if(len)*len=0; return nullptr; }
static void *hook_GetReport2(int,int *len)         { if(len)*len=0; return nullptr; }
static void *hook_GetReport3(int,int *len,int)     { if(len)*len=0; return nullptr; }
static void *hook_GetReport4(int,int *len,int,int) { if(len)*len=0; return nullptr; }
static int   hook_ms_scan(int, void*)              { return 0; }

__attribute__((constructor))
static void install_ano_bypass() {
    void *h = dlopen("libanogs.so", RTLD_LAZY | RTLD_NOLOAD);
    if (!h) h = dlopen("libanogs.so", RTLD_LAZY);
    if (!h) { LOG("libanogs.so not found"); return; }

    auto sym = [&](const char *name) { return dlsym(h, name); };

    DobbyHook(sym("AnoSDKIoctl"),          (void*)hook_AnoSDKIoctl,  (void**)&orig_AnoSDKIoctl);
    DobbyHook(sym("AnoSDKGetReportData"),  (void*)hook_GetReport,    (void**)&orig_AnoSDKGetReportData);
    DobbyHook(sym("AnoSDKGetReportData2"), (void*)hook_GetReport2,   (void**)&orig_AnoSDKGetReportData2);
    DobbyHook(sym("AnoSDKGetReportData3"), (void*)hook_GetReport3,   (void**)&orig_AnoSDKGetReportData3);
    DobbyHook(sym("AnoSDKGetReportData4"), (void*)hook_GetReport4,   (void**)&orig_AnoSDKGetReportData4);
    DobbyHook(sym("ms_scan_start"),        (void*)hook_ms_scan,      (void**)&orig_ms_scan_start);

    LOG("AnoSDK bypass installed");
}
