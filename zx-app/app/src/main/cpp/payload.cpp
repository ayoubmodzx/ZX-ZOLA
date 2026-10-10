// zx_payload.so — injected into FF process via dlopen
// anosdk_bypass.cpp installs via __attribute__((constructor)) automatically
#include "anti_detect.hpp"
#include "il2cpp_scanner.hpp"
#include "features.hpp"
#include "esp_renderer.hpp"
#include <android/log.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <atomic>

#define TAG "ZX-PAYLOAD"
#define LOG(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

// Version marker — visible in logcat if this binary actually loaded.
// If you see "ZX-PAYLOAD: build=v7" the new binary is running.
// If dlopen still fails you never see this — it means the OLD APK is still installed.
static const char kBuildTag[] __attribute__((used)) = "ZX-BUILD-v7";

// Control struct — written by injector via /proc/PID/mem.
// NOT exported as a symbol: exporting it caused __g_sdktbl1 to appear as UND
// in the payload's .dynsym (LLD + NDK r27 bug/quirk), causing dlopen to fail.
// Instead: injector locates the struct by scanning for the 16-byte magic tag
// placed immediately before the ctrl fields in __g_block.  No .dynsym entry,
// no import, dlopen succeeds cleanly.
struct ZxCtrl {
    std::atomic<int> cmd{0};
    std::atomic<int> enable{0};
    std::atomic<int> intensity{0};
};

static struct ZxCtrlBlock {
    volatile uint64_t tag[2];
    ZxCtrl ctrl;
} __g_block __attribute__((used)) = {
    {0xDEADBEEFC0DE5A5AULL, 0x5A5AFACE00000012ULL},
    {}
};
#define __g_sdktbl1 (__g_block.ctrl)

static void *ctrl_loop(void *) {
    prctl(PR_SET_NAME, "kworker/u16:3", 0, 0, 0);
    sleep(3);

    if (!Il2Cpp::init()) {
        LOG("Il2Cpp init failed");
        return nullptr;
    }
    LOG("Il2Cpp ready — starting class discovery + engine hooks");
    Features::init();
    ESP::init();
    LOG("Payload ready");

    int  last_intensity = -1;
    int  last_cmd_seen  = 0;
    bool last_enable    = false;
    while (true) {
        int cmd = __g_sdktbl1.cmd.load(std::memory_order_acquire);
        if (cmd != 0) {
            bool en        = __g_sdktbl1.enable.load(std::memory_order_relaxed) != 0;
            int  intensity = __g_sdktbl1.intensity.load(std::memory_order_relaxed);

            bool state_changed     = (cmd != last_cmd_seen) || (en != last_enable);
            bool intensity_changed = (intensity != last_intensity) || state_changed;

            if (state_changed)
                Features::apply(cmd, en);
            if (intensity_changed)
                Features::applyIntensity(cmd, intensity);

            last_cmd_seen  = en ? cmd : 0;
            last_enable    = en;
            last_intensity = intensity;
            __g_sdktbl1.cmd.store(0, std::memory_order_release);
        }
        usleep(50000);
    }
    return nullptr;
}

// Called when payload is dlopen'd into FF
__attribute__((constructor(102)))
static void payload_init() {
    LOG("build=%s", kBuildTag);
    LOG("ZX-ZOLA payload injected");
    // Anti-detection runs first — before any IL2CPP or feature work
    AntiDetect::install();
    pthread_t t;
    pthread_create(&t, nullptr, ctrl_loop, nullptr);
    pthread_detach(t);
}
