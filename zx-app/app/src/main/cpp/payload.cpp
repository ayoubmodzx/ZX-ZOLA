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
#ifndef ZX_RELEASE
#define LOG(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#else
#define LOG(...) ((void)0)
#endif

// Control struct — written by injector via /proc/PID/mem.
// visibility("default") is REQUIRED: -fvisibility=hidden is the global build flag;
// without it __g_sdktbl1 has hidden visibility, lives only in .symtab, and the
// classloader-namespace runtime linker sees it as an unresolved import → dlopen fails.
extern "C" struct ZxCtrl {
    std::atomic<int> cmd{0};
    std::atomic<int> enable{0};
    std::atomic<int> intensity{0};
} __attribute__((visibility("default"))) __attribute__((used)) __g_sdktbl1;

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
    LOG("ZX-ZOLA payload injected");
    // Anti-detection runs first — before any IL2CPP or feature work
    AntiDetect::install();
    pthread_t t;
    pthread_create(&t, nullptr, ctrl_loop, nullptr);
    pthread_detach(t);
}
