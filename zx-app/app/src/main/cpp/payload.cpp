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

// Control struct — written by injector via /proc/PID/mem
extern "C" struct ZxCtrl {
    std::atomic<int> cmd{0};
    std::atomic<int> enable{0};
    std::atomic<int> intensity{0}; // 0-100, for risk slider features
} g_zx_ctrl;

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

    // Each injector call writes a fresh {cmd, enable, intensity} then expects a
    // single processing pass. We clear cmd after each dispatch so the next write
    // is always treated as a new command — this fixes re-toggle and toggle-off.
    int  last_intensity = -1;
    int  last_cmd_seen  = 0;
    bool last_enable    = false;
    while (true) {
        int cmd = g_zx_ctrl.cmd.load(std::memory_order_acquire);
        if (cmd != 0) {
            bool en        = g_zx_ctrl.enable.load(std::memory_order_relaxed) != 0;
            int  intensity = g_zx_ctrl.intensity.load(std::memory_order_relaxed);

            bool state_changed     = (cmd != last_cmd_seen) || (en != last_enable);
            bool intensity_changed = (intensity != last_intensity) || state_changed;

            if (state_changed)
                Features::apply(cmd, en);
            if (intensity_changed)
                Features::applyIntensity(cmd, intensity); // handles intensity=0 correctly

            last_cmd_seen  = en ? cmd : 0; // reset so re-enable fires apply() again
            last_enable    = en;
            last_intensity = intensity;
            g_zx_ctrl.cmd.store(0, std::memory_order_release);
        }
        usleep(50000); // 50ms poll — negligible CPU
    }
    return nullptr;
}

// Called when payload is dlopen'd into FF
__attribute__((constructor))
static void payload_init() {
    LOG("ZX-ZOLA payload injected");
    // Anti-detection runs first — before any IL2CPP or feature work
    AntiDetect::install();
    pthread_t t;
    pthread_create(&t, nullptr, ctrl_loop, nullptr);
    pthread_detach(t);
}
