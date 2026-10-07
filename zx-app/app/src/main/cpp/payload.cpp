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

    int last_cmd = 0;
    while (true) {
        int cmd = g_zx_ctrl.cmd.load(std::memory_order_relaxed);
        if (cmd != 0 && cmd != last_cmd) {
            bool en        = g_zx_ctrl.enable.load() != 0;
            int  intensity = g_zx_ctrl.intensity.load(std::memory_order_relaxed);
            Features::apply(cmd, en);
            if (intensity > 0)
                Features::applyIntensity(cmd, intensity);
            last_cmd = cmd;
            g_zx_ctrl.cmd.store(0, std::memory_order_release);
        } else if (cmd != 0) {
            // Same cmd as last — could be an intensity-only update
            int intensity = g_zx_ctrl.intensity.load(std::memory_order_relaxed);
            static int last_intensity = -1;
            if (intensity != last_intensity) {
                Features::applyIntensity(cmd, intensity);
                last_intensity = intensity;
            }
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
