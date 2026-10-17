// zx_payload.so — injected into FF process via dlopen
// anosdk_bypass.cpp installs via __attribute__((constructor)) automatically
#include "anti_detect.hpp"
#include "il2cpp_scanner.hpp"
#include "features.hpp"
#include "esp_renderer.hpp"
#include "stealth_ext7.hpp"
#include <android/log.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <atomic>

#define TAG "ZX-PAYLOAD"
#ifndef ZX_RELEASE
#define LOG(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#else
#define LOG(...) ((void)0)
#endif

// Control struct — written by injector via /proc/PID/mem.
// Attribute placement: visibility must be on the VARIABLE not the type.
// -Bsymbolic (CMakeLists) eliminates the R_AARCH64_GLOB_DAT relocation that
// would force FF's bionic linker to resolve __g_sdktbl1 from its namespace
// (it can't — we own the symbol).  With -Bsymbolic, internal refs are direct
// and the symbol is still exported to .dynsym so dlsym() finds it.
struct ZxCtrl {
    std::atomic<int> cmd{0};        // +0  written by injector, cleared by ctrl_loop
    std::atomic<int> enable{0};     // +4
    std::atomic<int> intensity{0};  // +8  0-100
    std::atomic<int> ack{0};        // +12 last cmd processed by ctrl_loop (readback by injector)
    std::atomic<int> live{0};       // +16 bitmask: 1=antidect 2=il2cpp 4=features 8=loop_ticked
};
extern "C" ZxCtrl _unity_gfx_params __attribute__((visibility("default"), used)) = {};

static void *ctrl_loop(void *) {
    zx_register_tid(gettid());
    prctl(PR_SET_NAME, "kworker/u16:3", 0, 0, 0);

    // il2cpp loads asynchronously — Unity domain + assemblies may not be ready for
    // several seconds after injection. We retry il2cpp init + feature discovery
    // every 1s for up to 60s so Features::init() always runs with a live image.
    // Il2Cpp::init() is idempotent; Features::init() skips already-installed hooks.
    for (int i = 0; i < 60; i++) {
        usleep(1000000); // 1s
        bool il2ok = Il2Cpp::init();
        if (il2ok) _unity_gfx_params.live.fetch_or(2, std::memory_order_relaxed);
        Features::init();
        if (Features::isReady()) {
            _unity_gfx_params.live.fetch_or(4, std::memory_order_relaxed);
            LOG("Features ready after %ds", i + 1);
            break;
        }
        if (i == 59) LOG("Feature discovery timed out (60s) — running degraded");
    }
    ESP::init();
    _unity_gfx_params.live.fetch_or(8, std::memory_order_relaxed); // loop entering main dispatch
    LOG("Payload ready");

    // Each injector call writes a fresh {cmd, enable, intensity} then expects a
    // single processing pass. We clear cmd after each dispatch so the next write
    // is always treated as a new command — this fixes re-toggle and toggle-off.
    int  last_intensity = -1;
    int  last_cmd_seen  = 0;
    bool last_enable    = false;
    while (true) {
        int cmd = _unity_gfx_params.cmd.load(std::memory_order_acquire);
        if (cmd != 0) {
            bool en        = _unity_gfx_params.enable.load(std::memory_order_relaxed) != 0;
            int  intensity = _unity_gfx_params.intensity.load(std::memory_order_relaxed);

            bool state_changed     = (cmd != last_cmd_seen) || (en != last_enable);
            bool intensity_changed = (intensity != last_intensity) || state_changed;

            if (state_changed)
                Features::apply(cmd, en);
            if (intensity_changed)
                Features::applyIntensity(cmd, intensity);

            last_cmd_seen  = en ? cmd : 0;
            last_enable    = en;
            last_intensity = intensity;
            _unity_gfx_params.ack.store(cmd, std::memory_order_relaxed); // ACK before clearing cmd
            _unity_gfx_params.cmd.store(0, std::memory_order_release);
        }
        usleep(50000); // 50ms poll — negligible CPU
    }
    return nullptr;
}

// Called explicitly by injector after GOT PAC-stripping — NOT a constructor.
// On PAC-capable devices FF's bionic signs our GLOB_DAT GOT entries with PACIA,
// so any PLT call in a constructor crashes with BR X16 on the signed pointer.
// The injector: (1) dlopen with no-op constructor, (2) strips GOT PAC entries,
// (3) calls this symbol directly via a second shellcode run.
extern "C" __attribute__((visibility("default"), used))
void unity_render_thread_init() {
    LOG("ZX-ZOLA payload start");
    AntiDetect::install();
    _unity_gfx_params.live.fetch_or(1, std::memory_order_relaxed); // bit0 = anti-detect installed
    pthread_t t;
    pthread_create(&t, nullptr, ctrl_loop, nullptr);
    pthread_detach(t);
}

// Constructor is intentionally a no-op so dlopen completes without touching PLT.
// All real init is in zx_payload_start() above, called by the injector.
__attribute__((constructor(102)))
static void payload_init() {
    (void)0;
}
