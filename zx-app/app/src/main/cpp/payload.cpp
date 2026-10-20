// zx_payload.so — injected into FF process via dlopen
// anosdk_bypass.cpp installs via __attribute__((constructor)) automatically
#include "anti_detect.hpp"
#include "il2cpp_scanner.hpp"
#include "features.hpp"
#include "esp_renderer.hpp"
#include "stealth_ext7.hpp"
#include <android/log.h>
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
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

    // Phase-1: il2cpp + feature discovery retry (200ms ticks, 300 ticks = 60s max).
    // Commands arriving during this window are buffered and applied immediately on
    // each tick so the injector's 600ms ACK window always catches the first dispatch.
    int  last_intensity  = -1;
    int  last_cmd_seen   = 0;
    bool last_enable     = false;
    bool features_primed = false;

    for (int i = 0; i < 300; i++) {
        usleep(200000); // 200ms — 5× faster ticks vs old 1s

        bool il2ok = Il2Cpp::init();
        if (il2ok) _unity_gfx_params.live.fetch_or(2, std::memory_order_relaxed);
        Features::init();
        if (!features_primed && Features::isReady()) {
            features_primed = true;
            _unity_gfx_params.live.fetch_or(4, std::memory_order_relaxed);
            LOG("Features ready after %.1fs", (i + 1) * 0.2f);
        }

        // Drain any command that arrived while we were initialising — this is
        // what makes features toggle within the injector's 600ms ACK window even
        // when il2cpp is still warming up.
        int cmd = _unity_gfx_params.cmd.load(std::memory_order_acquire);
        if (cmd != 0) {
            bool en        = _unity_gfx_params.enable.load(std::memory_order_relaxed) != 0;
            int  intensity = _unity_gfx_params.intensity.load(std::memory_order_relaxed);
            bool st_chg    = (cmd != last_cmd_seen) || (en != last_enable);
            bool in_chg    = (intensity != last_intensity) || st_chg;
            if (st_chg) Features::apply(cmd, en);
            if (in_chg) Features::applyIntensity(cmd, intensity);
            last_cmd_seen  = en ? cmd : 0;
            last_enable    = en;
            last_intensity = intensity;
            _unity_gfx_params.ack.store(cmd, std::memory_order_relaxed);
            _unity_gfx_params.cmd.store(0, std::memory_order_release);
            LOG("Init-phase cmd=%d en=%d dispatched at tick %d", cmd, (int)en, i);
        }

        if (features_primed && il2ok) break; // fully ready — skip remaining ticks
        if (i == 299) LOG("Feature discovery timed out (60s) — running degraded");
    }
    ESP::init();
    _unity_gfx_params.live.fetch_or(8, std::memory_order_relaxed); // entering main dispatch
    LOG("Payload ready");

    // Phase-2: main dispatch loop (50ms poll).
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
            _unity_gfx_params.ack.store(cmd, std::memory_order_relaxed);
            _unity_gfx_params.cmd.store(0, std::memory_order_release);
        }
        usleep(50000); // 50ms poll — negligible CPU
    }
    return nullptr;
}

// SIGABRT shield: absorb AnoSDK's sigqueue(pid,SIGABRT) during install window.
// si_code <= 0 means external kill (SI_QUEUE=-1, SI_USER=0); si_code > 0 is kernel.
// bionic's own abort() uses SI_TKILL (-6) — also <= 0 but g_in_antidect_install=false by then.
static volatile bool g_in_antidect_install = false;
static struct sigaction g_old_sigabrt_sa = {};

static void ano_sigabrt_shield(int, siginfo_t *info, void *) {
    if (g_in_antidect_install && info && info->si_code <= 0) {
        return; // drop AnoSDK's sigqueue SIGABRT during install window
    }
    sigaction(SIGABRT, &g_old_sigabrt_sa, nullptr);
    raise(SIGABRT);
}

// Called explicitly by injector after GOT PAC-stripping — NOT a constructor.
// On PAC-capable devices FF's bionic signs our GLOB_DAT GOT entries with PACIA,
// so any PLT call in a constructor crashes with BR X16 on the signed pointer.
// The injector: (1) dlopen with no-op constructor, (2) strips GOT PAC entries,
// (3) calls this symbol directly via a second shellcode run.
extern "C" __attribute__((visibility("default"), used))
void unity_render_thread_init() {
    LOG("ZX-ZOLA payload start");
    // Resolve pthread via dlsym BEFORE calling AntiDetect::install().
    // dlsym's GOT entry is always correctly written by the injector (libdl.so is
    // stable across sessions); pthread_create/detach PLT entries may point to a
    // non-executable libc copy when the process has multiple libc mappings.
    typedef int (*fn_pc_t)(pthread_t*, const pthread_attr_t*, void*(*)(void*), void*);
    typedef int (*fn_pd_t)(pthread_t);
    auto real_pthread_create = (fn_pc_t)dlsym(RTLD_DEFAULT, "pthread_create");
    auto real_pthread_detach = (fn_pd_t)dlsym(RTLD_DEFAULT, "pthread_detach");

    // Shield against AnoSDK's scanner firing sigqueue(pid,SIGABRT) while we install hooks.
    // The scanner detects Dobby's mprotect(rwxp) and tries to kill the process mid-install.
    {
        struct sigaction sa = {};
        sa.sa_sigaction = ano_sigabrt_shield;
        sa.sa_flags = SA_SIGINFO | SA_NODEFER;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGABRT, &sa, &g_old_sigabrt_sa);
    }
    g_in_antidect_install = true;
    AntiDetect::install();
    g_in_antidect_install = false;
    _unity_gfx_params.live.fetch_or(1, std::memory_order_relaxed); // bit0 = anti-detect installed
    // Restore old handler — install_ano_bypass() now owns AnoSDK's signal path.
    sigaction(SIGABRT, &g_old_sigabrt_sa, nullptr);

    if (real_pthread_create) {
        pthread_t t;
        real_pthread_create(&t, nullptr, ctrl_loop, nullptr);
        if (real_pthread_detach) real_pthread_detach(t);
    }
}

// Constructor is intentionally a no-op so dlopen completes without touching PLT.
// All real init is in zx_payload_start() above, called by the injector.
__attribute__((constructor(102)))
static void payload_init() {
    (void)0;
}
