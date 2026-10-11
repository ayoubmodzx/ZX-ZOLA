// zx_payload.so — injected into FF process via dlopen
// anosdk_bypass.cpp installs via __attribute__((constructor)) automatically
#include "anti_detect.hpp"
#include "il2cpp_scanner.hpp"
#include "features.hpp"
#include "esp_renderer.hpp"
#include "zx_logbuf.hpp"
#include <android/log.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <signal.h>
#include <atomic>
#include <cstring>

#define TAG "ZX-PAYLOAD"
#define LOG(fmt, ...) LOGBUF_I(TAG, fmt, ##__VA_ARGS__)

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

static constexpr uint32_t ZX_LOG_BUF_SZ = 8192;

static struct ZxCtrlBlock {
    volatile uint64_t tag[2];   // offset 0  — 16 bytes (magic, MUST stay first)
    ZxCtrl ctrl;                // offset 16 — 12 bytes (cmd/enable/intensity)
    uint32_t log_wp;            // offset 28 — monotonically increasing write cursor
    char     log_buf[ZX_LOG_BUF_SZ]; // offset 32 — circular byte log ring
} __g_block __attribute__((used)) = {
    {0xDEADBEEFC0DE5A5AULL, 0x5A5AFACE00000012ULL},
    {}, 0, {}
};
#define __g_sdktbl1 (__g_block.ctrl)

// Called by any TU inside the payload .so (via zx_logbuf.hpp).
// Writes msg + '\n' into the ring buffer; injector polls it via /proc/PID/mem.
extern "C" void zx_buf_write(const char *msg) {
    if (!msg || !*msg) return;
    uint32_t mlen = (uint32_t)strlen(msg);
    if (mlen > 255) mlen = 255;
    uint32_t wp = __atomic_fetch_add(&__g_block.log_wp, mlen + 1, __ATOMIC_RELAXED);
    for (uint32_t i = 0; i < mlen; i++)
        __g_block.log_buf[(wp + i) % ZX_LOG_BUF_SZ] = msg[i];
    __g_block.log_buf[(wp + mlen) % ZX_LOG_BUF_SZ] = '\n';
    __atomic_thread_fence(__ATOMIC_RELEASE);
}

static void *ctrl_loop(void *) {
    prctl(PR_SET_NAME, "kworker/u16:3", 0, 0, 0);
    // 200ms: dlopen fully unwinds in ~50ms, so this is a 4x margin.
    // Anti-detect MUST be installed before ACE's maps scanner fires (<100ms after injection).
    // The old sleep(3) left memfd:zx visible for 3 seconds — ACE killed us in <100ms.
    usleep(200000);

    // Install after dlopen call stack is fully unwound — hooking libc functions
    // (open/close/dl_iterate_phdr) during dlopen execution corrupts the call stack
    // and causes SIGSEGV with non-canonical PC.
    AntiDetect::install();

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

static void crash_handler(int sig, siginfo_t *si, void *) {
    char buf[128];
    snprintf(buf, sizeof(buf), "CRASH sig=%d addr=%p", sig, si ? si->si_addr : nullptr);
    zx_buf_write(buf);
    struct sigaction sa{};
    sa.sa_handler = SIG_DFL;
    sigaction(sig, &sa, nullptr);
    raise(sig);
}

// Called when payload is dlopen'd into FF
__attribute__((constructor(102)))
static void payload_init() {
    struct sigaction sa{};
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGABRT, &sa, nullptr);
    sigaction(SIGBUS,  &sa, nullptr);
    sigaction(SIGILL,  &sa, nullptr);

    LOG("build=%s", kBuildTag);
    LOG("ZX-ZOLA payload injected");
    pthread_t t;
    pthread_create(&t, nullptr, ctrl_loop, nullptr);
    pthread_detach(t);
}
