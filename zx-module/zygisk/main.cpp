#include "../include/zygisk.hpp"
#include "il2cpp_api.hpp"
#include "hook_engine.hpp"
#include "async_worker.hpp"
#include "feature_engine.hpp"
#include "anosdk_bypass.hpp"
#include "memory_guard.hpp"
#include <android/log.h>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

#define TAG "ZX-ZOLA"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// All known Free Fire package names — must match exactly what Zygote sees
static constexpr const char *kFfPkgs[] = {
    "com.dts.freefireth",      // FF global (older)
    "com.dts.freefiremax",     // FF MAX global
    "com.garena.game.fftw",    // FF Garena (SEA / most regions)
    "com.garena.game.kgtw",    // FF Korea
    nullptr
};

static AsyncWorker g_worker;

class ZxZolaModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *) override {
        m_api = api;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *) override {
        // Do NOT call DLCLOSE here — JNI jstring access via ZygiskNext is
        // unreliable across fork boundaries. Package check happens in
        // postAppSpecialize via /proc/self/cmdline which is always valid.
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // Read the process name — reliable after specialization is complete
        char cmdline[256] = {};
        int fd = open("/proc/self/cmdline", O_RDONLY);
        if (fd >= 0) {
            read(fd, cmdline, sizeof(cmdline) - 1);
            close(fd);
        }

        LOGI("postAppSpecialize: cmdline=[%s]", cmdline);

        bool is_ff = false;
        for (int i = 0; kFfPkgs[i]; ++i) {
            if (strcmp(cmdline, kFfPkgs[i]) == 0) { is_ff = true; break; }
        }

        if (!is_ff) {
            LOGI("Not a FF process, skipping");
            return;
        }

        LOGI("Free Fire detected (cmdline=%s)", cmdline);

        // Phase 1: Hook libc.so kill/exit/abort IMMEDIATELY on the main thread.
        // libc.so is always loaded at this point — hooks succeed before any game
        // library (including libanogs.so) has a chance to load and call exit().
        AnoBypass::installEarly();

        g_worker.start();

        g_worker.post([] {
            // Hide ourselves from AnoSDK memory scan
            if (MemoryGuard::init()) {
                MemoryGuard::hideSelf();
            }

            // Phase 2: Start watcher thread that polls for libanogs.so and
            // installs SDK-level API hooks once it appears (~100ms intervals)
            AnoBypass::startWatcher();

            // Il2cpp init with retry — libil2cpp.so may not be mapped yet.
            // Poll every 300ms for up to 15s before giving up.
            struct Il2CppInitRetry {
                static void attempt(AsyncWorker *worker, int tries_left) {
                    if (Il2CppApi::init()) {
                        FeatureEngine::get().init(worker);
                        LOGI("ZX-ZOLA fully loaded — listening on \\0zx_zola");
                        return;
                    }
                    if (tries_left <= 0) {
                        LOGE("Il2Cpp init failed after all retries — libil2cpp.so not found");
                        return;
                    }
                    LOGI("Il2Cpp not ready yet, retrying (%d left)", tries_left);
                    worker->postDelayed([worker, tries_left] {
                        attempt(worker, tries_left - 1);
                    }, 300);
                }
            };
            Il2CppInitRetry::attempt(&g_worker, 50);
        });
    }

private:
    zygisk::Api *m_api = nullptr;
};

REGISTER_ZYGISK_MODULE(ZxZolaModule)
