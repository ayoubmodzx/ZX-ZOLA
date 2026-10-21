#include "../include/zygisk.hpp"
#include "il2cpp_api.hpp"
#include "hook_engine.hpp"
#include "async_worker.hpp"
#include "feature_engine.hpp"
#include "anosdk_bypass.hpp"
#include "memory_guard.hpp"
#include <android/log.h>
#include <cstring>

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
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        // api is only valid for the duration of onLoad; preAppSpecialize
        // receives its own per-call api implicitly via Magisk callbacks.
        // We store it here only because preAppSpecialize calls setOption
        // on the same object — Magisk keeps it alive for the module lifetime.
        m_api = api;
        m_env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        if (!args->nice_name) {
            m_api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        const char *pkg = m_env->GetStringUTFChars(args->nice_name, nullptr);
        if (!pkg) { m_api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY); return; }

        bool is_ff = false;
        for (int i = 0; kFfPkgs[i]; ++i) {
            if (strcmp(pkg, kFfPkgs[i]) == 0) { is_ff = true; break; }
        }
        m_env->ReleaseStringUTFChars(args->nice_name, pkg);

        if (!is_ff) {
            // Unload from every non-FF process — zero overhead everywhere else
            m_api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        m_target = true;
        LOGI("Free Fire detected");
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (!m_target) return;

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

            // Init il2cpp API
            if (!Il2CppApi::init()) {
                LOGE("Il2Cpp init failed");
                return;
            }

            // Features — resolve il2cpp classes + start socket server for app control
            FeatureEngine::get().init(&g_worker);

            LOGI("ZX-ZOLA fully loaded — listening on \\0zx_zola");
        });
    }

private:
    zygisk::Api *m_api    = nullptr;
    JNIEnv      *m_env    = nullptr;
    bool         m_target = false;
};

REGISTER_ZYGISK_MODULE(ZxZolaModule)
