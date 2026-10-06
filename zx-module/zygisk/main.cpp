#include "../include/zygisk.hpp"
#include "il2cpp_api.hpp"
#include "hook_engine.hpp"
#include "async_worker.hpp"
#include "feature_engine.hpp"
#include <android/log.h>
#include <cstring>

#define TAG "ZX-ZOLA"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Free Fire package — the only target we care about
static constexpr const char *FF_PKG = "com.dts.freefireth";
static constexpr const char *FF_PKG_MAX = "com.dts.freefiremax";

// Global worker — one thread, SCHED_IDLE priority, never competes with render
static AsyncWorker g_worker;

class ZxZolaModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        m_api = api;
        m_env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        if (!args->nice_name) return;

        const char *pkg = m_env->GetStringUTFChars(args->nice_name, nullptr);
        if (!pkg) return;

        bool is_ff = (strcmp(pkg, FF_PKG) == 0 || strcmp(pkg, FF_PKG_MAX) == 0);
        m_env->ReleaseStringUTFChars(args->nice_name, pkg);

        if (!is_ff) {
            // Not FF — do nothing, zero overhead on other apps
            m_api->setOption(/*DLCLOSE_MODULE_LIBRARY*/ 1);
            return;
        }

        m_target = true;
        LOGI("Free Fire detected, module active");
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (!m_target) return;

        // Start background worker — SCHED_IDLE, won't touch render thread
        g_worker.start();

        // Init il2cpp API on background thread — not on main thread
        g_worker.post([] {
            if (!Il2CppApi::init()) {
                LOGE("Il2Cpp init failed");
                return;
            }
            LOGI("Il2Cpp ready, initializing features");
            FeatureEngine::get().init(&g_worker);
        });
    }

private:
    zygisk::Api *m_api   = nullptr;
    JNIEnv      *m_env   = nullptr;
    bool         m_target = false;
};

REGISTER_ZYGISK_MODULE(ZxZolaModule)
