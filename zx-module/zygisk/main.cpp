#include "../include/zygisk.hpp"
#include "il2cpp_api.hpp"
#include "hook_engine.hpp"
#include "async_worker.hpp"
#include "feature_engine.hpp"
#include "anosdk_bypass.hpp"
#include "memory_guard.hpp"
#include "kill_shield.hpp"
#include <android/log.h>
#include <cstring>

#define TAG "ZX-ZOLA"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static constexpr const char *FF_PKG     = "com.dts.freefireth";
static constexpr const char *FF_PKG_MAX = "com.dts.freefiremax";

static AsyncWorker g_worker;

class ZxZolaModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
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

        bool is_ff = (strcmp(pkg, FF_PKG) == 0 || strcmp(pkg, FF_PKG_MAX) == 0);
        m_env->ReleaseStringUTFChars(args->nice_name, pkg);

        if (!is_ff) {
            m_api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        m_target = true;
        LOGI("Free Fire detected");
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (!m_target) return;

        g_worker.start();

        g_worker.post([] {
            // 1. Kill-path neutraliser — FIRST: patches kill stubs + MVM
            //    dispatcher on load, delivers seccomp to every new thread
            KillShield::install();

            // 2. Hide ourselves from AnoSDK memory scan
            if (MemoryGuard::init()) {
                MemoryGuard::hideSelf();
            }

            // 3. Intercept AnoSDK reporting — BEFORE it initializes
            AnoBypass::install();

            // 3. Init il2cpp API
            if (!Il2CppApi::init()) {
                LOGE("Il2Cpp init failed");
                return;
            }

            // 4. Features — run delayed to let il2cpp stabilize
            FeatureEngine::get().init(&g_worker);

            LOGI("ZX-ZOLA fully loaded");
        });
    }

private:
    zygisk::Api *m_api    = nullptr;
    JNIEnv      *m_env    = nullptr;
    bool         m_target = false;
};

REGISTER_ZYGISK_MODULE(ZxZolaModule)
