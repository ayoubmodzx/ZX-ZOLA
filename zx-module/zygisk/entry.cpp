#include "../include/zygisk.hpp"
#include <android/log.h>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>

#define TAG "Choreographer"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static constexpr const char *kFfPkgs[] = {
    "com.dts.freefireth",
    "com.dts.freefiremax",
    "com.garena.game.fftw",
    "com.garena.game.kgtw",
    nullptr
};

static constexpr const char *kPayloadPath = "/data/adb/modules/zx_zola_v2/payload.so";

typedef void (*payload_init_fn)(JNIEnv *env);

class GfxModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        m_api = api;
        m_env = env;
        LOGI("onLoad — entry stub attached");
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        m_is_ff = false;
        if (!m_env || !args->nice_name) return;
        const char *name = m_env->GetStringUTFChars(args->nice_name, nullptr);
        if (!name) return;
        LOGI("preAppSpecialize: [%s]", name);
        for (int i = 0; kFfPkgs[i]; ++i) {
            if (strcmp(name, kFfPkgs[i]) == 0) { m_is_ff = true; break; }
        }
        m_env->ReleaseStringUTFChars(args->nice_name, name);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (!m_is_ff) return;

        LOGI("Free Fire detected — loading payload from %s", kPayloadPath);

        void *handle = dlopen(kPayloadPath, RTLD_NOW);
        if (!handle) {
            LOGE("dlopen payload failed: %s", dlerror());
            return;
        }

        auto init = (payload_init_fn)dlsym(handle, "payload_init");
        if (!init) {
            LOGE("dlsym payload_init failed: %s", dlerror());
            dlclose(handle);
            return;
        }

        LOGI("payload loaded — calling payload_init");
        init(m_env);
    }

private:
    zygisk::Api *m_api = nullptr;
    JNIEnv      *m_env = nullptr;
    bool         m_is_ff = false;
};

REGISTER_ZYGISK_MODULE(GfxModule)
