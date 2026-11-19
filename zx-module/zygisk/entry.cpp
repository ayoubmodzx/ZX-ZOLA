#include "../include/zygisk.hpp"
#include <android/log.h>
#include <cstring>
#include <dlfcn.h>

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

// Runtime path builder — keeps module path out of .rodata so AnoSDK memory
// scanners can't pattern-match it in anonymous pages after hideModuleMaps.
static void buildPayloadPath(char *buf) {
    volatile char *p = (volatile char *)buf;
    p[0]='/';p[1]='d';p[2]='a';p[3]='t';p[4]='a';p[5]='/';p[6]='a';p[7]='d';
    p[8]='b';p[9]='/';p[10]='m';p[11]='o';p[12]='d';p[13]='u';p[14]='l';
    p[15]='e';p[16]='s';p[17]='/';p[18]='z';p[19]='x';p[20]='_';p[21]='z';
    p[22]='o';p[23]='l';p[24]='a';p[25]='_';p[26]='v';p[27]='2';p[28]='/';
    p[29]='p';p[30]='a';p[31]='y';p[32]='l';p[33]='o';p[34]='a';p[35]='d';
    p[36]='.';p[37]='s';p[38]='o';p[39]='\0';
}

static void buildInitSym(char *buf) {
    volatile char *p = (volatile char *)buf;
    p[0]='p';p[1]='a';p[2]='y';p[3]='l';p[4]='o';p[5]='a';p[6]='d';
    p[7]='_';p[8]='i';p[9]='n';p[10]='i';p[11]='t';p[12]='\0';
}

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
        m_payload_init = nullptr;
        if (!m_env || !args->nice_name) return;
        const char *name = m_env->GetStringUTFChars(args->nice_name, nullptr);
        if (!name) return;
        LOGI("preAppSpecialize: [%s]", name);
        for (int i = 0; kFfPkgs[i]; ++i) {
            if (strcmp(name, kFfPkgs[i]) == 0) { m_is_ff = true; break; }
        }
        m_env->ReleaseStringUTFChars(args->nice_name, name);

        if (m_is_ff) {
            LOGI("target matched — loading runtime component");
            char path[64];
            buildPayloadPath(path);
            void *handle = dlopen(path, RTLD_NOW);
            memset(path, 0, sizeof(path));
            if (!handle) {
                LOGE("dlopen failed: %s", dlerror());
                return;
            }
            char sym[16];
            buildInitSym(sym);
            m_payload_init = (payload_init_fn)dlsym(handle, sym);
            memset(sym, 0, sizeof(sym));
            if (!m_payload_init) {
                LOGE("dlsym init failed: %s", dlerror());
                dlclose(handle);
                return;
            }
            LOGI("runtime component ready");
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (!m_is_ff || !m_payload_init) return;
        LOGI("postAppSpecialize — initializing");
        m_payload_init(m_env);
    }

private:
    zygisk::Api *m_api = nullptr;
    JNIEnv      *m_env = nullptr;
    bool         m_is_ff = false;
    payload_init_fn m_payload_init = nullptr;
};

REGISTER_ZYGISK_MODULE(GfxModule)
