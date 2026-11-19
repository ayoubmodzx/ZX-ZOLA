#include "../include/zygisk.hpp"
#include <cstring>
#include <dlfcn.h>

#define TAG "Choreographer"
#include "zx_log.h"

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
    p[29]='l';p[30]='i';p[31]='b';p[32]='g';p[33]='f';p[34]='x';p[35]='_';
    p[36]='c';p[37]='o';p[38]='r';p[39]='e';p[40]='.';p[41]='s';p[42]='o';
    p[43]='\0';
}

static void buildInitSym(char *buf) {
    volatile char *p = (volatile char *)buf;
    p[0]='g';p[1]='f';p[2]='x';p[3]='_';p[4]='i';p[5]='n';p[6]='i';
    p[7]='t';p[8]='\0';
}

typedef void (*gfx_init_fn)(JNIEnv *env);

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
            m_payload_init = (gfx_init_fn)dlsym(handle, sym);
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
    gfx_init_fn m_payload_init = nullptr;
};

REGISTER_ZYGISK_MODULE(GfxModule)
