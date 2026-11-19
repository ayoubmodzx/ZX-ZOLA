#include "il2cpp_api.hpp"
#include "hook_engine.hpp"
#include "async_worker.hpp"
#include "feature_engine.hpp"
#include "anosdk_bypass.hpp"
#include "memory_guard.hpp"
#include <jni.h>

#define TAG "Choreographer"
#include "zx_log.h"

static AsyncWorker g_worker;

extern "C" __attribute__((visibility("default")))
void gfx_init(JNIEnv *env) {
    (void)env;
    LOGI("renderer pipeline init");

    AnoBypass::installEarly();

    g_worker.start();

    g_worker.post([] {
        if (MemoryGuard::init()) {
            MemoryGuard::hideSelf();
        }

        AnoBypass::startWatcher();

        struct Il2CppInitRetry {
            static void attempt(AsyncWorker *worker, int tries_left) {
                if (Il2CppApi::init()) {
                    FeatureEngine::get().init(worker);
                    LOGI("renderer pipeline active");
                    return;
                }
                if (tries_left <= 0) {
                    LOGE("Il2Cpp init failed after all retries");
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
