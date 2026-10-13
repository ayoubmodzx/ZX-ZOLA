#pragma once
// Zygisk API v4 — proper C-ABI header for Magisk 26+ (tested: 30.7)
// zygisk_module_entry returns ModuleAbi* — Magisk reads api_version from it.
#include <cstdint>
#include <jni.h>

#define ZYGISK_API_VERSION 4

namespace zygisk {

struct Api;

struct AppSpecializeArgs {
    jint        &uid;
    jint        &gid;
    jintArray   &gids;
    jint        &runtime_flags;
    jint        &mount_external;
    jstring     &se_info;
    jstring     &nice_name;
    jstring     &instruction_set;
    jstring     &app_data_dir;
    jboolean *const is_child_zygote;
    jboolean *const is_top_app;
    jobjectArray *const pkg_data_info_list;
    jobjectArray *const whitelisted_data_info_list;
    jboolean *const mount_data_dirs;
    jboolean *const mount_storage_dirs;
};

struct ServerSpecializeArgs {
    jint  &uid;
    jint  &gid;
    jintArray &gids;
    jint  &runtime_flags;
    jlong &permitted_capabilities;
    jlong &effective_capabilities;
};

class ModuleBase {
public:
    virtual void onLoad(Api *api, JNIEnv *env) {}
    virtual void preAppSpecialize(AppSpecializeArgs *args) {}
    virtual void postAppSpecialize(const AppSpecializeArgs *args) {}
    virtual void preServerSpecialize(ServerSpecializeArgs *args) {}
    virtual void postServerSpecialize(const ServerSpecializeArgs *args) {}
    virtual ~ModuleBase() = default;
};

// Minimal Api stub — setOption is no-op; module loads in all processes
// but only acts in the target (Free Fire). Acceptable trade-off.
struct Api {
    void setOption(int) {}
    int  connectCompanion() { return -1; }
    void exemptFd(int) {}
    bool isGlobalNamespaceLoaded() { return false; }
};

// ── C ABI bridge — this is what Magisk actually reads at runtime ──────────────
namespace internal {

struct ModuleAbi {
    long   api_version;   // FIRST field — Magisk checks this for compatibility
    void  *impl;          // pointer to the ModuleBase instance

    // Callbacks — Magisk calls these via function pointers (no vtable lookup)
    void (*preAppSpecialize   )(void *, AppSpecializeArgs *);
    void (*postAppSpecialize  )(void *, const AppSpecializeArgs *);
    void (*preServerSpecialize)(void *, ServerSpecializeArgs *);
    void (*postServerSpecialize)(void *, const ServerSpecializeArgs *);
};

template<class T>
struct Adapter {
    static void preApp  (void *s, AppSpecializeArgs          *a) { static_cast<T*>(s)->preAppSpecialize(a);    }
    static void postApp (void *s, const AppSpecializeArgs    *a) { static_cast<T*>(s)->postAppSpecialize(a);   }
    static void preSrv  (void *s, ServerSpecializeArgs       *a) { static_cast<T*>(s)->preServerSpecialize(a); }
    static void postSrv (void *s, const ServerSpecializeArgs *a) { static_cast<T*>(s)->postServerSpecialize(a);}

    static ModuleAbi *make(T *mod) {
        static ModuleAbi abi {
            ZYGISK_API_VERSION, mod,
            preApp, postApp, preSrv, postSrv
        };
        abi.impl = mod; // refresh impl pointer on each call (static module, same addr)
        return &abi;
    }
};

} // namespace internal

// ── Module registration macro — expands at file scope in the .cpp ─────────────
#define REGISTER_ZYGISK_MODULE(clazz)                                                \
    extern "C" __attribute__((visibility("default"))) __attribute__((used))          \
    zygisk::internal::ModuleAbi *zygisk_module_entry(zygisk::Api *api, JNIEnv *env){ \
        static clazz _m;                                                              \
        _m.onLoad(api, env);                                                          \
        return zygisk::internal::Adapter<clazz>::make(&_m);                          \
    }

} // namespace zygisk
