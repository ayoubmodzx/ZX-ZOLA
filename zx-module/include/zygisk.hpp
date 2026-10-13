#pragma once
// Official Zygisk API v4 — matches Magisk 24.2+ ABI exactly
// Stub methods replaced with real api_table function-pointer dispatch.
#include <jni.h>
#include <cstdint>
#include <sys/types.h>

#define ZYGISK_API_VERSION 4

namespace zygisk {

enum Option : int {
    FORCE_DENYLIST_UNMOUNT = 0,
    DLCLOSE_MODULE_LIBRARY = 1,
};

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
    jboolean    *const is_child_zygote;
    jboolean    *const is_top_app;
    jobjectArray *const pkg_data_info_list;
    jobjectArray *const whitelisted_data_info_list;
    jboolean    *const mount_data_dirs;
    jboolean    *const mount_storage_dirs;
};

struct ServerSpecializeArgs {
    jint  &uid;
    jint  &gid;
    jintArray &gids;
    jint  &runtime_flags;
    jlong &permitted_capabilities;
    jlong &effective_capabilities;
};

namespace internal { struct api_table; struct module_abi; }

class ModuleBase;

class Api {
public:
    void setOption(Option opt) {
        if (impl && impl->setOption) impl->setOption(impl, opt);
    }
    int connectCompanion() {
        return (impl && impl->connectCompanion) ? impl->connectCompanion(impl) : -1;
    }
    void hookJniNativeMethods(JNIEnv *env, const char *cls,
                              JNINativeMethod *methods, int count) {
        if (impl && impl->hookJniNativeMethods)
            impl->hookJniNativeMethods(env, cls, methods, count);
    }
    void pltHookRegister(dev_t dev, ino_t inode,
                         const char *sym, void *newFn, void **oldFn) {
        if (impl && impl->pltHookRegister)
            impl->pltHookRegister(dev, inode, sym, newFn, oldFn);
    }
    void pltHookExclude(const char *module, const char *sym) {
        if (impl && impl->pltHookExclude) impl->pltHookExclude(module, sym);
    }
    bool pltHookCommit() {
        return (impl && impl->pltHookCommit) ? impl->pltHookCommit() : false;
    }
private:
    internal::api_table *impl;
    Api() = delete;
    explicit Api(internal::api_table *t) : impl(t) {}
    friend struct internal::api_table;
    friend struct internal::module_abi;
};

class ModuleBase {
public:
    virtual void onLoad(Api *api, JNIEnv *env)                           {}
    virtual void preAppSpecialize(AppSpecializeArgs *args)               {}
    virtual void postAppSpecialize(const AppSpecializeArgs *args)        {}
    virtual void preServerSpecialize(ServerSpecializeArgs *args)         {}
    virtual void postServerSpecialize(const ServerSpecializeArgs *args)  {}
    virtual ~ModuleBase() = default;
};

// ── Internal ABI structures ────────────────────────────────────────────────
namespace internal {

struct api_table {
    void *_reserved;                    // Magisk-internal use
    bool (*registerModule)(api_table *, long *);
    void (*hookJniNativeMethods)(JNIEnv *, const char *, JNINativeMethod *, int);
    void (*pltHookRegister)(dev_t, ino_t, const char *, void *, void **);
    void (*pltHookExclude)(const char *, const char *);
    bool (*pltHookCommit)();
    int  (*connectCompanion)(api_table *);
    void (*setOption)(api_table *, Option);
};

struct module_abi {
    long         api_version;   // must be first — Magisk reads this to gate compat
    ModuleBase  *module;
    void (*preAppSpecialize)   (ModuleBase *, AppSpecializeArgs *);
    void (*postAppSpecialize)  (ModuleBase *, const AppSpecializeArgs *);
    void (*preServerSpecialize)(ModuleBase *, ServerSpecializeArgs *);
    void (*postServerSpecialize)(ModuleBase *, const ServerSpecializeArgs *);
};

} // namespace internal

// ── Module registration macro ──────────────────────────────────────────────
// Entry point Magisk dlsym-looks for. Takes internal api_table*, calls
// registerModule so Magisk knows our ABI version and callback table.
#define REGISTER_ZYGISK_MODULE(clazz)                                            \
extern "C" __attribute__((visibility("default")))                                \
void zygisk_module_entry(zygisk::internal::api_table *table, JNIEnv *env) {     \
    static clazz _module;                                                        \
    static zygisk::internal::module_abi _abi = {                                 \
        ZYGISK_API_VERSION,                                                      \
        &_module,                                                                \
        [](zygisk::ModuleBase *m, zygisk::AppSpecializeArgs *a) {               \
            m->preAppSpecialize(a);                                              \
        },                                                                       \
        [](zygisk::ModuleBase *m, const zygisk::AppSpecializeArgs *a) {         \
            m->postAppSpecialize(a);                                             \
        },                                                                       \
        [](zygisk::ModuleBase *m, zygisk::ServerSpecializeArgs *a) {            \
            m->preServerSpecialize(a);                                           \
        },                                                                       \
        [](zygisk::ModuleBase *m, const zygisk::ServerSpecializeArgs *a) {      \
            m->postServerSpecialize(a);                                          \
        },                                                                       \
    };                                                                           \
    static zygisk::Api _api(table);  /* static: table ptr is Magisk-owned, lives forever */ \
    if (table && table->registerModule && table->registerModule(table, (long *)&_abi)) { \
        _module.onLoad(&_api, env);                                              \
    }                                                                            \
}

} // namespace zygisk
