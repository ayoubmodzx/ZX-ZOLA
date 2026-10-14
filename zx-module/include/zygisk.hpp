#pragma once
// Zygisk API v4 — compatible with Magisk 26.0+ / Magisk 30.x stable
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
    jint         &uid;
    jint         &gid;
    jintArray    &gids;
    jint         &runtime_flags;
    jint         &mount_external;
    jstring      &se_info;
    jstring      &nice_name;
    jstring      &instruction_set;
    jstring      &app_data_dir;
    jboolean     *const is_child_zygote;
    jboolean     *const is_top_app;
    jobjectArray *const pkg_data_info_list;
    jobjectArray *const whitelisted_data_info_list;
    jboolean     *const mount_data_dirs;
    jboolean     *const mount_storage_dirs;
};

struct ServerSpecializeArgs {
    jint      &uid;
    jint      &gid;
    jintArray &gids;
    jint      &runtime_flags;
    jlong     &permitted_capabilities;
    jlong     &effective_capabilities;
};

class ModuleBase;

// ── Internal ABI ──────────────────────────────────────────────────────────────
namespace internal {

struct module_abi {
    long        api_version;
    ModuleBase *impl;
    void (*preAppSpecialize)   (ModuleBase *, AppSpecializeArgs *);
    void (*postAppSpecialize)  (ModuleBase *, const AppSpecializeArgs *);
    void (*preServerSpecialize)(ModuleBase *, ServerSpecializeArgs *);
    void (*postServerSpecialize)(ModuleBase *, const ServerSpecializeArgs *);
};

// Matches Magisk's internal api_table exactly — field order and types are ABI.
// impl is an opaque context pointer; pass it as first arg to every callback.
struct api_table {
    void    *impl;
    bool     (*registerModule)(api_table *, module_abi *);
    void     (*hookJniNativeMethods)(JNIEnv *, const char *, JNINativeMethod *, int);
    void     (*pltHookRegister)(dev_t, ino_t, const char *, void *, void **);
    bool     (*exemptFd)(int);
    bool     (*pltHookCommit)();
    int      (*connectCompanion)(void *);
    void     (*setOption)(void *, Option);
    int      (*getModuleDir)(void *);
    uint32_t (*getFlags)(void *);
};

} // namespace internal

// ── Api ───────────────────────────────────────────────────────────────────────
class Api {
public:
    explicit Api(internal::api_table *t) : impl(t) {}

    void setOption(Option opt) {
        if (impl && impl->setOption) impl->setOption(impl->impl, opt);
    }
    int connectCompanion() {
        return (impl && impl->connectCompanion) ? impl->connectCompanion(impl->impl) : -1;
    }
    int getModuleDir() {
        return (impl && impl->getModuleDir) ? impl->getModuleDir(impl->impl) : -1;
    }
    uint32_t getFlags() {
        return (impl && impl->getFlags) ? impl->getFlags(impl->impl) : 0u;
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
    bool pltHookCommit() {
        return (impl && impl->pltHookCommit) ? impl->pltHookCommit() : false;
    }

private:
    internal::api_table *impl;
};

// ── ModuleBase ────────────────────────────────────────────────────────────────
class ModuleBase {
public:
    virtual void onLoad(Api *api, JNIEnv *env)                          {}
    virtual void preAppSpecialize(AppSpecializeArgs *args)              {}
    virtual void postAppSpecialize(const AppSpecializeArgs *args)       {}
    virtual void preServerSpecialize(ServerSpecializeArgs *args)        {}
    virtual void postServerSpecialize(const ServerSpecializeArgs *args) {}
    virtual ~ModuleBase() = default;
};

// ── Entry-point macro ─────────────────────────────────────────────────────────
#define REGISTER_ZYGISK_MODULE(clazz)                                             \
extern "C" __attribute__((visibility("default")))                                 \
void zygisk_module_entry(zygisk::internal::api_table *table, JNIEnv *env) {      \
    static clazz _module;                                                         \
    static zygisk::internal::module_abi _abi = {                                  \
        ZYGISK_API_VERSION,                                                       \
        &_module,                                                                 \
        [](zygisk::ModuleBase *m, zygisk::AppSpecializeArgs *a) {                \
            m->preAppSpecialize(a);                                               \
        },                                                                        \
        [](zygisk::ModuleBase *m, const zygisk::AppSpecializeArgs *a) {          \
            m->postAppSpecialize(a);                                              \
        },                                                                        \
        [](zygisk::ModuleBase *m, zygisk::ServerSpecializeArgs *a) {             \
            m->preServerSpecialize(a);                                            \
        },                                                                        \
        [](zygisk::ModuleBase *m, const zygisk::ServerSpecializeArgs *a) {       \
            m->postServerSpecialize(a);                                           \
        },                                                                        \
    };                                                                            \
    static zygisk::Api _api(table);                                               \
    if (table && table->registerModule && table->registerModule(table, &_abi)) { \
        _module.onLoad(&_api, env);                                               \
    }                                                                             \
}

} // namespace zygisk
