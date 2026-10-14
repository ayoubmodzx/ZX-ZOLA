#pragma once
// Zygisk API v5 — mirrors topjohnwu/zygisk-module-sample exactly
#include <jni.h>
#include <cstdint>
#include <sys/types.h>

#define ZYGISK_API_VERSION 5

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

// Forward declarations
class Api;
class ModuleBase;

namespace internal {

struct api_table {
    void    *impl;
    bool     (*registerModule)(api_table *, struct module_abi *);
    void     (*hookJniNativeMethods)(JNIEnv *, const char *, JNINativeMethod *, int);
    void     (*pltHookRegister)(dev_t, ino_t, const char *, void *, void **);
    bool     (*exemptFd)(int);
    bool     (*pltHookCommit)();
    int      (*connectCompanion)(void *);
    void     (*setOption)(void *, Option);
    int      (*getModuleDir)(void *);
    uint32_t (*getFlags)(void *);
};

struct module_abi {
    long        api_version;
    ModuleBase *impl;

    void (*preAppSpecialize)   (ModuleBase *, AppSpecializeArgs *);
    void (*postAppSpecialize)  (ModuleBase *, const AppSpecializeArgs *);
    void (*preServerSpecialize)(ModuleBase *, ServerSpecializeArgs *);
    void (*postServerSpecialize)(ModuleBase *, const ServerSpecializeArgs *);

    explicit module_abi(ModuleBase *module) : api_version(ZYGISK_API_VERSION), impl(module) {
        preAppSpecialize     = [](ModuleBase *m, AppSpecializeArgs *a)         { m->preAppSpecialize(a); };
        postAppSpecialize    = [](ModuleBase *m, const AppSpecializeArgs *a)   { m->postAppSpecialize(a); };
        preServerSpecialize  = [](ModuleBase *m, ServerSpecializeArgs *a)      { m->preServerSpecialize(a); };
        postServerSpecialize = [](ModuleBase *m, const ServerSpecializeArgs *a){ m->postServerSpecialize(a); };
    }
};

} // namespace internal

// ── Api ───────────────────────────────────────────────────────────────────────
class Api {
public:
    internal::api_table *tbl = nullptr;

    void setOption(Option opt) {
        if (tbl && tbl->setOption) tbl->setOption(tbl->impl, opt);
    }
    int connectCompanion() {
        return (tbl && tbl->connectCompanion) ? tbl->connectCompanion(tbl->impl) : -1;
    }
    int getModuleDir() {
        return (tbl && tbl->getModuleDir) ? tbl->getModuleDir(tbl->impl) : -1;
    }
    uint32_t getFlags() {
        return (tbl && tbl->getFlags) ? tbl->getFlags(tbl->impl) : 0u;
    }
    void hookJniNativeMethods(JNIEnv *env, const char *cls,
                              JNINativeMethod *methods, int count) {
        if (tbl && tbl->hookJniNativeMethods)
            tbl->hookJniNativeMethods(env, cls, methods, count);
    }
    void pltHookRegister(dev_t dev, ino_t inode,
                         const char *sym, void *newFn, void **oldFn) {
        if (tbl && tbl->pltHookRegister)
            tbl->pltHookRegister(dev, inode, sym, newFn, oldFn);
    }
    bool pltHookCommit() {
        return (tbl && tbl->pltHookCommit) ? tbl->pltHookCommit() : false;
    }
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

// ── entry_impl (defined after Api and ModuleBase are complete) ────────────────
namespace internal {

template <class T>
void entry_impl(api_table *table, JNIEnv *env) {
    static Api api;
    api.tbl = table;
    static T module;
    ModuleBase *m = &module;
    static module_abi abi(m);
    if (!table->registerModule(table, &abi)) return;
    m->onLoad(&api, env);
}

} // namespace internal

// ── Entry-point macro ─────────────────────────────────────────────────────────
#define REGISTER_ZYGISK_MODULE(clazz)                                              \
extern "C" __attribute__((visibility("default")))                                  \
void zygisk_module_entry(zygisk::internal::api_table *table, JNIEnv *env) {       \
    zygisk::internal::entry_impl<clazz>(table, env);                               \
}

} // namespace zygisk
