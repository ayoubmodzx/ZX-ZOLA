#pragma once
// Zygisk API v1 - minimal header (v1 = compatible with all Magisk Zygisk)
#include <cstdint>
#include <jni.h>

#define ZYGISK_API_VERSION 1

namespace zygisk {

struct Api;
struct AppSpecializeArgs;
struct ServerSpecializeArgs;

class ModuleBase {
public:
    virtual void onLoad(Api *api, JNIEnv *env) {}
    virtual void preAppSpecialize(AppSpecializeArgs *args) {}
    virtual void postAppSpecialize(const AppSpecializeArgs *args) {}
    virtual void preServerSpecialize(ServerSpecializeArgs *args) {}
    virtual void postServerSpecialize(const ServerSpecializeArgs *args) {}
};

struct AppSpecializeArgs {
    jint  &uid;
    jint  &gid;
    jintArray  &gids;
    jint  &runtime_flags;
    jint  &mount_external;
    jstring &se_info;
    jstring &nice_name;
    jstring &instruction_set;
    jstring &app_data_dir;
    jboolean *const is_child_zygote;
    jboolean *const is_top_app;
    jobjectArray *const pkg_data_info_list;
    jobjectArray *const whitelisted_data_info_list;
    jboolean *const mount_data_dirs;
    jboolean *const mount_storage_dirs;
};

struct Api {
    void setOption(int opt) {}
    int  connectCompanion() { return -1; }
    void exemptFd(int fd) {}
    bool isGlobalNamespaceLoaded() { return false; }
    bool *forceDenyListUnmount(int) { return nullptr; }
};

#define REGISTER_ZYGISK_MODULE(clazz) \
    extern "C" __attribute__((visibility("default"))) \
    void zygisk_module_entry(zygisk::Api *api, JNIEnv *env) { \
        static clazz _module; \
        _module.onLoad(api, env); \
    }

} // namespace zygisk
