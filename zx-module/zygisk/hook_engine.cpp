#include "hook_engine.hpp"
#include "../include/dobby.h"
#include <dlfcn.h>
#include <android/log.h>

#define TAG "ZX-HOOK"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

HookEngine &HookEngine::get() {
    static HookEngine instance;
    return instance;
}

bool HookEngine::hookAddr(void *target, void *replacement,
                           void **original, const char *tag) {
    if (!target || !replacement) {
        LOGE("[%s] null target or replacement", tag);
        return false;
    }

    uintptr_t key = reinterpret_cast<uintptr_t>(target);

    // Don't double-hook
    if (m_hooks.count(key) && m_hooks[key].installed) {
        LOGI("[%s] already hooked at %p, skipping", tag, target);
        return true;
    }

    int ret = DobbyHook(target, replacement, original);
    if (ret != 0) {
        LOGE("[%s] DobbyHook failed at %p, ret=%d", tag, target, ret);
        return false;
    }

    m_hooks[key] = { .original = *original,
                     .replacement = replacement,
                     .trampoline  = original,
                     .installed   = true };

    LOGI("[%s] hooked %p -> %p", tag, target, replacement);
    return true;
}

bool HookEngine::hookSym(const char *lib, const char *symbol,
                          void *replacement, void **original, const char *tag) {
    void *handle = dlopen(lib, RTLD_LAZY | RTLD_NOLOAD);
    if (!handle) {
        LOGE("[%s] dlopen %s failed", tag, lib);
        return false;
    }

    void *sym = dlsym(handle, symbol);
    dlclose(handle);

    if (!sym) {
        // Try Dobby's resolver as fallback
        sym = DobbySymbolResolver(lib, symbol);
    }

    if (!sym) {
        LOGE("[%s] symbol %s not found in %s", tag, symbol, lib);
        return false;
    }

    return hookAddr(sym, replacement, original, tag);
}

bool HookEngine::unhook(void *target) {
    uintptr_t key = reinterpret_cast<uintptr_t>(target);
    auto it = m_hooks.find(key);
    if (it == m_hooks.end() || !it->second.installed) return false;

    DobbyDestroy(target);
    it->second.installed = false;
    LOGI("Unhooked %p", target);
    return true;
}

void HookEngine::unhookAll() {
    for (auto &[addr, entry] : m_hooks) {
        if (entry.installed) {
            DobbyDestroy(reinterpret_cast<void *>(addr));
            entry.installed = false;
        }
    }
    m_hooks.clear();
    LOGI("All hooks removed");
}

size_t HookEngine::count() const {
    size_t n = 0;
    for (auto &[_, e] : m_hooks) n += e.installed ? 1 : 0;
    return n;
}
