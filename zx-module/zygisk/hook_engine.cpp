#include "hook_engine.hpp"
#include "../include/dobby.h"
#include "../include/il2cpp_types.hpp"
#include <dlfcn.h>
#include <android/log.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

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

    if (m_hooks.count(key) && m_hooks[key].installed) {
        LOGI("[%s] already hooked at %p, skipping", tag, target);
        return true;
    }

    int ret = DobbyHook(target, replacement, original);
    if (ret != 0) {
        LOGE("[%s] DobbyHook failed at %p, ret=%d", tag, target, ret);
        return false;
    }

    m_hooks[key] = { .original    = (original ? *original : nullptr),
                     .replacement = replacement,
                     .trampoline  = original,
                     .installed   = true,
                     .method_swap = false };

    LOGI("[%s] dobby-hooked %p -> %p", tag, target, replacement);
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
        sym = dlsym(RTLD_DEFAULT, symbol);
    }

    if (!sym) {
        LOGE("[%s] symbol %s not found in %s", tag, symbol, lib);
        return false;
    }

    return hookAddr(sym, replacement, original, tag);
}

// MethodInfo pointer swap — changes the methodPointer field (offset 0 in the
// MethodInfo struct) without touching any .text code page.  AnoSDK's inline
// hook opcode scanner is blind to data-only modifications.
bool HookEngine::hookMethod(void *methodInfo, void *replacement,
                             void **original, const char *tag) {
    if (!methodInfo || !replacement) {
        LOGE("[%s] null methodInfo or replacement", tag);
        return false;
    }

    // Cast to MethodInfo* — methodPointer is at offset 8 (after name ptr)
    auto *mi = static_cast<MethodInfo *>(methodInfo);
    void **slot = reinterpret_cast<void **>(&mi->methodPointer);
    void *orig = mi->methodPointer;

    if (!orig) {
        LOGE("[%s] methodPointer is null in methodInfo %p", tag, methodInfo);
        return false;
    }

    uintptr_t key = reinterpret_cast<uintptr_t>(methodInfo);
    if (m_hooks.count(key) && m_hooks[key].installed) {
        LOGI("[%s] already method-hooked at %p, skipping", tag, methodInfo);
        if (original) *original = m_hooks[key].original;
        return true;
    }

    if (original) *original = orig;

    // Attempt direct write first (MethodInfo is usually heap-allocated → writable)
    *slot = replacement;
    __sync_synchronize();

    // Verify the write stuck — if the page was RO the write silently failed on
    // some kernels.  Fall back to mprotect then /proc/self/mem.
    if (*slot != replacement) {
        uintptr_t page = reinterpret_cast<uintptr_t>(slot) & ~0xFFFULL;
        if (mprotect(reinterpret_cast<void *>(page), 4096,
                     PROT_READ | PROT_WRITE) == 0) {
            *slot = replacement;
            __sync_synchronize();
        }
        if (*slot != replacement) {
            int fd = open("/proc/self/mem", O_WRONLY);
            if (fd >= 0) {
                pwrite(fd, &replacement, sizeof(void *),
                       static_cast<off_t>(reinterpret_cast<uintptr_t>(slot)));
                close(fd);
            }
        }
        if (*slot != replacement) {
            LOGE("[%s] method-swap FAILED at %p — page unwritable", tag, methodInfo);
            return false;
        }
    }

    m_hooks[key] = { .original    = orig,
                     .replacement = replacement,
                     .trampoline  = original,
                     .installed   = true,
                     .method_swap = true };

    LOGI("[%s] method-swap %p: %p -> %p (no .text modification)", tag, methodInfo, orig, replacement);
    return true;
}

bool HookEngine::unhook(void *target) {
    uintptr_t key = reinterpret_cast<uintptr_t>(target);
    auto it = m_hooks.find(key);
    if (it == m_hooks.end() || !it->second.installed) return false;

    if (it->second.method_swap) {
        return unhookMethod(target);
    }

    DobbyDestroy(target);
    it->second.installed = false;
    LOGI("Dobby-unhooked %p", target);
    return true;
}

bool HookEngine::unhookMethod(void *methodInfo) {
    uintptr_t key = reinterpret_cast<uintptr_t>(methodInfo);
    auto it = m_hooks.find(key);
    if (it == m_hooks.end() || !it->second.installed) return false;

    auto *mi = static_cast<MethodInfo *>(methodInfo);
    void **slot = reinterpret_cast<void **>(&mi->methodPointer);
    *slot = it->second.original;
    __sync_synchronize();

    if (*slot != it->second.original) {
        uintptr_t page = reinterpret_cast<uintptr_t>(slot) & ~0xFFFULL;
        mprotect(reinterpret_cast<void *>(page), 4096, PROT_READ | PROT_WRITE);
        *slot = it->second.original;
        __sync_synchronize();
    }

    it->second.installed = false;
    LOGI("Method-swap unhooked %p (restored %p)", methodInfo, it->second.original);
    return true;
}

void HookEngine::unhookAll() {
    for (auto &[addr, entry] : m_hooks) {
        if (!entry.installed) continue;
        if (entry.method_swap) {
            auto *mi = reinterpret_cast<MethodInfo *>(addr);
            mi->methodPointer = entry.original;
        } else {
            DobbyDestroy(reinterpret_cast<void *>(addr));
        }
        entry.installed = false;
    }
    __sync_synchronize();
    m_hooks.clear();
    LOGI("All hooks removed");
}

size_t HookEngine::count() const {
    size_t n = 0;
    for (auto &[_, e] : m_hooks) n += e.installed ? 1 : 0;
    return n;
}
