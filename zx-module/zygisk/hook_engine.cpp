#include "hook_engine.hpp"
#include "../include/il2cpp_types.hpp"
#include <dlfcn.h>
#include <android/log.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

#define TAG "art"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

HookEngine &HookEngine::get() {
    static HookEngine instance;
    return instance;
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
                     .installed   = true };

    LOGI("[%s] method-swap %p: %p -> %p (no .text modification)", tag, methodInfo, orig, replacement);
    return true;
}

bool HookEngine::unhook(void *target) {
    uintptr_t key = reinterpret_cast<uintptr_t>(target);
    auto it = m_hooks.find(key);
    if (it == m_hooks.end() || !it->second.installed) return false;
    return unhookMethod(target);
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
        auto *mi = reinterpret_cast<MethodInfo *>(addr);
        mi->methodPointer = entry.original;
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
