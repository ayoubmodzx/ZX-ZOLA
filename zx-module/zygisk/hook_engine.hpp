#pragma once
#include <cstdint>
#include <functional>
#include <unordered_map>
#include <string>

// Minimal hook engine — wraps Dobby, tracks installs, avoids double-hooking
class HookEngine {
public:
    struct HookEntry {
        void  *original;
        void  *replacement;
        void **trampoline;
        bool   installed;
    };

    static HookEngine &get();

    // Hook a specific address — returns true on success
    bool hookAddr(void *target, void *replacement, void **original, const char *tag = "");

    // Hook an exported symbol from a library — null-safe
    bool hookSym(const char *lib, const char *symbol,
                 void *replacement, void **original, const char *tag = "");

    // Remove a specific hook
    bool unhook(void *target);

    // Remove all hooks — call on module unload
    void unhookAll();

    // Get hook count
    size_t count() const;

private:
    HookEngine() = default;
    std::unordered_map<uintptr_t, HookEntry> m_hooks;
};
