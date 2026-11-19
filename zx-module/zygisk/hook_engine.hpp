#pragma once
#include <cstdint>
#include <functional>
#include <unordered_map>
#include <string>

class HookEngine {
public:
    struct HookEntry {
        void  *original;
        void  *replacement;
        void **trampoline;
        bool   installed;
    };

    static HookEngine &get();

    bool hookMethod(void *methodInfo, void *replacement, void **original, const char *tag = "");
    bool unhook(void *target);
    bool unhookMethod(void *methodInfo);
    void unhookAll();
    size_t count() const;

private:
    HookEngine() = default;
    std::unordered_map<uintptr_t, HookEntry> m_hooks;
};
