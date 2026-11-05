#pragma once
#include <cstdint>
#include <functional>
#include <unordered_map>
#include <string>

// Minimal hook engine — Dobby inline hooks + MethodInfo pointer swaps.
// MethodInfo pointer swap: changes MethodInfo::methodPointer (offset 0, a DATA
// field) instead of patching .text opcodes.  AnoSDK's ms_hook_opcode scanner
// reads the .text section for Dobby branch trampolines — pointer swaps are
// invisible to that scanner because no code bytes are modified.
class HookEngine {
public:
    struct HookEntry {
        void  *original;
        void  *replacement;
        void **trampoline;
        bool   installed;
        bool   method_swap;   // true = MethodInfo pointer swap, false = Dobby
    };

    static HookEngine &get();

    // Hook a specific code address via Dobby inline hook — modifies .text bytes.
    // Use ONLY for non-IL2CPP targets (e.g. libc GOT, native stubs).
    bool hookAddr(void *target, void *replacement, void **original, const char *tag = "");

    // Hook an exported symbol from a library via Dobby
    bool hookSym(const char *lib, const char *symbol,
                 void *replacement, void **original, const char *tag = "");

    // Hook an IL2CPP MethodInfo by swapping its methodPointer (offset 0).
    // NEVER modifies .text — safe against code-integrity scanners.
    // methodInfo must point to a valid MethodInfo struct.
    bool hookMethod(void *methodInfo, void *replacement, void **original, const char *tag = "");

    // Remove a Dobby inline hook
    bool unhook(void *target);

    // Remove a MethodInfo pointer-swap hook (restores original pointer)
    bool unhookMethod(void *methodInfo);

    // Remove all hooks — call on module unload
    void unhookAll();

    // Get hook count
    size_t count() const;

private:
    HookEngine() = default;
    std::unordered_map<uintptr_t, HookEntry> m_hooks;
};
