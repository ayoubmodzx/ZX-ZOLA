#pragma once
#include <cstdint>
#include <cstddef>
#include <string>

// /proc/PID/mem read/write — no ptrace needed, just root
namespace ProcMem {
    bool     open(int pid);
    void     close();

    bool     read(uintptr_t addr, void *buf, size_t len);
    bool     write(uintptr_t addr, const void *buf, size_t len);

    template<typename T>
    T        read(uintptr_t addr) {
        T v{}; read(addr, &v, sizeof(T)); return v;
    }
    template<typename T>
    bool     write(uintptr_t addr, T val) {
        return write(addr, &val, sizeof(T));
    }

    // Find a loaded library base address from /proc/PID/maps
    uintptr_t findLibBase(int pid, const char *lib_name);

    // Find a specific symbol offset inside a library using /proc/PID/mem
    uintptr_t findSymbol(int pid, const char *lib_name, const char *sym_name);

    // Like findSymbol but loads the symbol offset from a known local path instead
    // of relying on the soname being in the injector's linker namespace.
    // Use this for memfd-injected libs that appear as "memfd:zx" in /proc/maps.
    uintptr_t findSymbolFromPath(int pid, const char *remote_lib_name,
                                 const char *sym_name, const char *local_path);
}
