#include "proc_mem.hpp"
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <cstdint>

static int g_mem_fd = -1;

bool ProcMem::open(int pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    g_mem_fd = ::open(path, O_RDWR);
    return g_mem_fd >= 0;
}

void ProcMem::close() {
    if (g_mem_fd >= 0) { ::close(g_mem_fd); g_mem_fd = -1; }
}

bool ProcMem::read(uintptr_t addr, void *buf, size_t len) {
    if (g_mem_fd < 0) return false;
    return pread64(g_mem_fd, buf, len, (off64_t)addr) == (ssize_t)len;
}

bool ProcMem::write(uintptr_t addr, const void *buf, size_t len) {
    if (g_mem_fd < 0) return false;
    return pwrite64(g_mem_fd, buf, len, (off64_t)addr) == (ssize_t)len;
}

uintptr_t ProcMem::findLibBase(int pid, const char *lib_name) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *fp = fopen(maps_path, "r");
    if (!fp) return 0;

    char   line[512];
    uintptr_t base = 0;

    // memfd-injected payload shows up as "/memfd:zx (deleted)" in maps,
    // not as "libzx_payload.so".  Accept either form.
    const char *alt_name = nullptr;
    if (strcmp(lib_name, "libzx_payload.so") == 0) alt_name = "memfd:zx";

    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, lib_name) && !(alt_name && strstr(line, alt_name))) continue;
        // Only first executable/read-only mapping (text segment)
        if (!strstr(line, "r-xp") && !strstr(line, "r--p")) continue;
        sscanf(line, "%lx", &base);
        break;
    }
    fclose(fp);
    return base;
}

uintptr_t ProcMem::findSymbol(int pid, const char *lib_name, const char *sym_name) {
    uintptr_t remote_base = findLibBase(pid, lib_name);
    if (!remote_base) return 0;

    void *handle = dlopen(lib_name, RTLD_LAZY | RTLD_NOLOAD);
    if (!handle) handle = dlopen(lib_name, RTLD_LAZY);
    if (!handle) return 0;

    void *local_sym = dlsym(handle, sym_name);
    if (!local_sym) { dlclose(handle); return 0; }

    Dl_info info;
    dladdr(local_sym, &info);
    uintptr_t local_base = reinterpret_cast<uintptr_t>(info.dli_fbase);
    uintptr_t offset = reinterpret_cast<uintptr_t>(local_sym) - local_base;
    dlclose(handle);

    return remote_base + offset;
}

uintptr_t ProcMem::findCtrlByMagic(int pid) {
    uintptr_t base = findLibBase(pid, "libzx_payload.so"); // memfd:zx alias handled
    if (!base) return 0;

    static const uint64_t kTag[2] = {
        0xDEADBEEFC0DE5A5AULL, 0x5A5AFACE00000012ULL
    };

    // Scan 4KB chunks with 15-byte overlap to catch boundary-split matches.
    // .data is usually within the first 2MB; scan up to 8MB to be safe.
    const size_t CHUNK = 4096;
    uint8_t buf[CHUNK];
    for (size_t off = 0; off < 8u * 1024u * 1024u; off += CHUNK - 15u) {
        if (!read(base + off, buf, CHUNK)) continue;
        for (size_t i = 0; i + 16u <= CHUNK; i++) {
            if (memcmp(buf + i, kTag, 16) == 0)
                return base + off + i + 16u; // ctrl.cmd is 16 bytes after tag
        }
    }
    return 0;
}

uintptr_t ProcMem::findSymbolFromPath(int pid, const char *remote_lib_name,
                                      const char *sym_name, const char *local_path) {
    // Remote base: findLibBase already handles the "libzx_payload.so" → "memfd:zx" alias
    uintptr_t remote_base = findLibBase(pid, remote_lib_name);
    if (!remote_base) return 0;

    // Load local copy by path (not soname) so this works even if the injector
    // never had the lib in its own linker namespace (e.g. after memfd injection).
    void *handle = dlopen(local_path, RTLD_LAZY | RTLD_LOCAL);
    if (!handle) return 0;

    void *local_sym = dlsym(handle, sym_name);
    if (!local_sym) { dlclose(handle); return 0; }

    Dl_info info;
    dladdr(local_sym, &info);
    uintptr_t local_base = reinterpret_cast<uintptr_t>(info.dli_fbase);
    uintptr_t offset = reinterpret_cast<uintptr_t>(local_sym) - local_base;
    dlclose(handle);

    return remote_base + offset;
}
