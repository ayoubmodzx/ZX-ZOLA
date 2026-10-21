#include "proc_mem.hpp"
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>

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
    size_t done = 0;
    while (done < len) {
        ssize_t n = pread64(g_mem_fd, (char*)buf + done, len - done, (off64_t)(addr + done));
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return true;
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

    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, lib_name)) continue;
        // Only first mapping (text segment)
        if (!strstr(line, "r-xp") && !strstr(line, "r--p")) continue;
        sscanf(line, "%lx", &base);
        break;
    }
    fclose(fp);
    return base;
}

uintptr_t ProcMem::findSymbol(int pid, const char *lib_name, const char *sym_name) {
    // 1. Find base in target process
    uintptr_t remote_base = findLibBase(pid, lib_name);
    if (!remote_base) return 0;

    // 2. Load the same .so locally to get the symbol offset
    void *handle = dlopen(lib_name, RTLD_LAZY | RTLD_NOLOAD);
    if (!handle) handle = dlopen(lib_name, RTLD_LAZY);
    if (!handle) return 0;

    void *local_sym = dlsym(handle, sym_name);
    if (!local_sym) { dlclose(handle); return 0; }

    // 3. Local base of same lib
    Dl_info info;
    dladdr(local_sym, &info);
    uintptr_t local_base = reinterpret_cast<uintptr_t>(info.dli_fbase);

    uintptr_t offset = reinterpret_cast<uintptr_t>(local_sym) - local_base;
    dlclose(handle);

    return remote_base + offset;
}
