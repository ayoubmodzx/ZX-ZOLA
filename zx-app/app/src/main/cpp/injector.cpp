// zx_injector — standalone root binary
// Usage: zx_injector <pid> <cmd> <1|0>
// Injects zx_payload.so into FF process via /proc/PID/mem + dlopen shellcode
#include "proc_mem.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <libgen.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <asm/ptrace.h>
#include <elf.h>
#include <errno.h>
#include <android/log.h>

#define TAG "ZX-INJ"
#define LOG(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define ERR(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Feature command IDs — must match Cmd in ZxEngine.kt and features.cpp
enum Cmd {
    ANTI_RECOIL   = 1, NO_SPREAD    = 2,
    RAPID_FIRE    = 3, AIM_ASSIST   = 4,
    SPEED_HACK    = 5, HIGH_JUMP    = 6,
    VEHICLE_SPEED = 7, WIDE_POV     = 8,
    NO_GRASS      = 9, MAX_HEALTH   = 10,
    ANTI_DAMAGE   = 11,
};

// Payload .so path (extracted by ZxEngine.kt into app filesDir)
static constexpr const char *PAYLOAD_NAME = "libzx_payload.so";

// ── ptrace remote call helpers ────────────────────────────────────────────────

static bool ptrace_attach(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0) {
        ERR("ptrace attach failed: %s", strerror(errno));
        return false;
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFSTOPPED(status);
}

static bool ptrace_detach(pid_t pid) {
    return ptrace(PTRACE_DETACH, pid, nullptr, nullptr) == 0;
}

static bool get_regs(pid_t pid, struct pt_regs *regs) {
    struct iovec iov = { regs, sizeof(*regs) };
    return ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) == 0;
}

static bool set_regs(pid_t pid, struct pt_regs *regs) {
    struct iovec iov = { regs, sizeof(*regs) };
    return ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &iov) == 0;
}

// Allocate RWX memory in target process via remote mmap syscall
static uintptr_t remote_mmap(pid_t pid, size_t size) {
    struct pt_regs orig, regs;
    if (!get_regs(pid, &orig)) return 0;

    // Find mmap syscall address in target via maps
    uintptr_t mmap_addr = ProcMem::findSymbol(pid, "libc.so", "mmap");
    if (!mmap_addr) return 0;

    memcpy(&regs, &orig, sizeof(regs));

    // arm64: syscall via SVC #0, args in x0-x5, syscall num in x8
    // mmap(NULL, size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0)
    regs.regs[8]  = 222; // __NR_mmap
    regs.regs[0]  = 0;
    regs.regs[1]  = size;
    regs.regs[2]  = PROT_READ | PROT_WRITE | PROT_EXEC;
    regs.regs[3]  = MAP_PRIVATE | MAP_ANONYMOUS;
    regs.regs[4]  = (uint64_t)-1;
    regs.regs[5]  = 0;
    regs.pc       = mmap_addr;

    if (!set_regs(pid, &regs)) return 0;
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
    waitpid(pid, nullptr, 0);

    get_regs(pid, &regs);
    uintptr_t result = regs.regs[0];

    // Restore original registers
    set_regs(pid, &orig);

    return (result > 0x1000) ? result : 0;
}

// Write memory to target and call dlopen via ptrace
static bool remote_dlopen(pid_t pid, const char *so_path) {
    size_t path_len = strlen(so_path) + 1;
    size_t alloc    = path_len + 128; // path + shellcode space

    // 1. Allocate remote memory
    uintptr_t remote_buf = remote_mmap(pid, alloc);
    if (!remote_buf) { ERR("remote_mmap failed"); return false; }

    // 2. Write path string
    if (!ProcMem::write(remote_buf, so_path, path_len)) {
        ERR("write path failed"); return false;
    }

    // 3. Find dlopen in target
    uintptr_t dlopen_addr = ProcMem::findSymbol(pid, "libdl.so", "dlopen");
    if (!dlopen_addr) { ERR("dlopen not found"); return false; }

    // 4. Set up registers for dlopen(path, RTLD_NOW|RTLD_GLOBAL)
    struct pt_regs orig, regs;
    get_regs(pid, &orig);
    memcpy(&regs, &orig, sizeof(regs));

    regs.regs[0] = remote_buf;            // const char *filename
    regs.regs[1] = RTLD_NOW | RTLD_GLOBAL;
    regs.pc      = dlopen_addr;

    // Set LR to a known trap address so we catch return
    uintptr_t trap_addr = ProcMem::findLibBase(pid, "linker64");
    if (trap_addr) regs.regs[30] = trap_addr; // LR

    set_regs(pid, &regs);
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);

    // Wait for SIGSEGV/SIGILL at trap (dlopen returned)
    int status;
    waitpid(pid, &status, 0);

    // Restore original context
    set_regs(pid, &orig);

    LOG("dlopen complete, signal=%d", WSTOPSIG(status));
    return true;
}

// ── Main ──────────────────────────────────────────────────────────────────────

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: zx_injector <pid> <cmd> <0|1> [payload_path]\n");
        return 1;
    }

    pid_t pid    = atoi(argv[1]);
    int   cmd    = atoi(argv[2]);
    bool  enable = atoi(argv[3]) != 0;

    LOG("ZX Injector — pid=%d cmd=%d enable=%d", pid, cmd, enable);

    // Open /proc/PID/mem (needs root)
    if (!ProcMem::open(pid)) {
        ERR("Cannot open /proc/%d/mem — are we root?", pid);
        return 2;
    }

    // Check if payload is already loaded in target
    uintptr_t payload_base = ProcMem::findLibBase(pid, "libzx_payload.so");

    if (!payload_base) {
        // First activation — inject the payload
        char payload_path[512];
        if (argc >= 5 && argv[4][0] != '\0') {
            // Payload path passed explicitly from ZxEngine (preferred)
            strncpy(payload_path, argv[4], sizeof(payload_path) - 1);
            payload_path[sizeof(payload_path) - 1] = '\0';
        } else {
            // Fallback: derive from our own binary location
            char argv0[512];
            strncpy(argv0, argv[0], sizeof(argv0) - 1);
            argv0[sizeof(argv0) - 1] = '\0';
            snprintf(payload_path, sizeof(payload_path),
                     "%s/libzx_payload.so", dirname(argv0));
        }

        LOG("Injecting payload from %s", payload_path);

        if (!ptrace_attach(pid)) { ProcMem::close(); return 3; }
        bool ok = remote_dlopen(pid, payload_path);
        ptrace_detach(pid);

        if (!ok) { ERR("Injection failed"); ProcMem::close(); return 4; }

        payload_base = ProcMem::findLibBase(pid, "libzx_payload.so");
        LOG("Payload loaded at 0x%lx", payload_base);
    }

    // Send command to payload via shared memory flag
    // The payload polls a small control struct it mmap'd at a known offset
    uintptr_t ctrl_addr = ProcMem::findSymbol(pid, "libzx_payload.so", "g_zx_ctrl");
    if (ctrl_addr) {
        struct { int cmd; int enable; } ctrl = { cmd, enable ? 1 : 0 };
        ProcMem::write(ctrl_addr, ctrl);
        LOG("Command sent: cmd=%d enable=%d", cmd, enable);
    }

    ProcMem::close();
    return 0;
}
