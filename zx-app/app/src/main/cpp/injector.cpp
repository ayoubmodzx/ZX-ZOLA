// zx_injector — standalone root binary
// Usage: zx_injector <pid> <cmd> <1|0>
// Injects zx_payload.so into FF process via /proc/PID/mem + dlopen shellcode
// NOTE: This binary is ARM64-only; FF is a 64-bit process and ptrace
//       register layout below is ARM64-specific (user_pt_regs / .regs[] / .pc).
//       ARM32 builds compile a stub that exits immediately.

#ifdef __aarch64__

#include "proc_mem.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <libgen.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <asm/ptrace.h>
#include <elf.h>
// Android NDK ARM64 provides user_pt_regs, not pt_regs, in userspace headers
typedef struct user_pt_regs pt_regs;
#include <errno.h>
#include <android/log.h>
#include <dirent.h>
#include <cstdarg>

#define TAG "ZX-INJ"
#define LOG(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define ERR(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Write to both logcat AND stderr — stderr is captured by ZxEngine and shown
// in the in-app console, which logcat-only ERR() never reaches.
__attribute__((format(printf,1,2)))
static void zerr(const char *fmt, ...) {
    char buf[256];
    va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    __android_log_print(ANDROID_LOG_ERROR, TAG, "%s", buf);
    fprintf(stderr, "%s\n", buf);
}

// Feature command IDs — must match Cmd in ZxEngine.kt and features.cpp
enum Cmd {
    ANTI_RECOIL     = 1,  NO_SPREAD       = 2,
    RAPID_FIRE      = 3,  WIDE_POV        = 4,
    ESP             = 5,  SPEED_HACK      = 6,
    HIGH_JUMP       = 7,  VEHICLE_SPEED   = 8,
    RAPID_FIRE_RISK = 9,  NO_GRASS        = 10,
    ANTI_DAMAGE     = 11,
    AIM_ENABLE      = 12, AIM_BONE        = 13,
    AIM_FOV         = 14, AIM_SMOOTH      = 15,
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

// Freeze all threads in the process EXCEPT the main thread (already attached).
// This prevents anti-cheat threads from detecting ptrace during the injection window.
static pid_t s_extra_tids[256];
static int   s_extra_n = 0;

static void freeze_threads(pid_t pid) {
    char path[64]; snprintf(path, sizeof(path), "/proc/%d/task", pid);
    DIR *d = opendir(path); if (!d) return;
    struct dirent *e; s_extra_n = 0;
    while ((e = readdir(d)) != nullptr && s_extra_n < 256) {
        if (e->d_name[0] == '.') continue;
        pid_t tid = (pid_t)atoi(e->d_name);
        if (tid <= 0 || tid == pid) continue;
        if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == 0) {
            int st; waitpid(tid, &st, 0);
            s_extra_tids[s_extra_n++] = tid;
        }
    }
    closedir(d);
    LOG("freeze_threads: stopped %d extra threads", s_extra_n);
}

static void thaw_threads() {
    for (int i = 0; i < s_extra_n; i++)
        ptrace(PTRACE_DETACH, s_extra_tids[i], nullptr, nullptr);
    s_extra_n = 0;
}

static bool get_regs(pid_t pid, pt_regs *regs) {
    struct iovec iov = { regs, sizeof(*regs) };
    return ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) == 0;
}

static bool set_regs(pid_t pid, pt_regs *regs) {
    struct iovec iov = { regs, sizeof(*regs) };
    return ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &iov) == 0;
}

// Scan target's libc.so for a raw SVC #0 gadget — bypasses BTI/CFI on the mmap wrapper.
// ARM64 SVC #0 encoding (LE): 0xD4000001
static uintptr_t find_svc_gadget(pid_t pid) {
    uintptr_t base = ProcMem::findLibBase(pid, "libc.so");
    if (!base) { zerr("find_svc_gadget: libc.so not mapped"); return 0; }
    static uint8_t s_buf[65536];
    const uint32_t SVC0 = 0xD4000001u;
    for (size_t off = 0; off < 3 * 1024 * 1024; off += sizeof(s_buf)) {
        if (!ProcMem::read(base + off, s_buf, sizeof(s_buf))) continue;
        for (size_t i = 0; i + 4 <= sizeof(s_buf); i += 4) {
            uint32_t insn;
            memcpy(&insn, s_buf + i, 4);
            if (insn == SVC0) {
                zerr("find_svc_gadget: SVC#0 at 0x%lx (libc+0x%zx)", (unsigned long)(base + off + i), off + i);
                return base + off + i;
            }
        }
    }
    zerr("find_svc_gadget: no SVC#0 found in libc.so");
    return 0;
}

// Allocate RWX memory in target via a raw SVC #0 gadget + PTRACE_SINGLESTEP.
// Bypasses the mmap() C wrapper whose BTI guard (ARMv8.5+) causes SIGSEGV when
// we teleport PC there via PTRACE_SETREGSET instead of a real BL/BLR instruction.
static uintptr_t remote_mmap(pid_t pid, size_t size) {
    pt_regs orig, regs;
    if (!get_regs(pid, &orig)) { zerr("remote_mmap: get_regs failed errno=%d", errno); return 0; }

    uintptr_t svc_addr = find_svc_gadget(pid);
    if (!svc_addr) return 0;

    memcpy(&regs, &orig, sizeof(regs));
    // Clear PSTATE.BTYPE [11:10]: if the thread was stopped mid-branch these bits
    // encode the pending branch type.  Any non-zero BTYPE causes the CPU to enforce
    // BTI on the next instruction — a SVC in the middle of a guarded libc page is
    // not a BTI instruction, so it faults instantly.  BTYPE=0 means "no pending
    // branch check" → CPU skips the BTI guard entirely.
    regs.pstate &= ~(uint64_t)(3u << 10); // PSR_BTYPE_MASK
    // Direct mmap syscall: X8=nr, X0-X5=args — no wrapper, no BTI, no prologue
    regs.regs[8] = 222; // __NR_mmap
    regs.regs[0] = 0;
    regs.regs[1] = size;
    regs.regs[2] = PROT_READ | PROT_WRITE | PROT_EXEC;
    regs.regs[3] = MAP_PRIVATE | MAP_ANONYMOUS;
    regs.regs[4] = (uint64_t)-1;
    regs.regs[5] = 0;
    regs.pc      = svc_addr;

    if (!set_regs(pid, &regs)) {
        zerr("remote_mmap: set_regs failed errno=%d", errno);
        return 0;
    }

    // PTRACE_SINGLESTEP: executes exactly the SVC instruction, then stops with SIGTRAP.
    // The kernel handles the mmap syscall during the SVC, returns X0 = mapped address.
    ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);
    int wst = 0;
    waitpid(pid, &wst, 0);

    if (!WIFSTOPPED(wst) || WSTOPSIG(wst) != SIGTRAP) {
        pt_regs crash; get_regs(pid, &crash);
        zerr("remote_mmap: singlestep bad stop wst=0x%x sig=%d crash_PC=0x%lx",
             wst, WSTOPSIG(wst), (unsigned long)crash.pc);
        set_regs(pid, &orig);
        return 0;
    }

    get_regs(pid, &regs);
    uintptr_t result = regs.regs[0];
    zerr("remote_mmap: SVC mmap result=0x%lx", (unsigned long)result);

    set_regs(pid, &orig);
    // Kernel returns -errno as a large unsigned value on failure
    return (result < (uintptr_t)-4096ULL) ? result : 0;
}

// Write memory to target and call dlopen via a small shellcode stub.
//
// Direct PC-teleport to dlopen() segfaults on ARMv8.5+ BTI devices (same
// root cause as the mmap wrapper crash).  Instead we write a tiny shellcode
// into the RWX page we just allocated:
//
//   [+0 ] LDR X8, #16      — load dlopen_addr from the literal pool at +16
//   [+4 ] BLR X8           — call dlopen via BLR (BTI-C compatible)
//   [+8 ] BRK #0           — stop; ptrace catches SIGTRAP here
//   [+12] NOP               — 8-byte padding
//   [+16] dlopen_addr(u64) — literal pool
//
// Our mmap'd page has no GP/BTI guard bit, so the initial PC-teleport into
// the shellcode is fine.  The BLR is what matters for the guarded dlopen page.
static bool remote_dlopen(pid_t pid, const char *so_path) {
    size_t path_len     = strlen(so_path) + 1;
    size_t path_aligned = (path_len + 7) & ~(size_t)7; // 8-byte align for shellcode
    size_t alloc        = path_aligned + 24;             // path + 24-byte shellcode

    // 1. Allocate RWX scratch page
    uintptr_t remote_buf = remote_mmap(pid, alloc);
    if (!remote_buf) { zerr("remote_dlopen: remote_mmap returned 0"); return false; }

    // 2. Write path string
    if (!ProcMem::write(remote_buf, so_path, path_len)) {
        zerr("remote_dlopen: write path failed errno=%d", errno); return false;
    }

    // 3. Find dlopen in target
    uintptr_t dlopen_addr = ProcMem::findSymbol(pid, "libdl.so", "dlopen");
    if (!dlopen_addr) { zerr("remote_dlopen: dlopen not found in libdl.so"); return false; }
    zerr("remote_dlopen: dlopen_addr=0x%lx sc_addr=0x%lx", (unsigned long)dlopen_addr, (unsigned long)(remote_buf + path_aligned));

    // 4. Write shellcode
    uintptr_t sc_addr = remote_buf + path_aligned;
    struct { uint32_t insns[4]; uint64_t fn_addr; } sc;
    sc.insns[0] = 0x58000088u; // LDR X8, #16
    sc.insns[1] = 0xD63F0100u; // BLR X8
    sc.insns[2] = 0xD4200000u; // BRK #0
    sc.insns[3] = 0xD503201Fu; // NOP (literal pool alignment)
    sc.fn_addr  = (uint64_t)dlopen_addr;
    if (!ProcMem::write(sc_addr, &sc, sizeof(sc))) {
        zerr("remote_dlopen: write shellcode failed errno=%d", errno); return false;
    }

    // 5. Jump into shellcode: X0=path, X1=flags, PC=shellcode
    pt_regs orig, regs;
    get_regs(pid, &orig);
    memcpy(&regs, &orig, sizeof(regs));
    regs.pstate &= ~(uint64_t)(3u << 10); // clear PSTATE.BTYPE — BLR inside shellcode handles dlopen's BTI
    regs.regs[0] = remote_buf;             // dlopen arg 1: path
    regs.regs[1] = RTLD_NOW | RTLD_GLOBAL; // dlopen arg 2: flags
    regs.pc      = sc_addr;

    if (!set_regs(pid, &regs)) {
        zerr("remote_dlopen: set_regs failed errno=%d", errno); return false;
    }
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
    int status;
    waitpid(pid, &status, 0);

    set_regs(pid, &orig);

    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        zerr("remote_dlopen: bad stop sig=%d (want SIGTRAP)", WSTOPSIG(status));
        return false;
    }

    pt_regs post; get_regs(pid, &post);
    zerr("remote_dlopen: dlopen handle=0x%lx", (unsigned long)post.regs[0]);
    return post.regs[0] != 0;
}

// ── Main ──────────────────────────────────────────────────────────────────────

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: zx_injector <pid> <cmd> <0|1> [payload_path] [intensity]\n");
        return 1;
    }

    pid_t pid       = atoi(argv[1]);
    int   cmd       = atoi(argv[2]);
    bool  enable    = atoi(argv[3]) != 0;
    int   intensity = (argc >= 6) ? atoi(argv[5]) : 0;

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
        freeze_threads(pid);       // stop anti-cheat threads during injection
        bool ok = remote_dlopen(pid, payload_path);
        thaw_threads();
        ptrace_detach(pid);

        if (!ok) { ERR("Injection failed"); ProcMem::close(); return 4; }

        payload_base = ProcMem::findLibBase(pid, "libzx_payload.so");
        LOG("Payload loaded at 0x%lx", payload_base);
    }

    // Send command to payload via shared memory flag
    // The payload polls a small control struct it mmap'd at a known offset
    uintptr_t ctrl_addr = ProcMem::findSymbol(pid, "libzx_payload.so", "__g_sdktbl1");
    if (ctrl_addr) {
        // Write enable (+4) and intensity (+8) before cmd (+0) so the payload never
        // reads a non-zero cmd with stale enable/intensity values (write-ordering fix)
        int enable_val    = enable ? 1 : 0;
        int intensity_val = intensity;
        ProcMem::write(ctrl_addr + 4, &enable_val,    sizeof(int));
        ProcMem::write(ctrl_addr + 8, &intensity_val, sizeof(int));
        ProcMem::write(ctrl_addr,     &cmd,           sizeof(int)); // cmd last as trigger
        LOG("Command sent: cmd=%d enable=%d intensity=%d", cmd, enable_val, intensity_val);
    }

    ProcMem::close();
    return 0;
}

#else // !__aarch64__

// ARM32 stub — injector targets a 64-bit FF process; not applicable on 32-bit ABI
int main(int /*argc*/, char ** /*argv*/) { return 1; }

#endif // __aarch64__
