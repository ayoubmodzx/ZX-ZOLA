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
#include <signal.h>

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
    BULLET_DAMAGE   = 28,  // multiply outgoing bullet damage per shot
};

// Payload .so path (extracted by ZxEngine.kt into app filesDir)
static constexpr const char *PAYLOAD_NAME = "libunity_render.so";
// Staged name in FF's lib dir — blends with FF's own renderer JNI libs.
// The source .so is still libzx_payload.so; we copy it under this alias so
// /proc/maps never shows a "zx" or "payload" string before Layer 2 hides it.
static constexpr const char *STAGED_NAME  = "libunity_gc.so";
// Bump whenever ZxCtrl struct layout or payload ABI changes so the injector
// knows to force re-inject rather than re-using a stale in-memory payload.
#define PAYLOAD_VERSION 2
static constexpr const char *VER_FILE     = "/data/local/tmp/.zxver";

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

// Returns true if this TID belongs to AnoSDK or our own ctrl_loop — both
// should be excluded from the freeze pass.
// AnoSDK thread names: "ano*", "*scan*", "libanogs*"
// Our ctrl_loop: "kworker/*" (prctl rename in ctrl_loop)
static bool is_anogs_thread(pid_t pid, pid_t tid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task/%d/comm", pid, tid);
    char comm[32] = {};
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    ssize_t n = read(fd, comm, sizeof(comm) - 1);
    close(fd);
    if (n <= 0) return false;
    for (int i = 0; i < n; i++) if (comm[i] == '\n' || comm[i] == '\r') { comm[i] = '\0'; break; }
    return strncmp(comm, "ano",     3) == 0 ||
           strncmp(comm, "mrpcs",   5) == 0 ||
           strncmp(comm, "mvm_bk",  6) == 0 ||
           strstr( comm, "scan")       != nullptr ||
           strncmp(comm, "libanogs", 8) == 0 ||
           strncmp(comm, "kworker",  7) == 0;
}

// SIGSTOP-based thread freezer — much quieter than ptrace per-thread.
// Skips AnoSDK scanner threads entirely: ptracing them is the #1 detection vector
// because AnoSDK explicitly monitors for external ptrace on its own TIDs.
static pid_t s_sigstop_tids[256];
static int   s_sigstop_n = 0;

static void freeze_threads_safe(pid_t pid) {
    char path[64]; snprintf(path, sizeof(path), "/proc/%d/task", pid);
    DIR *d = opendir(path); if (!d) return;
    struct dirent *e; s_sigstop_n = 0;
    while ((e = readdir(d)) != nullptr && s_sigstop_n < 256) {
        if (e->d_name[0] == '.') continue;
        pid_t tid = (pid_t)atoi(e->d_name);
        if (tid <= 0 || tid == pid) continue;
        if (is_anogs_thread(pid, tid)) {
            LOG("freeze: skip tid=%d (AnoSDK/ctrl)", tid);
            continue;
        }
        if (kill(tid, SIGSTOP) == 0)
            s_sigstop_tids[s_sigstop_n++] = tid;
    }
    closedir(d);
    usleep(8000);
    LOG("freeze_threads_safe: stopped %d threads", s_sigstop_n);
}

static void thaw_threads_safe() {
    for (int i = 0; i < s_sigstop_n; i++)
        kill(s_sigstop_tids[i], SIGCONT);
    s_sigstop_n = 0;
}

static bool get_regs(pid_t pid, pt_regs *regs) {
    struct iovec iov = { regs, sizeof(*regs) };
    return ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) == 0;
}

static bool set_regs(pid_t pid, pt_regs *regs) {
    struct iovec iov = { regs, sizeof(*regs) };
    return ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &iov) == 0;
}

// Patch a single ARM64 instruction in the target process via PTRACE_PEEKTEXT/POKETEXT.
// Works on r-x pages (linker64 code) when running as root with ptrace attached.
// The kernel handles ARM64 dcache/icache coherency for ptrace writes automatically.
static bool remote_poke_insn(pid_t pid, uintptr_t addr, uint32_t insn) {
    uintptr_t aligned = addr & ~(uintptr_t)7;
    errno = 0;
    long peek_val = ptrace(PTRACE_PEEKTEXT, pid, (void*)aligned, NULL);
    if (errno) {
        zerr("remote_poke_insn: PEEKTEXT@0x%lx errno=%d", (unsigned long)aligned, errno);
        return false;
    }
    uint64_t word = (uint64_t)(unsigned long)peek_val;
    if ((addr & 4) == 0)
        word = (word & 0xFFFFFFFF00000000ULL) | (uint64_t)insn;
    else
        word = (word & 0x00000000FFFFFFFFULL) | ((uint64_t)insn << 32);
    if (ptrace(PTRACE_POKETEXT, pid, (void*)aligned, (void*)(uintptr_t)word) < 0) {
        zerr("remote_poke_insn: POKETEXT@0x%lx errno=%d", (unsigned long)aligned, errno);
        return false;
    }
    return true;
}

// Scan target's libc.so for a raw SVC #0 gadget — ONLY in executable pages.
// ARM64 SVC #0 encoding (LE): 0xD4000001
// Previous bug: scanning from ELF base blindly hits data/rodata pages first;
// 0xD4000001 in a data page → SIGSEGV (SEGV_ACCERR) when CPU tries to fetch it.
static uintptr_t find_svc_gadget(pid_t pid) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) { zerr("find_svc_gadget: cannot open %s errno=%d", maps_path, errno); return 0; }

    struct Region { uintptr_t start, end; };
    Region exec_regions[32];
    int exec_n = 0;
    bool found_libc = false;
    int total_libc_segs = 0;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, "libc.so")) continue;
        found_libc = true;
        uintptr_t start = 0, end = 0;
        char perms[8] = {};
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) != 3) continue;
        total_libc_segs++;
        zerr("find_svc_gadget: libc seg[%d] [0x%lx-0x%lx] perms=%s size=%zuKB",
             total_libc_segs, start, end, perms, (size_t)(end - start) / 1024);
        if (perms[2] == 'x' && exec_n < 32) {
            exec_regions[exec_n++] = {start, end};
        }
    }
    fclose(f);

    if (!found_libc) { zerr("find_svc_gadget: libc.so not in /proc/%d/maps", pid); return 0; }
    zerr("find_svc_gadget: %d libc segments total, %d executable", total_libc_segs, exec_n);
    if (exec_n == 0) { zerr("find_svc_gadget: no executable libc.so pages found!"); return 0; }

    static uint8_t s_buf[65536];
    const uint32_t SVC0 = 0xD4000001u;

    for (int r = 0; r < exec_n; r++) {
        uintptr_t rstart = exec_regions[r].start;
        uintptr_t rend   = exec_regions[r].end;
        zerr("find_svc_gadget: scanning exec[%d] [0x%lx-0x%lx] size=%zuKB", r, rstart, rend, (size_t)(rend - rstart) / 1024);
        for (uintptr_t pos = rstart; pos < rend; pos += sizeof(s_buf)) {
            size_t chunk = (rend - pos < sizeof(s_buf)) ? (size_t)(rend - pos) : sizeof(s_buf);
            if (!ProcMem::read(pos, s_buf, chunk)) continue;
            for (size_t i = 0; i + 4 <= chunk; i += 4) {
                uint32_t insn;
                memcpy(&insn, s_buf + i, 4);
                if (insn == SVC0) {
                    uintptr_t gadget = pos + i;
                    zerr("find_svc_gadget: FOUND SVC#0 at 0x%lx (exec[%d]+0x%zx)",
                         gadget, r, (size_t)(gadget - rstart));
                    return gadget;
                }
            }
        }
        zerr("find_svc_gadget: no SVC#0 in exec[%d]", r);
    }
    zerr("find_svc_gadget: no SVC#0 found in ANY executable libc.so region");
    return 0;
}

// PTRACE_SINGLESTEP + waitpid with SIGSTOP/SIGTSTP retry.
// freeze_threads_safe() sends SIGSTOP to other threads which triggers a
// group-stop on the whole process — the ptraced main thread sees sig=19 instead
// of SIGTRAP. Suppress group-stops (sig=0) and re-issue SINGLESTEP up to 16×.
static int singlestep_wait(pid_t pid) {
    int wst = 0;
    for (int i = 0; i < 16; i++) {
        ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);
        waitpid(pid, &wst, 0);
        if (!WIFSTOPPED(wst)) break;
        int sig = WSTOPSIG(wst);
        if (sig == SIGTRAP) break;
        if (sig == SIGSTOP || sig == SIGTSTP) continue; // group-stop — suppress & retry
        break; // any other signal — fall through to caller's error handler
    }
    return wst;
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

    zerr("remote_mmap: setting PC=0x%lx pstate=0x%lx btype_bits=%llu x8(nr)=%llu",
         (unsigned long)svc_addr, (unsigned long)regs.pstate,
         (unsigned long long)((regs.pstate >> 10) & 3),
         (unsigned long long)regs.regs[8]);

    if (!set_regs(pid, &regs)) {
        zerr("remote_mmap: set_regs failed errno=%d", errno);
        return 0;
    }

    // Verify bytes at svc_addr before stepping
    {
        uint32_t verify_insn = 0;
        if (ProcMem::read(svc_addr, &verify_insn, 4))
            zerr("remote_mmap: insn@svc_addr=0x%08x (want 0xD4000001)", verify_insn);
        else
            zerr("remote_mmap: cannot read svc_addr bytes errno=%d", errno);
    }

    // PTRACE_SINGLESTEP: executes exactly the SVC instruction, then stops with SIGTRAP.
    // The kernel handles the mmap syscall during the SVC, returns X0 = mapped address.
    int wst = singlestep_wait(pid);

    if (!WIFSTOPPED(wst) || WSTOPSIG(wst) != SIGTRAP) {
        pt_regs crash; get_regs(pid, &crash);
        int sig = WIFSTOPPED(wst) ? WSTOPSIG(wst) : -1;
        zerr("remote_mmap: singlestep bad stop wst=0x%x sig=%d crash_PC=0x%lx crash_pstate=0x%lx",
             wst, sig, (unsigned long)crash.pc, (unsigned long)crash.pstate);
        siginfo_t si = {};
        if (ptrace(PTRACE_GETSIGINFO, pid, nullptr, &si) == 0) {
            zerr("remote_mmap: SIGINFO si_signo=%d si_code=%d si_addr=0x%lx",
                 si.si_signo, si.si_code, (unsigned long)(uintptr_t)si.si_addr);
            if (si.si_signo == SIGSEGV && si.si_code == SEGV_ACCERR)
                zerr("remote_mmap: SEGV_ACCERR => PC mapped but NOT executable (data page hit)");
            else if (si.si_signo == SIGSEGV && si.si_code == SEGV_MAPERR)
                zerr("remote_mmap: SEGV_MAPERR => PC address not mapped at all");
            else if (si.si_signo == SIGILL)
                zerr("remote_mmap: SIGILL => BTI violation or truly illegal instruction");
            else if (si.si_signo == SIGTRAP)
                zerr("remote_mmap: SIGTRAP si_code=%d (BRK/BKPT?)", si.si_code);
        } else {
            zerr("remote_mmap: PTRACE_GETSIGINFO failed errno=%d", errno);
        }
        zerr("remote_mmap: crash_x0=0x%lx crash_x8=0x%lx",
             (unsigned long)crash.regs[0], (unsigned long)crash.regs[8]);
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

// Free an anonymous mapping we created in the target process.
// Mirrors remote_mmap: SVC #0 gadget + PTRACE_SINGLESTEP for __NR_munmap (215).
// Called after injection to eliminate the rwxp anonymous mapping from /proc/maps
// before AnoSDK's memory scanner sees it.
static bool remote_munmap(pid_t pid, uintptr_t addr, size_t size) {
    if (!addr || !size) return false;
    pt_regs orig, regs;
    if (!get_regs(pid, &orig)) { zerr("remote_munmap: get_regs failed errno=%d", errno); return false; }

    uintptr_t svc_addr = find_svc_gadget(pid);
    if (!svc_addr) { zerr("remote_munmap: no SVC gadget"); return false; }

    memcpy(&regs, &orig, sizeof(regs));
    regs.pstate    &= ~(uint64_t)(3u << 10);
    regs.regs[8]    = 215;   // __NR_munmap
    regs.regs[0]    = addr;
    regs.regs[1]    = (uint64_t)size;
    regs.pc         = svc_addr;

    if (!set_regs(pid, &regs)) { zerr("remote_munmap: set_regs failed errno=%d", errno); return false; }

    int wst = singlestep_wait(pid);
    pt_regs after; get_regs(pid, &after);
    set_regs(pid, &orig);

    if (!WIFSTOPPED(wst) || WSTOPSIG(wst) != SIGTRAP) {
        zerr("remote_munmap: bad stop wst=0x%x", wst);
        return false;
    }
    long rc = (long)after.regs[0];
    zerr("remote_munmap: munmap(0x%lx, %zu) rc=%ld", (unsigned long)addr, size, rc);
    return rc == 0;
}

// One hook record: target address + original instruction + ACE's replacement.
struct AcePatch {
    uintptr_t tgt_addr;
    uint32_t  orig;
    uint32_t  ace;
};

// Scan ALL executable pages of linker64 in both processes and collect every
// instruction that differs (ACE inline hooks).  Static 64 KB read buffers avoid
// stack overflow on large code sections.  Returns number of patches found.
static int find_ace_linker_hooks(pid_t pid,
                                  uintptr_t our_linker,
                                  uintptr_t target_linker,
                                  AcePatch* patches, int max_patches) {
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) { zerr("find_ace_linker_hooks: open /proc/self/maps failed"); return 0; }

    static uint8_t s_our[65536], s_tgt[65536];
    int count = 0;
    char line[512];

    while (fgets(line, sizeof(line), maps) && count < max_patches) {
        uintptr_t start, end;
        char perms[8] = {};
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3) continue;
        if (perms[2] != 'x') continue;
        if (!strstr(line, "linker64")) continue;
        if (start < our_linker || start >= our_linker + 0x400000UL) continue;

        uintptr_t region_len = end - start;
        uintptr_t our_off    = start - our_linker;
        uintptr_t tgt_start  = target_linker + our_off;

        zerr("find_ace_linker_hooks: exec region linker64+[0x%lx, 0x%lx)",
             (unsigned long)our_off, (unsigned long)(our_off + region_len));

        for (uintptr_t co = 0; co < region_len && count < max_patches; co += sizeof(s_our)) {
            uintptr_t chunk = (region_len - co < sizeof(s_our)) ? (region_len - co) : sizeof(s_our);
            memcpy(s_our, (const void*)(start + co), chunk);
            if (!ProcMem::read(tgt_start + co, s_tgt, chunk)) {
                zerr("find_ace_linker_hooks: read failed at tgt=0x%lx",
                     (unsigned long)(tgt_start + co));
                continue;
            }
            for (uintptr_t i = 0; i + 4 <= chunk && count < max_patches; i += 4) {
                uint32_t ours = *(uint32_t*)(s_our + i);
                uint32_t tgt  = *(uint32_t*)(s_tgt + i);
                if (ours != tgt) {
                    uintptr_t loff = our_off + co + i;
                    zerr("ACE hook linker64+0x%05lx: ours=0x%08x ace=0x%08x",
                         (unsigned long)loff, ours, tgt);
                    patches[count++] = {target_linker + loff, ours, tgt};
                }
            }
        }
    }
    fclose(maps);
    zerr("find_ace_linker_hooks: %d total divergent instructions in linker64", count);
    return count;
}

// ACE anti-cheat (libanogs.so) uses And64InlineHook style patching (ms_set_inlie_hook /
// ms_hook_opcode) somewhere inside linker64's call chain to intercept dlopen.
// The exact hook location is unknown — it is NOT at do_dlopen[0..63].
// find_real_loader_dlopen locates __loader_dlopen and do_dlopen by decoding PLT/GOT
// in our own (unhooked) process, then maps the same offsets to target's linker64.
// find_ace_linker_hooks then scans all executable pages of linker64 to find ALL
// patched instructions so we can restore them before calling __loader_dlopen.
static uintptr_t find_real_loader_dlopen(int target_pid,
                                          uintptr_t *out_do_dlopen_local,
                                          uintptr_t *out_do_dlopen_target,
                                          uintptr_t *out_our_linker    = nullptr,
                                          uintptr_t *out_target_linker = nullptr) {
    if (out_do_dlopen_local)  *out_do_dlopen_local  = 0;
    if (out_do_dlopen_target) *out_do_dlopen_target = 0;
    if (out_our_linker)       *out_our_linker        = 0;
    if (out_target_linker)    *out_target_linker     = 0;
    // 1. Our local dlopen = 4-insn wrapper in libdl.so
    uintptr_t our_dlopen = (uintptr_t)(void*)dlopen;
    zerr("find_real_loader_dlopen: our_dlopen=0x%lx", (unsigned long)our_dlopen);

    // 2. BL at wrapper+12 → PLT stub for __loader_dlopen
    uint32_t bl_insn = *(uint32_t*)(our_dlopen + 12);
    if ((bl_insn >> 26) != 0x25u) {
        zerr("find_real_loader_dlopen: insn@+12=0x%08x not BL — cannot locate PLT", bl_insn);
        return 0;
    }
    int64_t off26 = (int64_t)(bl_insn & 0x3FFFFFFu);
    if (off26 & (1LL << 25)) off26 |= ~(int64_t)0x3FFFFFFu;
    uintptr_t our_plt = (our_dlopen + 12) + (uintptr_t)(off26 * 4);
    zerr("find_real_loader_dlopen: our_plt=0x%lx", (unsigned long)our_plt);

    // 3. Decode ADRP+LDR in PLT to get GOT entry address
    uint32_t adrp = *(uint32_t*)our_plt;
    uint32_t ldr  = *(uint32_t*)(our_plt + 4);
    // ADRP X16: page = (PC & ~0xFFF) + sign_ext_imm21 * 4096
    int64_t immhi = (int64_t)((adrp >> 5) & 0x7FFFFu);
    int64_t immlo = (int64_t)((adrp >> 29) & 0x3u);
    int64_t imm21 = (immhi << 2) | immlo;
    if (imm21 & (1LL << 20)) imm21 |= ~(int64_t)0xFFFFFu;
    uintptr_t got_page = (our_plt & ~(uintptr_t)0xFFF) + (uintptr_t)(imm21 * 4096LL);
    // LDR Xn,[Xm,#imm12*8]: bits[21:10], 64-bit load scales by 8
    uint64_t imm12 = (ldr >> 10) & 0xFFFu;
    uintptr_t our_got_entry = got_page + (uintptr_t)(imm12 * 8);
    zerr("find_real_loader_dlopen: adrp=0x%08x ldr=0x%08x got_entry=0x%lx", adrp, ldr, (unsigned long)our_got_entry);

    // 4. Read our unhooked GOT → real __loader_dlopen VA in our process
    uintptr_t local_fn = *(uintptr_t*)our_got_entry;
    zerr("find_real_loader_dlopen: local_fn=0x%lx", (unsigned long)local_fn);

    // 5. Find linker64 base in OUR process
    uintptr_t our_linker = ProcMem::findLibBase((int)getpid(), "linker64");
    if (!our_linker) {
        zerr("find_real_loader_dlopen: linker64 not in /proc/self/maps");
        return 0;
    }
    if (local_fn < our_linker) {
        zerr("find_real_loader_dlopen: local_fn 0x%lx < our_linker 0x%lx — unexpected",
             (unsigned long)local_fn, (unsigned long)our_linker);
        return 0;
    }
    uintptr_t offset = local_fn - our_linker;

    // 6. Find linker64 base in TARGET process
    uintptr_t target_linker = ProcMem::findLibBase(target_pid, "linker64");
    if (!target_linker) {
        zerr("find_real_loader_dlopen: linker64 not in /proc/%d/maps", target_pid);
        return 0;
    }
    uintptr_t result = target_linker + offset;
    zerr("find_real_loader_dlopen: our_linker=0x%lx target_linker=0x%lx offset=0x%lx → target_fn=0x%lx",
         (unsigned long)our_linker, (unsigned long)target_linker,
         (unsigned long)offset, (unsigned long)result);
    if (out_our_linker)    *out_our_linker    = our_linker;
    if (out_target_linker) *out_target_linker = target_linker;

    // Decode the B instruction at __loader_dlopen+8 to locate do_dlopen.
    // The thunk is exactly: MOV X3,X2 / MOV X2,XZR / B do_dlopen
    // Bytes confirmed: aa0203e3 aa1f03e2 17ffffc0
    uint32_t b_insn = *(uint32_t*)(local_fn + 8);
    zerr("find_real_loader_dlopen: B@+8=0x%08x (want opcode 0x05 in bits[31:26])", b_insn);
    if ((b_insn >> 26) == 0x05u) {
        int64_t imm26 = (int64_t)(b_insn & 0x3FFFFFFu);
        if (imm26 & (1LL << 25)) imm26 |= ~(int64_t)0x3FFFFFFu;
        uintptr_t do_dlopen_local  = (local_fn + 8) + (uintptr_t)(imm26 * 4LL);
        uintptr_t do_dlopen_offset = do_dlopen_local - our_linker;
        uintptr_t do_dlopen_tgt    = target_linker + do_dlopen_offset;
        zerr("find_real_loader_dlopen: imm26=%lld do_dlopen_local=0x%lx do_dlopen_target=0x%lx",
             (long long)imm26, (unsigned long)do_dlopen_local, (unsigned long)do_dlopen_tgt);
        if (out_do_dlopen_local)  *out_do_dlopen_local  = do_dlopen_local;
        if (out_do_dlopen_target) *out_do_dlopen_target = do_dlopen_tgt;
    } else {
        zerr("find_real_loader_dlopen: insn@+8=0x%08x not B — cannot locate do_dlopen", b_insn);
    }
    return result;
}

// Find a named symbol in an ELF .so file on disk.
// Returns the symbol's value (VMA relative to load base for PIC), or 0 if not found.
static uintptr_t find_sym_in_file(const char *so_path, const char *sym_name) {
    int fd = open(so_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    Elf64_Ehdr ehdr = {};
    if (pread(fd, &ehdr, sizeof(ehdr), 0) != (ssize_t)sizeof(ehdr) ||
        ehdr.e_ident[0] != 0x7f) { close(fd); return 0; }
    // Find .dynamic to locate DT_SYMTAB, DT_STRTAB, DT_SYMENT
    uint64_t dyn_off = 0, dyn_size = 0;
    for (int i = 0; i < (int)ehdr.e_phnum; i++) {
        Elf64_Phdr ph = {};
        if (pread(fd, &ph, sizeof(ph),
                  (off_t)(ehdr.e_phoff + (uint64_t)i * ehdr.e_phentsize)) != (ssize_t)sizeof(ph))
            continue;
        if (ph.p_type == PT_DYNAMIC) { dyn_off = ph.p_offset; dyn_size = ph.p_filesz; break; }
    }
    if (!dyn_off) { close(fd); return 0; }
    // Find first PT_LOAD vaddr to convert VMA→file_offset
    uint64_t load_vaddr = 0, load_off = 0;
    for (int i = 0; i < (int)ehdr.e_phnum; i++) {
        Elf64_Phdr ph = {};
        if (pread(fd, &ph, sizeof(ph),
                  (off_t)(ehdr.e_phoff + (uint64_t)i * ehdr.e_phentsize)) != (ssize_t)sizeof(ph))
            continue;
        if (ph.p_type == PT_LOAD && !(ph.p_flags & PF_W)) {
            load_vaddr = ph.p_vaddr; load_off = ph.p_offset; break;
        }
    }
    // Read .dynamic entries to get DT_SYMTAB + DT_STRTAB
    uint64_t sym_vma = 0, str_vma = 0;
    size_t n_dyn = (size_t)(dyn_size / sizeof(Elf64_Dyn));
    for (size_t i = 0; i < n_dyn; i++) {
        Elf64_Dyn dyn = {};
        if (pread(fd, &dyn, sizeof(dyn), (off_t)(dyn_off + i * sizeof(dyn))) != (ssize_t)sizeof(dyn))
            break;
        if (dyn.d_tag == DT_SYMTAB) sym_vma = (uint64_t)dyn.d_un.d_ptr;
        if (dyn.d_tag == DT_STRTAB) str_vma = (uint64_t)dyn.d_un.d_ptr;
        if (dyn.d_tag == DT_NULL) break;
    }
    if (!sym_vma || !str_vma) { close(fd); return 0; }
    // Convert VMA→file offset: file_off = vma - load_vaddr + load_off
    auto vma2off = [&](uint64_t vma) -> uint64_t { return vma - load_vaddr + load_off; };
    uint64_t sym_off = vma2off(sym_vma);
    uint64_t str_off = vma2off(str_vma);
    // Scan dynsym (fixed entry size = sizeof(Elf64_Sym))
    for (size_t i = 0; ; i++) {
        Elf64_Sym sym = {};
        if (pread(fd, &sym, sizeof(sym), (off_t)(sym_off + i * sizeof(sym))) != (ssize_t)sizeof(sym))
            break;
        if (sym.st_name == 0 && i > 0 && sym.st_value == 0) break; // likely past end
        char name[256] = {};
        pread(fd, name, sizeof(name) - 1, (off_t)(str_off + sym.st_name));
        if (strcmp(name, sym_name) == 0) { close(fd); return (uintptr_t)sym.st_value; }
        if (i > 65536) break; // safety
    }
    close(fd);
    return 0;
}

// Parse staged .so ELF to find the writable PT_LOAD segment (contains GOT/data).
static bool find_rw_segment(const char *so_path, uint64_t *out_vaddr, uint64_t *out_size) {
    int fd = open(so_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    Elf64_Ehdr ehdr = {};
    if (pread(fd, &ehdr, sizeof(ehdr), 0) != (ssize_t)sizeof(ehdr) ||
        ehdr.e_ident[0] != 0x7f) { close(fd); return false; }
    *out_vaddr = 0; *out_size = 0;
    for (int i = 0; i < (int)ehdr.e_phnum; i++) {
        Elf64_Phdr ph = {};
        if (pread(fd, &ph, sizeof(ph),
                  (off_t)(ehdr.e_phoff + (uint64_t)i * ehdr.e_phentsize)) != (ssize_t)sizeof(ph))
            continue;
        if (ph.p_type != PT_LOAD) continue;
        if ((ph.p_flags & PF_W) == 0) continue;
        *out_vaddr = ph.p_vaddr;
        *out_size  = ph.p_filesz;
        break;
    }
    close(fd);
    return *out_size > 0;
}

// Android NDK elf.h may not define these — guard to avoid redefinition.
#ifndef R_AARCH64_GLOB_DAT
#define R_AARCH64_GLOB_DAT  1025u
#endif
#ifndef R_AARCH64_JUMP_SLOT
#define R_AARCH64_JUMP_SLOT 1026u
#endif

// Surgical PAC strip: parse RELA table from the .so file on disk,
// find only R_AARCH64_GLOB_DAT + R_AARCH64_JUMP_SLOT relocation slots,
// and strip PAC from those specific GOT entries in the target process.
// This avoids corrupting legitimate 64-bit data (vtables, constants, etc.)
// that a broad scan of the whole relro segment would clobber.
static void strip_pac_via_rela(pid_t pid, const char *so_path, uintptr_t elf_base_hint = 0) {
    int fd = open(so_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { zerr("pac_strip: open %s errno=%d", so_path, errno); return; }

    Elf64_Ehdr ehdr = {};
    if (pread(fd, &ehdr, sizeof(ehdr), 0) != (ssize_t)sizeof(ehdr) ||
        ehdr.e_ident[0] != 0x7f) { close(fd); zerr("pac_strip: bad ELF"); return; }

    uint64_t load_vaddr = 0, load_off = 0;
    uint64_t dyn_off = 0, dyn_sz = 0;
    for (int i = 0; i < (int)ehdr.e_phnum; i++) {
        Elf64_Phdr ph = {};
        pread(fd, &ph, sizeof(ph),
              (off_t)(ehdr.e_phoff + (uint64_t)i * ehdr.e_phentsize));
        if (ph.p_type == PT_LOAD && ph.p_offset == 0 && !load_off) {
            load_vaddr = ph.p_vaddr; load_off = ph.p_offset;
        }
        if (ph.p_type == PT_DYNAMIC) { dyn_off = ph.p_offset; dyn_sz = ph.p_filesz; }
    }
    if (!dyn_sz) { close(fd); zerr("pac_strip: no PT_DYNAMIC"); return; }

    uint64_t rela_vma = 0, rela_sz = 0, jmprel_vma = 0, jmprel_sz = 0;
    size_t ndyn = dyn_sz / sizeof(Elf64_Dyn);
    for (size_t i = 0; i < ndyn; i++) {
        Elf64_Dyn dyn = {};
        pread(fd, &dyn, sizeof(dyn), (off_t)(dyn_off + i * sizeof(dyn)));
        if      (dyn.d_tag == DT_RELA)     rela_vma   = dyn.d_un.d_ptr;
        else if (dyn.d_tag == DT_RELASZ)   rela_sz    = dyn.d_un.d_val;
        else if (dyn.d_tag == DT_JMPREL)   jmprel_vma = dyn.d_un.d_ptr;
        else if (dyn.d_tag == DT_PLTRELSZ) jmprel_sz  = dyn.d_un.d_val;
        else if (dyn.d_tag == DT_NULL)     break;
    }

    auto vma2off = [&](uint64_t vma) -> uint64_t { return vma - load_vaddr + load_off; };
    uintptr_t elf_base = elf_base_hint ? elf_base_hint : ProcMem::findLibBase(pid, STAGED_NAME);
    zerr("pac_strip: elf_base=0x%lx rela@0x%llx sz=%llu jmprel@0x%llx sz=%llu",
         (unsigned long)elf_base,
         (unsigned long long)rela_vma, (unsigned long long)rela_sz,
         (unsigned long long)jmprel_vma, (unsigned long long)jmprel_sz);

    int total_stripped = 0, total_scanned = 0;

    auto do_strip = [&](uint64_t vma, uint64_t sz, const char *label) {
        if (!vma || !sz || !elf_base) return;
        uint64_t off = vma2off(vma);
        size_t n = sz / sizeof(Elf64_Rela);
        for (size_t i = 0; i < n; i++) {
            Elf64_Rela r = {};
            if (pread(fd, &r, sizeof(r),
                      (off_t)(off + i * sizeof(r))) != (ssize_t)sizeof(r)) break;
            uint32_t type = (uint32_t)(r.r_info & 0xffffffffull);
            if (type != R_AARCH64_GLOB_DAT && type != R_AARCH64_JUMP_SLOT) continue;
            total_scanned++;
            uintptr_t slot = elf_base + (uintptr_t)r.r_offset;
            uint64_t val = 0;
            if (!ProcMem::read(slot, &val, 8)) continue;
            // PAC on arm64 uses top 16 bits ([63:48]) for the signature.
            // Valid user-space pointers have bits[63:48]==0; kernel ones 0xFFFF.
            // Use a 2-byte check so we catch PAC tags that span both top bytes
            // (e.g. 0xa90d... where top byte=0xa9 BUT lower PAC byte=0x0d also set).
            uint16_t top16 = (uint16_t)(val >> 48);
            if (top16 == 0 || top16 == 0xFFFFu) continue;
            if ((val & 0x0000FFFFFFFFFFFFull) < 0x10000ULL) continue;
            // Clear full 16-bit PAC region, not just top byte.
            uint64_t clean = val & 0x0000FFFFFFFFFFFFull;
            if (ProcMem::write(slot, &clean, 8)) {
                total_stripped++;
                zerr("pac_strip: %s[%zu] slot@0x%lx 0x%llx→0x%llx",
                     label, i, (unsigned long)slot,
                     (unsigned long long)val, (unsigned long long)clean);
            } else {
                zerr("pac_strip: write FAIL %s[%zu] slot@0x%lx errno=%d",
                     label, i, (unsigned long)slot, errno);
            }
        }
    };

    do_strip(rela_vma,   rela_sz,   "RELA");
    do_strip(jmprel_vma, jmprel_sz, "JMPREL");

    close(fd);
    zerr("pac_strip: done — %d/%d slots stripped", total_stripped, total_scanned);
}

// Force-populate the payload's JUMP_SLOT GOT entries with real function addresses.
//
// Root cause of 0/138 stripped: the payload uses lazy binding (BIND_NOW not honoured
// by FF's bionic for injected libs), so at strip time every GOT slot still holds a
// PLT resolver stub address (top16 == 0) — strip_pac_via_rela finds nothing to strip.
//
// Fix: before GGP can sign the resolved addresses we write the real addresses ourselves.
// After this call the GOT holds genuine function pointers.  GGP will sign them, and
// strip_pac_via_rela will now see PAC-tagged entries (top16 != 0) and strip them.
// The existing retry loop then cleans up any last-second re-signs after the strip.
//
// Algorithm:
//  Phase 1 — parse our .so's JMPREL to collect (r_offset, sym_name) pairs.
//  Phase 2 — scan /proc/PID/maps once; for each loaded .so open its DYNSYM and
//             match symbol names; record resolved runtime address per symbol.
//  Phase 3 — write each resolved address to elf_base + r_offset via ProcMem.
static void pre_resolve_got(pid_t pid, const char *so_path, uintptr_t elf_base) {
    if (!elf_base) { zerr("pre_resolve: no elf_base — skip"); return; }

    // ── Phase 1: collect JUMP_SLOT entries from our payload ───────────────────
    int fd = open(so_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { zerr("pre_resolve: open %s errno=%d", so_path, errno); return; }

    Elf64_Ehdr ehdr = {};
    if (pread(fd, &ehdr, sizeof(ehdr), 0) != (ssize_t)sizeof(ehdr) || ehdr.e_ident[0] != 0x7f) {
        close(fd); zerr("pre_resolve: bad ELF"); return;
    }

    uint64_t load_vaddr = 0, load_off = 0, dyn_off = 0, dyn_sz = 0;
    for (int i = 0; i < (int)ehdr.e_phnum; i++) {
        Elf64_Phdr ph = {};
        pread(fd, &ph, sizeof(ph), (off_t)(ehdr.e_phoff + (uint64_t)i * ehdr.e_phentsize));
        if (ph.p_type == PT_LOAD && ph.p_offset == 0 && !load_off)
            { load_vaddr = ph.p_vaddr; load_off = ph.p_offset; }
        if (ph.p_type == PT_DYNAMIC) { dyn_off = ph.p_offset; dyn_sz = ph.p_filesz; }
    }
    if (!dyn_sz) { close(fd); zerr("pre_resolve: no PT_DYNAMIC"); return; }

    uint64_t jmprel_vma = 0, jmprel_sz = 0, symtab_vma = 0, strtab_vma = 0, strtab_sz = 0;
    size_t syment_sz = sizeof(Elf64_Sym);
    size_t ndyn = dyn_sz / sizeof(Elf64_Dyn);
    for (size_t i = 0; i < ndyn; i++) {
        Elf64_Dyn dyn = {};
        pread(fd, &dyn, sizeof(dyn), (off_t)(dyn_off + i * sizeof(dyn)));
        switch (dyn.d_tag) {
        case DT_SYMTAB:   symtab_vma  = dyn.d_un.d_ptr; break;
        case DT_STRTAB:   strtab_vma  = dyn.d_un.d_ptr; break;
        case DT_STRSZ:    strtab_sz   = dyn.d_un.d_val; break;
        case DT_JMPREL:   jmprel_vma  = dyn.d_un.d_ptr; break;
        case DT_PLTRELSZ: jmprel_sz   = dyn.d_un.d_val; break;
        case DT_SYMENT:   syment_sz   = dyn.d_un.d_val; break;
        case DT_NULL:     i = ndyn;                      break;
        }
    }
    if (!jmprel_vma || !jmprel_sz || !symtab_vma || !strtab_vma || !strtab_sz) {
        close(fd); zerr("pre_resolve: missing DT_JMPREL/DT_SYMTAB/DT_STRTAB"); return;
    }

    auto vma2off = [&](uint64_t vma) -> off_t { return (off_t)(vma - load_vaddr + load_off); };

    char *strtab_buf = (char *)malloc(strtab_sz + 1);
    if (!strtab_buf) { close(fd); zerr("pre_resolve: malloc strtab OOM"); return; }
    strtab_buf[strtab_sz] = '\0';
    if (pread(fd, strtab_buf, strtab_sz, vma2off(strtab_vma)) != (ssize_t)strtab_sz) {
        free(strtab_buf); close(fd); zerr("pre_resolve: STRTAB read fail"); return;
    }

    struct JmpEntry { uint64_t r_offset; char sym_name[96]; };
    static const int MAX_JMPS = 256;
    JmpEntry jmps[MAX_JMPS];
    memset(jmps, 0, sizeof(jmps));
    int n_jmps = 0;

    size_t n_rel = jmprel_sz / sizeof(Elf64_Rela);
    for (size_t i = 0; i < n_rel && n_jmps < MAX_JMPS; i++) {
        Elf64_Rela r = {};
        if (pread(fd, &r, sizeof(r), (off_t)(vma2off(jmprel_vma) + (off_t)(i * sizeof(r)))) != (ssize_t)sizeof(r)) break;
        if ((uint32_t)(r.r_info & 0xffffffffull) != R_AARCH64_JUMP_SLOT) continue;
        uint32_t sym_idx = (uint32_t)(r.r_info >> 32);
        Elf64_Sym sym = {};
        if (pread(fd, &sym, sizeof(sym),
                  (off_t)(vma2off(symtab_vma) + (off_t)(sym_idx * syment_sz))) != (ssize_t)sizeof(sym)) continue;
        if (sym.st_name >= strtab_sz) continue;
        const char *sn = strtab_buf + sym.st_name;
        if (!sn[0]) continue;
        jmps[n_jmps].r_offset = r.r_offset;
        snprintf(jmps[n_jmps].sym_name, sizeof(jmps[n_jmps].sym_name), "%s", sn);
        n_jmps++;
    }
    free(strtab_buf);
    close(fd);
    zerr("pre_resolve: collected %d JUMP_SLOT entries to resolve", n_jmps);
    if (n_jmps == 0) return;

    // ── Phase 1.5: build executable address ranges ────────────────────────────
    // When a process has two copies of libc (e.g. AnoSDK loads its own copy),
    // the first copy in /proc/maps may be r--p (non-executable).  pre_resolve
    // must only write addresses from executable (r-xp / r-x) segments, otherwise
    // the GOT contains a non-exec address → BLR → SIGSEGV code=2 at the callee.
    struct ExecRange { uintptr_t start, end; };
    static const int MAX_EXEC_R = 4096;
    static ExecRange exec_ranges[MAX_EXEC_R];
    memset(exec_ranges, 0, sizeof(exec_ranges));
    int n_exec_r = 0;
    {
        char emap[64]; snprintf(emap, sizeof(emap), "/proc/%d/maps", pid);
        FILE *ef = fopen(emap, "r");
        if (ef) {
            char el[256];
            while (fgets(el, sizeof(el), ef) && n_exec_r < MAX_EXEC_R) {
                uintptr_t es = 0, ee = 0; char ep[8] = {};
                if (sscanf(el, "%lx-%lx %7s", &es, &ee, ep) >= 3 && ep[2] == 'x')
                    exec_ranges[n_exec_r++] = {es, ee};
            }
            fclose(ef);
        }
    }
    auto is_exec_addr = [&](uintptr_t a) -> bool {
        for (int i = 0; i < n_exec_r; i++)
            if (a >= exec_ranges[i].start && a < exec_ranges[i].end) return true;
        return false;
    };

    // ── Phase 2: scan /proc/PID/maps once, match symbols ──────────────────────
    // resolved_addrs[i] == 0 means jmps[i] not yet found
    uintptr_t resolved_addrs[MAX_JMPS];
    memset(resolved_addrs, 0, sizeof(resolved_addrs));

    char mpath[64]; snprintf(mpath, sizeof(mpath), "/proc/%d/maps", pid);
    FILE *mf = fopen(mpath, "r");
    if (!mf) { zerr("pre_resolve: cannot open maps errno=%d", errno); return; }

    char map_line[512];
    while (fgets(map_line, sizeof(map_line), mf)) {
        uintptr_t ms = 0; unsigned long mfoff = 0; char mp[8] = {}, md[16] = {};
        unsigned long mino = 0; char lib_path[256] = {};
        if (sscanf(map_line, "%lx-%*lx %7s %lx %15s %lu %255s",
                   &ms, mp, &mfoff, md, &mino, lib_path) < 6) continue;
        if (lib_path[0] != '/') continue;
        if (!strstr(lib_path, ".so")) continue;
        if (mfoff != 0) continue;           // only first mapping = ELF base
        if (mp[0] != 'r') continue;         // must be readable

        int lfd = open(lib_path, O_RDONLY | O_CLOEXEC);
        if (lfd < 0) continue;

        Elf64_Ehdr leh = {};
        if (pread(lfd, &leh, sizeof(leh), 0) != (ssize_t)sizeof(leh) || leh.e_ident[0] != 0x7f) {
            close(lfd); continue;
        }

        uint64_t llv = 0, llo = 0, ldoff = 0, ldsz = 0;
        for (int i = 0; i < (int)leh.e_phnum; i++) {
            Elf64_Phdr lph = {};
            pread(lfd, &lph, sizeof(lph), (off_t)(leh.e_phoff + (uint64_t)i * leh.e_phentsize));
            if (lph.p_type == PT_LOAD && lph.p_offset == 0 && !llo) { llv = lph.p_vaddr; llo = lph.p_offset; }
            if (lph.p_type == PT_DYNAMIC) { ldoff = lph.p_offset; ldsz = lph.p_filesz; }
        }
        if (!ldsz) { close(lfd); continue; }

        uint64_t ls_sym = 0, ls_str = 0, ls_strsz = 0; size_t ls_syment = sizeof(Elf64_Sym);
        size_t lndyn = ldsz / sizeof(Elf64_Dyn);
        for (size_t i = 0; i < lndyn; i++) {
            Elf64_Dyn ld = {};
            pread(lfd, &ld, sizeof(ld), (off_t)(ldoff + i * sizeof(ld)));
            switch (ld.d_tag) {
            case DT_SYMTAB: ls_sym    = ld.d_un.d_ptr; break;
            case DT_STRTAB: ls_str    = ld.d_un.d_ptr; break;
            case DT_STRSZ:  ls_strsz  = ld.d_un.d_val; break;
            case DT_SYMENT: ls_syment = ld.d_un.d_val; break;
            case DT_NULL:   i = lndyn;                  break;
            }
        }
        if (!ls_sym || !ls_str || !ls_strsz) { close(lfd); continue; }

        auto lvma2off = [&](uint64_t vma) -> off_t { return (off_t)(vma - llv + llo); };

        char *lstrtab = (char *)malloc(ls_strsz + 1);
        if (!lstrtab) { close(lfd); continue; }
        lstrtab[ls_strsz] = '\0';
        if (pread(lfd, lstrtab, ls_strsz, lvma2off(ls_str)) != (ssize_t)ls_strsz) {
            free(lstrtab); close(lfd); continue;
        }

        // Upper bound on symbol count: (STRTAB_vma - SYMTAB_vma) / syment
        size_t max_syms = (ls_str > ls_sym) ? (ls_str - ls_sym) / ls_syment : 0;
        if (max_syms > 65536) max_syms = 65536;

        uintptr_t lib_elf_base = ms - (uintptr_t)llv; // handles non-zero first PT_LOAD vaddr
        for (size_t i = 1; i < max_syms; i++) { // index 0 = STN_UNDEF
            Elf64_Sym lsym = {};
            if (pread(lfd, &lsym, sizeof(lsym),
                      (off_t)(lvma2off(ls_sym) + (off_t)(i * ls_syment))) != (ssize_t)sizeof(lsym)) break;
            if (lsym.st_shndx == 0)                            continue; // SHN_UNDEF — not defined here
            if (lsym.st_value == 0)                            continue;
            if ((lsym.st_info >> 4) == 0 /* STB_LOCAL */)     continue;
            if (lsym.st_name >= ls_strsz)                      continue;
            const char *lsname = lstrtab + lsym.st_name;
            if (!lsname[0]) continue;

            for (int j = 0; j < n_jmps; j++) {
                if (strcmp(jmps[j].sym_name, lsname) != 0) continue;
                uintptr_t cand = lib_elf_base + (uintptr_t)lsym.st_value;
                // Prefer executable address; first exec match is final.
                if (!resolved_addrs[j])
                    resolved_addrs[j] = cand;
                else if (is_exec_addr(cand) && !is_exec_addr(resolved_addrs[j]))
                    resolved_addrs[j] = cand;
            }
        }
        free(lstrtab);
        close(lfd);
    }
    fclose(mf);

    // ── Phase 3: write resolved addresses to GOT slots ────────────────────────
    int written = 0;
    for (int i = 0; i < n_jmps; i++) {
        if (!resolved_addrs[i]) {
            zerr("pre_resolve: MISS sym=%s", jmps[i].sym_name);
            continue;
        }
        if (!is_exec_addr(resolved_addrs[i])) {
            zerr("pre_resolve: SKIP sym=%s addr=0x%lx non-exec — would SIGSEGV code=2",
                 jmps[i].sym_name, (unsigned long)resolved_addrs[i]);
            continue;
        }
        uintptr_t slot = elf_base + (uintptr_t)jmps[i].r_offset;
        if (ProcMem::write(slot, &resolved_addrs[i], sizeof(uintptr_t))) {
            written++;
            if (strstr(jmps[i].sym_name, "pthread") || strstr(jmps[i].sym_name, "dlopen") ||
                strstr(jmps[i].sym_name, "dlsym")   || strstr(jmps[i].sym_name, "mmap"))
                zerr("pre_resolve: WROTE sym=%-32s addr=0x%lx slot=0x%lx",
                     jmps[i].sym_name, (unsigned long)resolved_addrs[i], (unsigned long)slot);
        } else {
            zerr("pre_resolve: WRITE FAIL sym=%s slot=0x%lx errno=%d",
                 jmps[i].sym_name, (unsigned long)slot, errno);
        }
    }
    zerr("pre_resolve: done — %d/%d GOT slots written", written, n_jmps);
}

// Patch all BRAA Xn,Xm PLT stubs in the payload's r-xp segment to plain BR Xn.
//
// Root cause: bionic (FF's linker) resolves GOT slots as UNSIGNED plain pointers.
// lld-generated PLT stubs use BRAA Xn,Xm which REQUIRES the GOT slot to be
// pacia-signed with Xm (the GOT slot address) as modifier. Since bionic writes
// unsigned pointers, authentication ALWAYS fails → the branch target register is
// poisoned with an invalid PAC-tagged address → SIGSEGV at zx_payload_start.
//
// Fix: replace every BRAA Xn,Xm instruction in the r-xp segment with BR Xn
// (same destination register, no authentication). The kernel handles D/I-cache
// coherency for PTRACE_POKETEXT writes automatically.
//
// BRAA Xn,Xm encoding: (insn & 0xFFFFFC00) == 0xD71F0800, Rn in bits [4:0].
// BR Xn encoding:       0xD61F0000 | (Rn << 5).
static void patch_plt_braa(pid_t pid) {
    char mpath[64]; snprintf(mpath, sizeof(mpath), "/proc/%d/maps", pid);
    FILE *mf = fopen(mpath, "r");
    if (!mf) { zerr("patch_plt: cannot open /proc/%d/maps errno=%d", pid, errno); return; }

    uintptr_t rx_start = 0, rx_end = 0;
    char line[512];
    while (fgets(line, sizeof(line), mf)) {
        uintptr_t s = 0, e = 0; char p[8] = {};
        sscanf(line, "%lx-%lx %7s", &s, &e, p);
        if (p[0]=='r' && p[1]=='-' && p[2]=='x' && strstr(line, STAGED_NAME)) {
            if (!rx_start || s < rx_start) rx_start = s;
            if (e > rx_end) rx_end = e;
        }
    }
    fclose(mf);

    if (!rx_start) { zerr("patch_plt: no r-xp segment for %s", STAGED_NAME); return; }
    zerr("patch_plt: r-xp [0x%lx-0x%lx] %zuKB",
         (unsigned long)rx_start, (unsigned long)rx_end, (size_t)(rx_end-rx_start)/1024);

    static uint8_t s_pbuf[65536];
    int total_found = 0, total_patched = 0;

    for (uintptr_t pos = rx_start; pos < rx_end; pos += sizeof(s_pbuf)) {
        size_t chunk = (rx_end - pos < sizeof(s_pbuf)) ? (size_t)(rx_end - pos) : sizeof(s_pbuf);
        if (!ProcMem::read(pos, s_pbuf, chunk)) continue;

        for (size_t i = 0; i + 4 <= chunk; i += 4) {
            uint32_t insn; memcpy(&insn, s_pbuf + i, 4);
            // BRAA Xn,Xm: bits [31:10] fixed = 0xD71F08 (key A, Z=0)
            // BRAB Xn,Xm also covered since both use same upper bits with different internal key bit
            if ((insn & 0xFFFFFC00u) != 0xD71F0800u) continue;
            total_found++;
            uint32_t rn   = insn & 0x1Fu;                    // branch target register
            uint32_t repl = 0xD61F0000u | (rn << 5u);        // BR Xn
            uintptr_t addr = pos + i;
            zerr("patch_plt: BRAA(0x%08x) @0x%lx X%u → BR_X%u(0x%08x)",
                 insn, (unsigned long)addr, rn, rn, repl);
            if (remote_poke_insn(pid, addr, repl)) total_patched++;
        }
    }
    zerr("patch_plt: done — %d stubs patched / %d found", total_patched, total_found);
}

// Call dlopen+dlerror via a single shellcode run to both open the .so and
// capture the error message if it fails — all in one PTRACE_CONT window.
//
// 56-byte shellcode layout:
//   [+0 ] LDR X8, #40    — load fn_dlopen from literal pool at +40
//   [+4 ] NOP             — padding
//   [+8 ] BLR X8          — call __loader_dlopen(X0=path, X1=flags, X2=caller_in_ff_ns)
//   [+12] MOV X19, X0    — save handle (callee-saved)
//   [+16] LDR X8, #32    — load fn_dlerror from pool at +48
//   [+20] BLR X8          — call dlerror() → X0 = error string ptr (or NULL)
//   [+24] MOV X1, X0     — dlerror ptr → X1
//   [+28] MOV X0, X19    — restore dlopen handle → X0
//   [+32] BRK #0          — stop; ptrace catches SIGTRAP; X0=handle, X1=dlerror_ptr
//   [+36] NOP             — align pool to 8-byte boundary
//   [+40] fn_dlopen  (8 bytes) — __loader_dlopen in target linker64
//   [+48] fn_dlerror (8 bytes)
static bool remote_dlopen(pid_t pid, const char *so_path) {
    size_t path_len     = strlen(so_path) + 1;
    size_t path_aligned = (path_len + 7) & ~(size_t)7;
    size_t alloc        = path_aligned + 32; // path + 32-byte shellcode

    uintptr_t remote_buf = remote_mmap(pid, alloc);
    if (!remote_buf) { zerr("remote_dlopen: remote_mmap returned 0"); return false; }

    if (!ProcMem::write(remote_buf, so_path, path_len)) {
        zerr("remote_dlopen: write path failed errno=%d", errno); return false;
    }

    // Get the REAL dlopen/dlerror via libmain.so's BIND_NOW-resolved GOT entries.
    // libmain.so imports dlopen@LIBC with GOT slot at ELF VMA 0x9130 and dlerror at 0x9138.
    // These are resolved by FF's own linker at load time → correct namespace, no -4 mystery.
    // Offsets verified from libmain.so arm64 ELF (readelf -r shows R_AARCH64_JUMP_SLOT).
    uintptr_t dlopen_addr = 0;
    {
        uintptr_t libmain_base = ProcMem::findLibBase(pid, "libmain.so");
        zerr("remote_dlopen: libmain_base=0x%lx", (unsigned long)libmain_base);
        if (libmain_base) {
            ProcMem::read(libmain_base + 0x9130UL, &dlopen_addr,  sizeof(dlopen_addr));
            zerr("remote_dlopen: got_dlopen=0x%lx", (unsigned long)dlopen_addr);
        }
    }
    // Fallback: symbol lookup (old method, known to return -4 on this device)
    if (!dlopen_addr) {
        zerr("remote_dlopen: GOT lookup failed, falling back to findSymbol");
        dlopen_addr = ProcMem::findSymbol(pid, "libdl.so", "dlopen");
    }
    if (!dlopen_addr) { zerr("remote_dlopen: no dlopen address found"); return false; }
    // Dump 8 instructions at dlopen_addr and verify it's the 4-insn libdl wrapper.
    // Wrapper fingerprint: insn[2] == MOV X2,X30 == 0xAA1E03E2
    {
        uint32_t insns[8] = {};
        ProcMem::read(dlopen_addr, insns, sizeof(insns));
        zerr("remote_dlopen: dlopen@0x%lx: %08x %08x %08x %08x %08x %08x %08x %08x",
             (unsigned long)dlopen_addr,
             insns[0],insns[1],insns[2],insns[3],insns[4],insns[5],insns[6],insns[7]);
        bool is_wrapper = (insns[2] == 0xAA1E03E2u); // MOV X2,X30
        zerr("remote_dlopen: is_libdl_wrapper=%d (insn[2]=0x%08x, need 0xaa1e03e2)",
             is_wrapper, insns[2]);
        if (!is_wrapper)
            zerr("remote_dlopen: WARNING — dlopen_addr is NOT the wrapper");
    }
    zerr("remote_dlopen: dlopen=0x%lx path=%s", (unsigned long)dlopen_addr, so_path);

    // Locate __loader_dlopen and do_dlopen, and expose linker64 bases for the full scan.
    uintptr_t do_dlopen_local = 0, do_dlopen_target = 0;
    uintptr_t our_linker = 0, target_linker = 0;
    uintptr_t loader_dlopen_addr = find_real_loader_dlopen(
        pid, &do_dlopen_local, &do_dlopen_target, &our_linker, &target_linker);
    if (!loader_dlopen_addr) {
        zerr("remote_dlopen: find_real_loader_dlopen failed — falling back to wrapper");
        loader_dlopen_addr = dlopen_addr;
    }
    zerr("remote_dlopen: loader_dlopen=0x%lx do_dlopen_tgt=0x%lx our_linker=0x%lx tgt_linker=0x%lx",
         (unsigned long)loader_dlopen_addr, (unsigned long)do_dlopen_target,
         (unsigned long)our_linker, (unsigned long)target_linker);

    // Scan ALL executable pages of linker64 for ACE inline hooks.
    static AcePatch s_ace_patches[256];
    int n_patches = 0;
    if (our_linker && target_linker) {
        n_patches = find_ace_linker_hooks(pid, our_linker, target_linker,
                                          s_ace_patches, 256);
    } else {
        zerr("remote_dlopen: linker bases unknown — skipping full scan");
    }

    // Test: can FF's process open the staged file? Use a remote openat syscall.
    // AT_FDCWD=-100, O_RDONLY=0
    {
        pt_regs ro, rr; get_regs(pid, &ro); memcpy(&rr, &ro, sizeof(rr));
        rr.pstate &= ~(uint64_t)(3u << 10);
        rr.regs[8] = 56;                         // __NR_openat
        rr.regs[0] = (uint64_t)-100LL;           // AT_FDCWD
        rr.regs[1] = remote_buf;                 // path (already written above)
        rr.regs[2] = 0;                          // O_RDONLY
        rr.regs[3] = 0;
        rr.pc = find_svc_gadget(pid);
        if (rr.pc && set_regs(pid, &rr)) {
            int wst = singlestep_wait(pid);
            pt_regs rp; get_regs(pid, &rp);
            int64_t fd_ret = (int64_t)rp.regs[0];
            zerr("remote_dlopen: openat test fd=%lld (neg=errno, >=0=ok)", (long long)fd_ret);
            if (fd_ret >= 0) {
                // close fd via syscall
                rp.regs[8] = 57; rp.regs[0] = (uint64_t)fd_ret;
                rp.pc = find_svc_gadget(pid);
                if (rp.pc && set_regs(pid, &rp))
                    singlestep_wait(pid);
            }
            (void)wst;
        }
        set_regs(pid, &ro);
    }

    uintptr_t sc_addr = remote_buf + path_aligned;
    // Minimal 32-byte shellcode: call do_dlopen directly (not __loader_dlopen).
    // __loader_dlopen does PACIBSP then B do_dlopen (tail call) — do_dlopen also does
    // PACIBSP → double-PAC on X30 → corrupted return address → SIGSEGV at RETAB.
    // Bypass by calling do_dlopen directly with proper args: (path, flags, NULL, caller_addr).
    // LDR X8,#24 / NOP / BLR X8 / BRK #0 / NOP / NOP / fn_do_dlopen(8 bytes)
    struct { uint32_t insns[6]; uint64_t fn_do_dlopen; } sc = {};
    sc.insns[0] = 0x580000C8u; // LDR X8, #24  (imm19=6, fn_do_dlopen at offset +24)
    sc.insns[1] = 0xD503201Fu; // NOP
    sc.insns[2] = 0xD63F0100u; // BLR X8  (do_dlopen; X2=NULL extinfo, X3=caller_addr)
    sc.insns[3] = 0xD4200000u; // BRK #0   — stop; X0 = dlopen handle
    sc.insns[4] = 0xD503201Fu; // NOP      (pool align)
    sc.insns[5] = 0xD503201Fu; // NOP
    // do_dlopen(path, flags, extinfo=NULL, caller_addr) — skip __loader_dlopen to avoid
    // double-PACIBSP corruption: __loader_dlopen signs LR then tail-calls do_dlopen which
    // signs the already-signed LR again, producing a corrupted address that crashes RETAB.
    sc.fn_do_dlopen = do_dlopen_target ? (uint64_t)do_dlopen_target : (uint64_t)loader_dlopen_addr;

    if (!ProcMem::write(sc_addr, &sc, sizeof(sc))) {
        zerr("remote_dlopen: write shellcode failed errno=%d", errno); return false;
    }
    // Readback: confirm shellcode landed correctly in remote memory
    {
        struct { uint32_t insns[6]; uint64_t fn_do_dlopen; } rb = {};
        ProcMem::read(sc_addr, &rb, sizeof(rb));
        zerr("remote_dlopen: sc_readback fn_do_dlopen=0x%lx", (unsigned long)rb.fn_do_dlopen);
        zerr("remote_dlopen: sc_readback insns: %08x %08x %08x %08x %08x %08x",
             rb.insns[0],rb.insns[1],rb.insns[2],rb.insns[3],rb.insns[4],rb.insns[5]);
        zerr("remote_dlopen: sc_addr=0x%lx brk_expected_at=0x%lx",
             (unsigned long)sc_addr, (unsigned long)(sc_addr + 12));
    }

    // sc_handle/sc_err_ptr are captured from sr (BRK-state registers) inside the
    // diagnostic block below, BEFORE set_regs(orig) restores the original thread state.
    // Reading them after set_regs would give the original X0/X1 of the target thread,
    // not dlopen's return value.
    uintptr_t sc_handle = 0;

    pt_regs orig, regs;
    get_regs(pid, &orig);
    memcpy(&regs, &orig, sizeof(regs));
    regs.pstate &= ~(uint64_t)(3u << 10); // clear PSTATE.BTYPE
    // do_dlopen(path, flags, extinfo, caller_addr)
    regs.regs[0] = remote_buf;   // path
    regs.regs[1] = RTLD_NOW;     // flags
    regs.regs[2] = 0;            // extinfo = NULL
    // caller_addr: any FF native lib base+0x1000 → do_dlopen resolves in FF's app namespace.
    // libmain.so may be absent in some FF versions; fall back through known Unity/FF libs.
    {
        static const char *const kNSLibs[] = {
            "libmain.so", "libil2cpp.so", "libunity.so", "libGameSDK.so",
            "libtersafe.so", "libUE4.so", nullptr
        };
        uintptr_t ff_ns_base = 0;
        const char *ff_ns_name = nullptr;
        for (int li = 0; kNSLibs[li] && !ff_ns_base; li++) {
            ff_ns_base = ProcMem::findLibBase(pid, kNSLibs[li]);
            if (ff_ns_base) ff_ns_name = kNSLibs[li];
        }
        regs.regs[3] = ff_ns_base ? ff_ns_base + 0x1000 : dlopen_addr;
        zerr("remote_dlopen: caller_addr=0x%lx via %s (base=0x%lx)",
             (unsigned long)regs.regs[3],
             ff_ns_name ? ff_ns_name : "dlopen_fallback",
             (unsigned long)ff_ns_base);
    }
    regs.pc = sc_addr;

    if (!set_regs(pid, &regs)) {
        zerr("remote_dlopen: set_regs failed errno=%d", errno); return false;
    }

    // ── Unity libunity.so PAC tail-call thunk patch ──────────────────────────────
    // libunity.so (20MB) has 28 tail-call thunks: LDP X29,X30 / AUTIBSP / BR X16
    // On PAC-capable devices, Unity's GOT entries are PAC-signed (PACIA + slot addr
    // as modifier). BR X16 doesn't authenticate → X16 high bits remain → SIGSEGV.
    // Fix: temporarily replace each BR X16 (0xD61F0200) with RET (0xD65F03C0).
    // AUTIBSP already cleaned X30 → RET returns correctly to the thunk's caller.
    // These thunks fire during our do_dlopen call via Unity's namespace resolver.
    // Patches are restored immediately after shellcode stops (BRK #0 or crash).
    static constexpr uint32_t kUnityThunkFileOffsets[] = {
        0x01398354,0x013984e0,0x0139992c,0x0139f7e8,
        0x0139f918,0x0139fa88,0x013a17b0,0x013a1de8,
        0x013a1e00,0x013a33ec,0x013a34c8,0x013a35a8,
        0x013a3670,0x013a3688,0x013a37a0,0x013a3b84,
        0x013a3de0,0x013a4974,0x013a51ec,0x013a5904,
        0x013a59ec,0x013a5c28,0x013a5f60,0x013a7134,
        0x013a7a20,0x013a7cec,0x013a7e24,0x013a82d4,
        0x013aabc0,0x013ab068,
    };
    // libunity.so TEXT segment: vaddr=0x413a00, file_offset=0x40fa00
    // → runtime_addr = unity_base + file_offset + 0x4000
    static constexpr uint32_t kUnityTextDelta = 0x4000;
    static constexpr uint32_t kBrX16  = 0xD61F0200u;
    static constexpr uint32_t kRet    = 0xD65F03C0u;

    struct UnityPatch { uintptr_t addr; uint32_t orig; };
    UnityPatch unity_patches[32];
    int n_unity_patches = 0;

    uintptr_t unity_base = ProcMem::findLibBase(pid, "libunity.so");
    if (unity_base) {
        zerr("remote_dlopen: libunity.so base=0x%lx — patching %zu BR_X16 tail-call thunks",
             (unsigned long)unity_base, sizeof(kUnityThunkFileOffsets)/sizeof(kUnityThunkFileOffsets[0]));
        for (auto fo : kUnityThunkFileOffsets) {
            uintptr_t addr = unity_base + fo + kUnityTextDelta;
            uint32_t cur = 0;
            if (!ProcMem::read(addr, &cur, 4)) continue;
            if (cur != kBrX16) {
                zerr("remote_dlopen: unity thunk @0x%lx expected BR_X16 got 0x%08x — skip",
                     (unsigned long)addr, cur);
                continue;
            }
            if (!ProcMem::write(addr, &kRet, 4)) {
                zerr("remote_dlopen: unity thunk @0x%lx write failed errno=%d",
                     (unsigned long)addr, errno);
                continue;
            }
            if (n_unity_patches < 32)
                unity_patches[n_unity_patches++] = {addr, kBrX16};
        }
        zerr("remote_dlopen: patched %d unity thunks BR_X16→RET", n_unity_patches);
    } else {
        zerr("remote_dlopen: libunity.so not found — no thunk patches");
    }

    // Restore all original instructions before shellcode runs.
    // All secondary threads are frozen — no race with ACE re-patching.
    int actually_patched = 0;
    for (int i = 0; i < n_patches; i++) {
        if (remote_poke_insn(pid, s_ace_patches[i].tgt_addr, s_ace_patches[i].orig)) {
            actually_patched++;
        } else {
            zerr("remote_dlopen: POKE FAILED linker64+0x%lx",
                 (unsigned long)(s_ace_patches[i].tgt_addr - target_linker));
        }
    }
    if (n_patches > 0)
        zerr("remote_dlopen: restored %d/%d ACE hooks before shellcode", actually_patched, n_patches);

    // Dump first 8 instructions of do_dlopen BEFORE running shellcode so we can
    // detect AnoSDK hooks at the entry point (BL/B to hook trampoline as insn[0]).
    {
        uint32_t di[8] = {};
        ProcMem::read(do_dlopen_target ? do_dlopen_target : loader_dlopen_addr, di, sizeof(di));
        zerr("remote_dlopen: do_dlopen@0x%lx insns: %08x %08x %08x %08x %08x %08x %08x %08x",
             (unsigned long)(do_dlopen_target ? do_dlopen_target : loader_dlopen_addr),
             di[0],di[1],di[2],di[3],di[4],di[5],di[6],di[7]);
        // Flag if insn[0] looks like a branch — likely AnoSDK inline hook
        uint32_t op0 = di[0] >> 26;
        if (op0 == 0x05 || op0 == 0x04 || (di[0] & 0xFC000000u) == 0x94000000u)
            zerr("remote_dlopen: WARNING do_dlopen insn[0]=0x%08x looks like a branch (AnoSDK hook?)", di[0]);
    }

    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
    int status;
    waitpid(pid, &status, 0);

    // Read ALL state immediately — BEFORE set_regs or re-hooking clobbers anything.
    pt_regs sr; get_regs(pid, &sr);
    siginfo_t si_crash = {};
    ptrace(PTRACE_GETSIGINFO, pid, nullptr, &si_crash);

    zerr("remote_dlopen: stop wstatus=0x%x sig=%d PC=0x%lx (sc_addr+%ld)",
         status, WSTOPSIG(status),
         (unsigned long)sr.pc, (long)sr.pc - (long)sc_addr);
    zerr("remote_dlopen: regs X0=0x%lx X1=0x%lx X2=0x%lx X3=0x%lx",
         (unsigned long)sr.regs[0], (unsigned long)sr.regs[1],
         (unsigned long)sr.regs[2], (unsigned long)sr.regs[3]);
    zerr("remote_dlopen: regs X8=0x%lx X16=0x%lx X17=0x%lx X29=0x%lx X30=0x%lx",
         (unsigned long)sr.regs[8], (unsigned long)sr.regs[16],
         (unsigned long)sr.regs[17], (unsigned long)sr.regs[29], (unsigned long)sr.regs[30]);
    zerr("remote_dlopen: SP=0x%lx PC=0x%lx pstate=0x%lx",
         (unsigned long)sr.sp, (unsigned long)sr.pc, (unsigned long)sr.pstate);

    if (WSTOPSIG(status) != SIGTRAP) {
        // SIGINFO read above (before set_regs) — si_crash has the real fault info
        zerr("remote_dlopen: CRASH sig=%d si_signo=%d si_code=%d si_addr=0x%lx",
             WSTOPSIG(status), si_crash.si_signo, si_crash.si_code,
             (unsigned long)(uintptr_t)si_crash.si_addr);
        // Stack dump — first 8 words above SP (likely contains return addresses)
        uint64_t stk[8] = {};
        if (ProcMem::read(sr.sp, stk, sizeof(stk)))
            zerr("remote_dlopen: stack[SP..SP+56]: %lx %lx %lx %lx %lx %lx %lx %lx",
                 (unsigned long)stk[0], (unsigned long)stk[1],
                 (unsigned long)stk[2], (unsigned long)stk[3],
                 (unsigned long)stk[4], (unsigned long)stk[5],
                 (unsigned long)stk[6], (unsigned long)stk[7]);
        // Instructions around crash PC (if it maps to a valid address)
        if (sr.pc && sr.pc < 0x800000000000ULL) {
            uint32_t ci[8] = {};
            if (ProcMem::read(sr.pc - 16, ci, sizeof(ci)))
                zerr("remote_dlopen: insns@[PC-16]: %08x %08x %08x %08x | %08x %08x %08x %08x",
                     ci[0],ci[1],ci[2],ci[3],ci[4],ci[5],ci[6],ci[7]);
        }

        // /proc/pid/maps scan — identify which library owns crash-related addresses.
        // PAC occupies bits [63:48] (top 16 bits) on all realistic arm64 configs.
        // Clear those 16 bits before range-checking so we find the right library.
        {
            constexpr uintptr_t PAC_MASK = 0x0000FFFFFFFFFFFFull;
            uintptr_t probe_addrs[] = {
                sr.regs[16] & PAC_MASK,   // X16 — PAC-tagged function pointer that crashed
                sr.regs[17] & PAC_MASK,   // X17 — PLT stub or trampoline
                sr.regs[30] & PAC_MASK,   // X30 (LR) — return address into crash function
                stk[0] & PAC_MASK,        // stack frame 0
                stk[1] & PAC_MASK,        // stack frame 1
                stk[7] & PAC_MASK,        // stack frame 7
            };
            zerr("remote_dlopen: maps scan probing X16=0x%lx X17=0x%lx X30=0x%lx stk0=0x%lx stk1=0x%lx stk7=0x%lx",
                 (unsigned long)probe_addrs[0], (unsigned long)probe_addrs[1],
                 (unsigned long)probe_addrs[2], (unsigned long)probe_addrs[3],
                 (unsigned long)probe_addrs[4], (unsigned long)probe_addrs[5]);

            char mpath[64];
            snprintf(mpath, sizeof(mpath), "/proc/%d/maps", pid);
            FILE *mf = fopen(mpath, "r");
            if (mf) {
                char line[512];
                // Track last printed lib to avoid duplicate lines for contiguous regions
                char last_name[256] = {};
                uintptr_t last_start = 0;
                while (fgets(line, sizeof(line), mf)) {
                    uintptr_t start = 0, end = 0;
                    char perms[8] = {}, name[256] = {};
                    sscanf(line, "%lx-%lx %7s %*s %*s %*s %255s",
                           &start, &end, perms, name);
                    if (perms[2] != 'x') continue; // exec regions only
                    bool relevant = false;
                    for (auto a : probe_addrs)
                        if (a && a >= start && a < end) { relevant = true; break; }
                    if (relevant) {
                        // Which probes hit this region
                        const char *labels[] = {"X16","X17","X30","stk0","stk1","stk7"};
                        char hit[64] = {};
                        int hpos = 0;
                        for (int k = 0; k < 6; k++) {
                            if (probe_addrs[k] && probe_addrs[k] >= start && probe_addrs[k] < end) {
                                hpos += snprintf(hit+hpos, sizeof(hit)-hpos, "%s+0x%lx ",
                                                 labels[k], (unsigned long)(probe_addrs[k] - start));
                            }
                        }
                        zerr("remote_dlopen: maps HIT %lx-%lx %s [%s] %s",
                             (unsigned long)start, (unsigned long)end, perms,
                             name[0] ? name : "[anon]", hit);
                    }
                }
                fclose(mf);
            } else {
                zerr("remote_dlopen: maps open failed errno=%d", errno);
            }
        }
    }

    if (sr.pc != sc_addr + 12)
        zerr("remote_dlopen: WARNING PC not at BRK — crashed before BRK");

    // Capture result NOW — before set_regs(orig) restores original thread state.
    sc_handle = (uintptr_t)sr.regs[0];
    zerr("remote_dlopen: captured sc_handle=0x%lx", (unsigned long)sc_handle);

    // Restore Unity tail-call thunk patches (BR_X16 back) before resuming FF.
    for (int i = 0; i < n_unity_patches; i++) {
        if (!ProcMem::write(unity_patches[i].addr, &unity_patches[i].orig, 4))
            zerr("remote_dlopen: unity restore failed @0x%lx errno=%d",
                 (unsigned long)unity_patches[i].addr, errno);
    }
    if (n_unity_patches > 0)
        zerr("remote_dlopen: restored %d unity thunk patches", n_unity_patches);

    // Re-apply ACE's hook instructions after shellcode stops.
    for (int i = 0; i < n_patches; i++) {
        if (!remote_poke_insn(pid, s_ace_patches[i].tgt_addr, s_ace_patches[i].ace))
            zerr("remote_dlopen: WARNING re-hook failed linker64+0x%lx",
                 (unsigned long)(s_ace_patches[i].tgt_addr - target_linker));
    }
    if (n_patches > 0)
        zerr("remote_dlopen: re-applied %d ACE hooks after shellcode", n_patches);

    set_regs(pid, &orig);

    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        return false;
    }

    // ── PLT BRAA → BR patch ──────────────────────────────────────────────────
    // PAC strip moved to immediately before each PTRACE_CONT in init_fn retry loop
    // below — this eliminates the GGP race window where GGP re-signs GOT after
    // strip but before init_fn executes.
    // MUST run AFTER dlopen (so the .so is mapped) and BEFORE zx_payload_start.
    // Replaces PAC-authenticated PLT stubs with plain unconditional branches.
    // Required because bionic (FF's linker) writes unsigned GOT entries; BRAA
    // stubs expect pacia-signed values → auth fail → poison → SIGSEGV.
    patch_plt_braa(pid);

    // ── Pre-resolve GOT so strip_pac_via_rela finds real PAC-tagged entries ──
    // Without this, GOT holds PLT resolver stubs (top16==0) → strip finds 0/138.
    // After this, GOT holds real function addresses → GGP signs them → strip
    // sees PAC tags → strips them → init_fn runs clean.
    uintptr_t elf_base2 = ProcMem::findLibBase(pid, STAGED_NAME);
    pre_resolve_got(pid, so_path, elf_base2);

    // ── Call zx_payload_start() ──────────────────────────────────────────────
    // Constructor was a no-op to avoid PAC PLT crash during dlopen.
    // Now that GOT is pre-resolved and patched, call the real init symbol.
    // NOTE: sc_addr = remote_buf+path_aligned is still valid here — munmap happens AFTER.
    bool payload_init_ok = false; // set to true only when antidect bit confirmed
    {
        uintptr_t sym_off  = find_sym_in_file(so_path, "unity_render_thread_init");
        // elf_base2 already computed above
        uintptr_t fn_start = sym_off ? (elf_base2 + sym_off) : 0;
        zerr("remote_dlopen: init_fn sym_off=0x%lx elf_base=0x%lx fn=0x%lx",
             (unsigned long)sym_off, (unsigned long)elf_base2, (unsigned long)fn_start);
        if (fn_start) {
            struct { uint32_t i[4]; uint64_t fn; } sc2 = {};
            sc2.i[0] = 0x58000088u; // LDR X8, #16  (fn at +16)
            sc2.i[1] = 0xD63F0100u; // BLR X8
            sc2.i[2] = 0xD4200000u; // BRK #0
            sc2.i[3] = 0xD503201Fu; // NOP (align)
            sc2.fn   = (uint64_t)fn_start;
            if (ProcMem::write(sc_addr, &sc2, sizeof(sc2))) {
                // Retry loop — GGP (AnoSDK thread, skipped by freeze_threads_safe) can
                // re-sign our payload's GOT with PACIA between strip and PTRACE_CONT.
                // Strip immediately before each PTRACE_CONT to close the race window.
                bool init_ok = false;
                for (int attempt = 0; attempt < 3 && !init_ok; attempt++) {
                    if (attempt > 0)
                        zerr("remote_dlopen: init_fn retry %d — GGP re-signed GOT, re-stripping PAC", attempt);
                    // Strip PAC right before PTRACE_CONT using the cached elf_base2 to
                    // avoid a redundant /proc/maps scan and shrink the race window further.
                    strip_pac_via_rela(pid, so_path, elf_base2);
                    pt_regs r2; get_regs(pid, &r2);
                    r2.pstate &= ~(uint64_t)(3u << 10);
                    r2.pc = sc_addr;
                    set_regs(pid, &r2);
                    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
                    int st2 = 0; waitpid(pid, &st2, 0);
                    pt_regs sr2; get_regs(pid, &sr2);
                    if (WIFSTOPPED(st2) && WSTOPSIG(st2) == SIGTRAP && sr2.pc == sc_addr + 8) {
                        zerr("remote_dlopen: init_fn OK (attempt %d)", attempt + 1);
                        init_ok = true;
                    } else {
                        int sig2 = WIFSTOPPED(st2) ? WSTOPSIG(st2) : -1;
                        zerr("remote_dlopen: init_fn FAIL wst=0x%x sig=%d PC=0x%lx (sc_addr+%ld)",
                             st2, sig2, (unsigned long)sr2.pc, (long)sr2.pc - (long)sc_addr);
                        zerr("remote_dlopen: start regs X0=0x%lx X1=0x%lx X8=0x%lx X16=0x%lx X17=0x%lx",
                             (unsigned long)sr2.regs[0], (unsigned long)sr2.regs[1],
                             (unsigned long)sr2.regs[8], (unsigned long)sr2.regs[16],
                             (unsigned long)sr2.regs[17]);
                        zerr("remote_dlopen: start regs X29=0x%lx X30=0x%lx SP=0x%lx pstate=0x%lx",
                             (unsigned long)sr2.regs[29], (unsigned long)sr2.regs[30],
                             (unsigned long)sr2.sp, (unsigned long)sr2.pstate);
                        siginfo_t si2 = {};
                        ptrace(PTRACE_GETSIGINFO, pid, nullptr, &si2);
                        zerr("remote_dlopen: start siginfo signo=%d code=%d si_addr=0x%lx",
                             si2.si_signo, si2.si_code, (unsigned long)(uintptr_t)si2.si_addr);
                        uint64_t stk2[8] = {};
                        if (ProcMem::read(sr2.sp, stk2, sizeof(stk2)))
                            zerr("remote_dlopen: start stack[SP]: %lx %lx %lx %lx %lx %lx %lx %lx",
                                 (unsigned long)stk2[0], (unsigned long)stk2[1],
                                 (unsigned long)stk2[2], (unsigned long)stk2[3],
                                 (unsigned long)stk2[4], (unsigned long)stk2[5],
                                 (unsigned long)stk2[6], (unsigned long)stk2[7]);
                        if (sr2.pc && sr2.pc < 0x800000000000ULL) {
                            uint32_t ci2[8] = {};
                            if (ProcMem::read(sr2.pc > 16 ? sr2.pc - 16 : sr2.pc, ci2, sizeof(ci2)))
                                zerr("remote_dlopen: start insns@[PC-16]: %08x %08x %08x %08x | %08x %08x %08x %08x",
                                     ci2[0],ci2[1],ci2[2],ci2[3],ci2[4],ci2[5],ci2[6],ci2[7]);
                        }
                        {
                            constexpr uintptr_t PAC_MASK = 0x0000FFFFFFFFFFFFull;
                            uintptr_t probes[] = {
                                sr2.regs[16] & PAC_MASK,
                                sr2.regs[17] & PAC_MASK,
                                sr2.regs[30] & PAC_MASK,
                                stk2[0] & PAC_MASK,
                                stk2[1] & PAC_MASK,
                            };
                            const char *labels[] = {"X16","X17","X30","stk0","stk1"};
                            zerr("remote_dlopen: start maps probe X16=0x%lx X17=0x%lx X30=0x%lx stk0=0x%lx stk1=0x%lx",
                                 (unsigned long)probes[0], (unsigned long)probes[1],
                                 (unsigned long)probes[2], (unsigned long)probes[3],
                                 (unsigned long)probes[4]);
                            char mpath2[64]; snprintf(mpath2, sizeof(mpath2), "/proc/%d/maps", pid);
                            FILE *mf2 = fopen(mpath2, "r");
                            if (mf2) {
                                char mline[512];
                                while (fgets(mline, sizeof(mline), mf2)) {
                                    uintptr_t ms = 0, me = 0; char mp[8]={}, mn[256]={};
                                    sscanf(mline, "%lx-%lx %7s %*s %*s %*s %255s", &ms, &me, mp, mn);
                                    if (mp[2] != 'x') continue;
                                    bool hit = false;
                                    for (auto a : probes) if (a && a >= ms && a < me) { hit = true; break; }
                                    if (!hit) continue;
                                    char hbuf[128] = {}; int hp = 0;
                                    for (int k = 0; k < 5; k++)
                                        if (probes[k] && probes[k] >= ms && probes[k] < me)
                                            hp += snprintf(hbuf+hp, sizeof(hbuf)-hp, "%s+0x%lx ",
                                                           labels[k], (unsigned long)(probes[k]-ms));
                                    zerr("remote_dlopen: start maps HIT %lx-%lx %s [%s] %s",
                                         (unsigned long)ms, (unsigned long)me, mp,
                                         mn[0] ? mn : "[anon]", hbuf);
                                }
                                fclose(mf2);
                            }
                        }
                        // SIGSEGV means GGP re-signed GOT — restore original regs and retry.
                        if (sig2 == SIGSEGV && attempt < 2) {
                            zerr("remote_dlopen: init_fn SIGSEGV — restoring regs and retrying");
                            set_regs(pid, &orig);
                            continue;
                        }
                    }
                } // end retry loop

                // ── Live-bits safety gate ─────────────────────────────────────────────
                // AntiDetect::install() runs synchronously in init_fn — bit0 of live
                // is set before init_fn returns.  If bit0==0 here the AnoSDK bypass
                // never installed → AnoSDK sees the process unmodified but we already
                // wrote shellcode into it → DETECTABLE → abort so the account survives.
                //
                // ZxCtrl layout: cmd@+0 enable@+4 intensity@+8 ack@+12 live@+16
                // std::atomic<int> stores plain int at its own base (no wrapper offset).
                if (init_ok) {
                    uintptr_t ctrl_off = find_sym_in_file(so_path, "_unity_gfx_params");
                    if (ctrl_off && elf_base2) {
                        uintptr_t live_addr = elf_base2 + ctrl_off + 16;
                        int live_val = 0;
                        ProcMem::read(live_addr, &live_val, sizeof(live_val));
                        bool b0 = (live_val & 1) != 0; // antidect installed
                        bool b1 = (live_val & 2) != 0; // il2cpp ready
                        bool b2 = (live_val & 4) != 0; // features ready
                        bool b3 = (live_val & 8) != 0; // loop ticked
                        zerr("ZX-SAFETY: live=0x%x ANTIDECT=%s IL2CPP=%s FEATURES=%s LOOP=%s",
                             live_val,
                             b0 ? "OK"      : "FAIL",
                             b1 ? "OK"      : "PENDING",
                             b2 ? "OK"      : "PENDING",
                             b3 ? "OK"      : "PENDING");
                        if (b0) {
                            zerr("ZX-SAFETY: *** HOOKS ACTIVE — AnoSDK bypass installed, safe to run ***");
                            payload_init_ok = true;
                        } else {
                            zerr("ZX-SAFETY: *** ANTIDECT FAILED — ABORTING INJECTION TO PREVENT BAN ***");
                            // init_ok stays true so set_regs restores thread, but
                            // payload_init_ok=false causes remote_dlopen to return false.
                        }
                    } else {
                        zerr("ZX-SAFETY: WARNING _unity_gfx_params sym not found "
                             "(ctrl_off=0x%lx elf_base=0x%lx) — skipping safety gate, assuming OK",
                             (unsigned long)ctrl_off, (unsigned long)elf_base2);
                        payload_init_ok = true; // can't verify — optimistic continue
                    }
                }

                set_regs(pid, &orig);
            }
        } else {
            zerr("remote_dlopen: init_fn not found — payload will not run");
        }
    }

    // ── Cleanup anonymous shellcode buffer (path + sc2 both live here) ───────
    remote_munmap(pid, remote_buf, alloc);

    // Use BRK-state registers captured in the diagnostic block above.
    uintptr_t handle = sc_handle;

    zerr("remote_dlopen: handle=0x%lx", (unsigned long)handle);

    // Ground-truth check: did the library actually appear in /proc/pid/maps?
    // Android 10+ uses 32-bit random obfuscated handles (zero-extended to 64 bits),
    // so a valid handle is always in [1, 0xFFFFFFFF]. But verify via maps regardless.
    bool in_maps = false;
    {
        char mpath[64]; snprintf(mpath, sizeof(mpath), "/proc/%d/maps", pid);
        FILE *mf = fopen(mpath, "r");
        char mline[512];
        const char *bname = strrchr(so_path, '/');
        bname = bname ? bname + 1 : so_path;
        while (mf && fgets(mline, sizeof(mline), mf))
            if (strstr(mline, bname)) { in_maps = true; break; }
        if (mf) fclose(mf);
        zerr("remote_dlopen: maps_check: in_maps=%d basename=%s", in_maps, bname);
    }
    // Dump bytes at loader_dlopen_addr to confirm what function is there
    {
        uint32_t ldi[4] = {};
        ProcMem::read(loader_dlopen_addr, ldi, sizeof(ldi));
        zerr("remote_dlopen: __loader_dlopen@0x%lx bytes: %08x %08x %08x %08x",
             (unsigned long)loader_dlopen_addr, ldi[0], ldi[1], ldi[2], ldi[3]);
    }
    // Valid handle: non-zero (includes PAC-tagged handles like 0x3e2b...063 on PAC devices)
    // OR the library appeared in maps (handle may be an internal cookie).
    // Also require payload_init_ok: if AntiDetect bit never set we abort to prevent ban.
    bool mapped_ok = (handle != 0) || in_maps;
    bool ok = mapped_ok && payload_init_ok;
    if (!mapped_ok)
        zerr("remote_dlopen: FAILED — handle=0x%lx in_maps=%d", (unsigned long)handle, in_maps);
    if (mapped_ok && !payload_init_ok)
        zerr("remote_dlopen: SAFETY ABORT — .so mapped but ANTIDECT bit never set");

    return ok;
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

    // Check if payload is already loaded in target (look up by staged name)
    uintptr_t payload_base = ProcMem::findLibBase(pid, STAGED_NAME);

    // Version file written after every successful inject. If it doesn't match
    // PAYLOAD_VERSION the loaded payload is stale (old build left in memory).
    // Force re-injection so the new payload is loaded alongside the old one.
    // Old ctrl_loop keeps running but commands go to the new payload's struct.
    if (payload_base) {
        int file_ver = 0;
        FILE *vf = fopen(VER_FILE, "r");
        if (vf) { fscanf(vf, "%d", &file_ver); fclose(vf); }
        if (file_ver != PAYLOAD_VERSION) {
            zerr("version_check: stale payload (v%d, need v%d) — forcing re-inject", file_ver, PAYLOAD_VERSION);
            payload_base = 0;
        } else {
            zerr("version_check: payload v%d OK", file_ver);
            // Check live bit — if init_fn was interrupted (SIGABRT/SIGSEGV) the
            // payload is mapped but DEAD.  Force re-inject so a fresh init_fn runs.
            const char *p_path = (argc >= 5 && argv[4][0] != '\0') ? argv[4] : nullptr;
            if (p_path) {
                uintptr_t ctrl_off = find_sym_in_file(p_path, "_unity_gfx_params");
                if (ctrl_off) {
                    uintptr_t live_addr = payload_base + ctrl_off + 16;
                    int live_val = 0;
                    ProcMem::read(live_addr, &live_val, sizeof(live_val));
                    if (live_val == 0) {
                        zerr("version_check: live=DEAD — init_fn failed previously, forcing re-inject");
                        payload_base = 0;
                    } else {
                        zerr("version_check: live=0x%x — payload running OK, skip re-inject", live_val);
                    }
                }
            }
        }
    }

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
                     "%s/libunity_render.so", dirname(argv0));
        }

        LOG("Injecting payload from %s", payload_path);

        // Stage payload to FF's own lib directory (always in its linker namespace).
        // /data/local/tmp is file-accessible but NOT in FF's linker namespace → handle=-4.
        // Staging next to libmain.so guarantees the namespace path check passes.
        {
            // Parse /proc/<pid>/maps to extract directory of libmain.so
            char ff_lib_dir[512] = {};
            {
                // libmain.so may be absent in some FF versions — try several known Unity/FF libs
                static const char *const kDirLibs[] = {
                    "libmain.so", "libil2cpp.so", "libunity.so", "libGameSDK.so",
                    "libtersafe.so", "libUE4.so", nullptr
                };
                char maps_path[64];
                snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
                FILE *mf = fopen(maps_path, "r");
                if (mf) {
                    char mline[1024];
                    while (fgets(mline, sizeof(mline), mf) && !ff_lib_dir[0]) {
                        bool matched = false;
                        for (int li = 0; kDirLibs[li] && !matched; li++)
                            if (strstr(mline, kDirLibs[li])) matched = true;
                        if (!matched) continue;
                        if (!strstr(mline, "r-xp") && !strstr(mline, "r--p")) continue;
                        char mpath[512] = {};
                        if (sscanf(mline, "%*lx-%*lx %*s %*lx %*s %*lu %511[^\n]", mpath) == 1) {
                            char *p = mpath; while (*p == ' ') p++;
                            if (*p == '/') {
                                char *sl = strrchr(p, '/');
                                if (sl && (size_t)(sl - p + 2) < sizeof(ff_lib_dir)) {
                                    size_t dlen = (size_t)(sl - p + 1);
                                    memcpy(ff_lib_dir, p, dlen);
                                    ff_lib_dir[dlen] = '\0';
                                }
                            }
                        }
                    }
                    fclose(mf);
                }
            }
            zerr("main: ff_lib_dir=\"%s\"", ff_lib_dir);

            // Try FF lib dir first (in namespace), then fall back to /data/local/tmp/
            const char *candidates[2] = { ff_lib_dir, "/data/local/tmp/" };
            bool staged = false;
            int fi = open(payload_path, O_RDONLY);
            if (fi < 0) {
                zerr("main: cannot open source %s errno=%d", payload_path, errno);
            } else {
                for (int ci = 0; ci < 2 && !staged; ci++) {
                    if (!candidates[ci][0]) continue;
                    char tmp_path[512];
                    snprintf(tmp_path, sizeof(tmp_path), "%s%s", candidates[ci], STAGED_NAME);
                    lseek(fi, 0, SEEK_SET);
                    int fo = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
                    if (fo < 0) { zerr("main: cannot create %s errno=%d", tmp_path, errno); continue; }
                    char cbuf[8192]; ssize_t n;
                    bool write_ok = true;
                    while ((n = read(fi, cbuf, sizeof(cbuf))) > 0)
                        if (write(fo, cbuf, (size_t)n) != n) { write_ok = false; break; }
                    close(fo);
                    if (write_ok) {
                        zerr("main: payload staged at %s", tmp_path);
                        strncpy(payload_path, tmp_path, sizeof(payload_path) - 1);
                        payload_path[sizeof(payload_path) - 1] = '\0';
                        staged = true;
                    } else {
                        zerr("main: write failed %s errno=%d", tmp_path, errno);
                        unlink(tmp_path);
                    }
                }
                close(fi);
            }
        }

        if (!ptrace_attach(pid)) { ProcMem::close(); return 3; }
        freeze_threads_safe(pid);  // SIGSTOP non-AnoSDK threads; skips AnoSDK scanner TIDs
        bool ok = remote_dlopen(pid, payload_path);
        thaw_threads_safe();
        ptrace_detach(pid);

        if (!ok) { ERR("Injection failed"); ProcMem::close(); return 4; }

        // Delete staged file from disk — once dlopen has mapped it into memory
        // the on-disk copy is no longer needed. Leaving it is detectable: AnoSDK
        // scans FF's lib directory for files not in the original APK manifest.
        unlink(payload_path);
        zerr("main: staged file unlinked: %s", payload_path);

        // Write version file so subsequent calls know this payload is current
        FILE *vf = fopen(VER_FILE, "w");
        if (vf) { fprintf(vf, "%d\n", PAYLOAD_VERSION); fclose(vf); }

        payload_base = ProcMem::findLibBase(pid, STAGED_NAME);
        LOG("Payload loaded at 0x%lx", payload_base);
    }

    // Send command to payload via shared memory flag.
    // ProcMem::findSymbol uses dlopen(STAGED_NAME) locally — but the staged file
    // is unlinked right after first injection (line ~1457). On every subsequent
    // call dlopen fails silently → ctrl_addr=0 → write never happens → no features.
    // Fix: resolve symbol offset from the ORIGINAL payload file (argv[4],
    // libunity_render.so — never unlinked) and apply it to the remote base found
    // via /proc/pid/maps (which still shows "libunity_gc.so (deleted)").
    uintptr_t ctrl_addr = 0;
    {
        uintptr_t cb = ProcMem::findLibBase(pid, STAGED_NAME);
        const char *orig = (argc >= 5 && argv[4][0] != '\0') ? argv[4] : nullptr;
        if (cb && orig) {
            uintptr_t off = find_sym_in_file(orig, "_unity_gfx_params");
            if (off) ctrl_addr = cb + off;
        }
        if (!ctrl_addr)
            zerr("ctrl_addr lookup failed: staged_base=0x%lx orig=%s",
                 (unsigned long)cb, orig ? orig : "(null)");
    }
    if (ctrl_addr) {
        // Read live/ack BEFORE write to show current payload state
        int pre_live = 0, pre_ack = 0;
        ProcMem::read(ctrl_addr + 16, &pre_live, sizeof(int));
        ProcMem::read(ctrl_addr + 12, &pre_ack,  sizeof(int));

        // live bitmask: 1=antidect 2=il2cpp 4=features_ready 8=loop_running
        char live_desc[64];
        if (pre_live == 0)        snprintf(live_desc, sizeof(live_desc), "DEAD(0x0) — payload not started yet");
        else if (!(pre_live & 1)) snprintf(live_desc, sizeof(live_desc), "0x%x — antidect not done", pre_live);
        else if (!(pre_live & 8)) snprintf(live_desc, sizeof(live_desc), "0x%x — antidect OK, loop still in init", pre_live);
        else if (!(pre_live & 4)) snprintf(live_desc, sizeof(live_desc), "0x%x — loop running but features NOT ready (il2cpp fail?)", pre_live);
        else                      snprintf(live_desc, sizeof(live_desc), "0x%x — FULLY READY", pre_live);
        zerr("payload_state: live=%s  last_ack=%d", live_desc, pre_ack);

        // Write enable (+4) and intensity (+8) before cmd (+0) so the payload never
        // reads a non-zero cmd with stale enable/intensity values (write-ordering fix)
        int enable_val    = enable ? 1 : 0;
        int intensity_val = intensity;
        ProcMem::write(ctrl_addr + 4, &enable_val,    sizeof(int));
        ProcMem::write(ctrl_addr + 8, &intensity_val, sizeof(int));
        ProcMem::write(ctrl_addr,     &cmd,           sizeof(int)); // cmd last as trigger
        zerr("ctrl_write: cmd=%d en=%d intensity=%d @ 0x%lx", cmd, enable_val, intensity_val, (unsigned long)ctrl_addr);

        // Poll for ACK from ctrl_loop (cmd cleared = processed); up to 600ms.
        // Skip ACK poll for cmd=0 — we wrote 0 so readback is trivially 0, not an ACK.
        if (cmd != 0) {
            bool acked = false;
            for (int i = 0; i < 12; i++) {
                usleep(50000); // 50ms
                int rb = -1;
                if (ProcMem::read(ctrl_addr, &rb, sizeof(int)) && rb == 0) { acked = true; break; }
            }
            int post_ack = 0, post_live = 0;
            ProcMem::read(ctrl_addr + 12, &post_ack,  sizeof(int));
            ProcMem::read(ctrl_addr + 16, &post_live, sizeof(int));
            if (acked)
                zerr("ctrl_ack: PROCESSED (ack=%d live=0x%x)", post_ack, post_live);
            else
                zerr("ctrl_ack: NOT processed within 600ms — loop in 60s init or crashed (live=0x%x ack=%d)", post_live, post_ack);
        }

        LOG("Command sent: cmd=%d enable=%d intensity=%d", cmd, enable_val, intensity_val);
    } else {
        zerr("ctrl_write: SKIP — ctrl_addr=0 (payload struct not found)");
    }

    ProcMem::close();
    return 0;
}

#else // !__aarch64__

// ARM32 stub — injector targets a 64-bit FF process; not applicable on 32-bit ABI
int main(int /*argc*/, char ** /*argv*/) { return 1; }

#endif // __aarch64__
