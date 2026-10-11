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
    ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);
    int wst = 0;
    waitpid(pid, &wst, 0);

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

// Call dlopen+dlerror via a single shellcode run to both open the .so and
// capture the error message if it fails — all in one PTRACE_CONT window.
//
// Extended 48-byte shellcode layout:
//   [+0 ] LDR X8, #32    — load dlopen_addr from literal pool at +32
//   [+4 ] BLR X8          — call dlopen(X0=path, X1=flags)
//   [+8 ] MOV X19, X0    — save handle in callee-saved X19
//   [+12] LDR X8, #28    — load dlerror_addr from literal pool at +40
//   [+16] BLR X8          — call dlerror() → X0 = error string ptr (or NULL)
//   [+20] MOV X1, X0     — dlerror ptr → X1
//   [+24] MOV X0, X19    — restore dlopen handle → X0
//   [+28] BRK #0          — stop; ptrace catches SIGTRAP; X0=handle, X1=dlerror_ptr
//   [+32] dlopen_addr  (8 bytes)
//   [+40] dlerror_addr (8 bytes)
static bool remote_dlopen(pid_t pid, const char *so_path) {
    size_t path_len     = strlen(so_path) + 1;
    size_t path_aligned = (path_len + 7) & ~(size_t)7;
    size_t alloc        = path_aligned + 120; // path + 72-byte shellcode + 48-byte android_dlextinfo

    uintptr_t remote_buf = remote_mmap(pid, alloc);
    if (!remote_buf) { zerr("remote_dlopen: remote_mmap returned 0"); return false; }

    if (!ProcMem::write(remote_buf, so_path, path_len)) {
        zerr("remote_dlopen: write path failed errno=%d", errno); return false;
    }

    // Get the REAL dlopen/dlerror via libmain.so's BIND_NOW-resolved GOT entries.
    // libmain.so imports dlopen@LIBC with GOT slot at ELF VMA 0x9130 and dlerror at 0x9138.
    // These are resolved by FF's own linker at load time → correct namespace, no -4 mystery.
    // Offsets verified from libmain.so arm64 ELF (readelf -r shows R_AARCH64_JUMP_SLOT).
    uintptr_t dlopen_addr = 0, dlerror_addr = 0;
    {
        uintptr_t libmain_base = ProcMem::findLibBase(pid, "libmain.so");
        zerr("remote_dlopen: libmain_base=0x%lx", (unsigned long)libmain_base);
        if (libmain_base) {
            ProcMem::read(libmain_base + 0x9130UL, &dlopen_addr,  sizeof(dlopen_addr));
            ProcMem::read(libmain_base + 0x9138UL, &dlerror_addr, sizeof(dlerror_addr));
            zerr("remote_dlopen: got_dlopen=0x%lx got_dlerror=0x%lx",
                 (unsigned long)dlopen_addr, (unsigned long)dlerror_addr);
        }
    }
    // Fallback: symbol lookup (old method, known to return -4 on this device)
    if (!dlopen_addr) {
        zerr("remote_dlopen: GOT lookup failed, falling back to findSymbol");
        dlopen_addr  = ProcMem::findSymbol(pid, "libdl.so", "dlopen");
        dlerror_addr = ProcMem::findSymbol(pid, "libdl.so", "dlerror");
        if (!dlerror_addr) dlerror_addr = ProcMem::findSymbol(pid, "libc.so", "dlerror");
    }
    if (!dlopen_addr) { zerr("remote_dlopen: no dlopen address found"); return false; }
    // Dump first 4 instructions at dlopen_addr to confirm we have a real function
    {
        uint32_t insns[4] = {};
        ProcMem::read(dlopen_addr, insns, sizeof(insns));
        zerr("remote_dlopen: dlopen@0x%lx bytes: %08x %08x %08x %08x",
             (unsigned long)dlopen_addr, insns[0], insns[1], insns[2], insns[3]);
    }
    zerr("remote_dlopen: dlopen=0x%lx dlerror=0x%lx path=%s",
         (unsigned long)dlopen_addr, (unsigned long)dlerror_addr, so_path);

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
    // Previous 64-insn do_dlopen scan found 0 divergences — ACE hooks deeper.
    // This scan covers every instruction in every r-xp linker64 segment.
    static AcePatch s_ace_patches[256];
    int n_patches = 0;
    if (our_linker && target_linker) {
        n_patches = find_ace_linker_hooks(pid, our_linker, target_linker,
                                          s_ace_patches, 256);
    } else {
        zerr("remote_dlopen: linker bases unknown — skipping full scan");
    }

    // ANDROID_DLEXT_USE_LIBRARY_FD (0x10): call do_dlopen with extinfo.library_fd.
    // Linker uses the fd for file I/O instead of re-opening by path — bypasses
    // namespace path checks. fd is later bounced to a memfd to bypass noexec mount.
    // AT_FDCWD=-100, O_RDONLY=0
    int64_t saved_fd = -1;
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
            ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);
            int wst = 0; waitpid(pid, &wst, 0);
            pt_regs rp; get_regs(pid, &rp);
            int64_t fd_ret = (int64_t)rp.regs[0];
            zerr("remote_dlopen: openat test fd=%lld (neg=errno, >=0=ok)", (long long)fd_ret);
            if (fd_ret >= 0) {
                saved_fd = fd_ret;
                zerr("remote_dlopen: fd=%lld kept open for ANDROID_DLEXT_USE_LIBRARY_FD", (long long)saved_fd);
            }
        }
        set_regs(pid, &ro);
    }
    uintptr_t sc_addr = remote_buf + path_aligned;

    // Bounce the tmp file through a memfd to bypass /data/local/tmp noexec mount.
    // mmap(PROT_EXEC, fd) from a noexec-mounted file → EACCES on segment 2.
    // memfd pages are not filesystem-backed so the kernel never checks noexec.
    if (saved_fd >= 0) {
        uintptr_t svc = find_svc_gadget(pid);
        if (svc) {
            // Write memfd name into sc_addr scratch area (overwritten by shellcode later)
            // Name matches Android ART JIT cache — ACE whitelists these in /proc/maps.
            const char mfd_name[] = "jit-zygote-cache";
            ProcMem::write(sc_addr, mfd_name, sizeof(mfd_name));

            // Helper: run one SVC in FF's process, restore registers, return x0
            auto do_svc = [&](uint64_t nr,
                              uint64_t a0 = 0, uint64_t a1 = 0,
                              uint64_t a2 = 0, uint64_t a3 = 0) -> int64_t {
                pt_regs ro, rr; get_regs(pid, &ro); memcpy(&rr, &ro, sizeof(rr));
                rr.pstate &= ~(uint64_t)(3u << 10);
                rr.regs[8]=nr; rr.regs[0]=a0; rr.regs[1]=a1;
                rr.regs[2]=a2; rr.regs[3]=a3;
                rr.pc = svc;
                if (!set_regs(pid, &rr)) { set_regs(pid, &ro); return -EINVAL; }
                ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);
                int wst=0; waitpid(pid, &wst, 0);
                pt_regs rp; get_regs(pid, &rp);
                set_regs(pid, &ro);
                return (int64_t)rp.regs[0];
            };

            // memfd_create(name, MFD_EXEC|MFD_CLOEXEC=0x11)
            // Kernel <6.3 doesn't know MFD_EXEC → EINVAL; retry with MFD_CLOEXEC=1
            int64_t mfd = do_svc(279, sc_addr, 0x11u);
            if (mfd < 0 && mfd > -4096)
                mfd = do_svc(279, sc_addr, 1u);
            zerr("remote_dlopen: memfd_create ret=%lld", (long long)mfd);

            if (mfd >= 0) {
                // sendfile(memfd, tmpfd, NULL, 64MB) — copies entire payload
                int64_t sf = do_svc(71, (uint64_t)mfd, (uint64_t)saved_fd, 0, 64u*1024*1024);
                zerr("remote_dlopen: sendfile(memfd=%lld, tmpfd=%lld) ret=%lld",
                     (long long)mfd, (long long)saved_fd, (long long)sf);
                do_svc(62, (uint64_t)mfd, 0, 0);  // lseek(memfd, 0, SEEK_SET)
                do_svc(57, (uint64_t)saved_fd);    // close tmp fd
                saved_fd = mfd;
                zerr("remote_dlopen: using memfd=%lld (no-noexec, exec-mappable)", (long long)saved_fd);
            }
        }
    }

    uintptr_t caller_addr_val;
    {
        uintptr_t lb = ProcMem::findLibBase(pid, "libmain.so");
        caller_addr_val = lb ? lb + 0x1000UL : dlopen_addr;
        zerr("remote_dlopen: caller_addr=0x%lx", (unsigned long)caller_addr_val);
    }

    if (do_dlopen_target) {
        // 72-byte shellcode: 4-arg do_dlopen + android_dlextinfo at sc_addr+72
        //   [+0 ] LDR X8,#40  — do_dlopen_target at pool[0]+40
        //   [+4 ] LDR X2,#44  — extinfo_ptr      at pool[1]+48
        //   [+8 ] LDR X3,#48  — caller_addr       at pool[2]+56
        //   [+12] BLR X8       — do_dlopen(X0=path,X1=flags,X2=extinfo,X3=caller)
        //   [+16] MOV X19,X0  — save handle
        //   [+20] LDR X8,#44  — dlerror_addr      at pool[3]+64
        //   [+24] BLR X8       — dlerror()
        //   [+28] MOV X1,X0   [+32] MOV X0,X19   [+36] BRK #0
        struct { uint32_t insns[10]; uint64_t p0, p1, p2, p3; } sc4;
        sc4.insns[0] = 0x58000148u; // LDR X8,#40  PC=0  imm19=10
        sc4.insns[1] = 0x58000162u; // LDR X2,#44  PC=4  imm19=11
        sc4.insns[2] = 0x58000183u; // LDR X3,#48  PC=8  imm19=12
        sc4.insns[3] = 0xD63F0100u; // BLR X8
        sc4.insns[4] = 0xAA0003F3u; // MOV X19,X0
        sc4.insns[5] = 0x58000168u; // LDR X8,#44  PC=20 imm19=11
        sc4.insns[6] = 0xD63F0100u; // BLR X8
        sc4.insns[7] = 0xAA0003E1u; // MOV X1,X0
        sc4.insns[8] = 0xAA1303E0u; // MOV X0,X19
        sc4.insns[9] = 0xD4200000u; // BRK #0
        sc4.p0 = (uint64_t)do_dlopen_target;
        sc4.p1 = (uint64_t)(sc_addr + 72);
        sc4.p2 = (uint64_t)caller_addr_val;
        sc4.p3 = dlerror_addr ? (uint64_t)dlerror_addr : 0ULL;
        if (!ProcMem::write(sc_addr, &sc4, sizeof(sc4))) {
            zerr("remote_dlopen: write shellcode failed errno=%d", errno); return false;
        }
        // android_dlextinfo (48 bytes) at sc_addr+72
        struct { uint64_t flags; uint64_t raddr; uint64_t rsz;
                 int32_t rfd; int32_t lfd; int64_t off; uint64_t ns; } ei = {};
        if (saved_fd >= 0) { ei.flags = 0x10ULL; ei.lfd = (int32_t)saved_fd; }  // ANDROID_DLEXT_USE_LIBRARY_FD=0x10
        if (!ProcMem::write(sc_addr + 72, &ei, sizeof(ei))) {
            zerr("remote_dlopen: write extinfo failed errno=%d", errno); return false;
        }
        zerr("remote_dlopen: extinfo at sc+72: flags=0x%llx lfd=%d",
             (unsigned long long)ei.flags, ei.lfd);
    } else {
        // Fallback: 56-byte shellcode calling __loader_dlopen (no extinfo fd bypass)
        struct { uint32_t insns[10]; uint64_t fn_dlopen; uint64_t fn_dlerror; } sc;
        sc.insns[0] = 0x58000148u; // LDR X8,#40
        sc.insns[1] = 0xD503201Fu; // NOP  (X2=caller pre-set in regs)
        sc.insns[2] = 0xD63F0100u; // BLR X8
        sc.insns[3] = 0xAA0003F3u; // MOV X19,X0
        sc.insns[4] = 0x58000108u; // LDR X8,#32  PC=16 pool=48
        sc.insns[5] = 0xD63F0100u; // BLR X8
        sc.insns[6] = 0xAA0003E1u; // MOV X1,X0
        sc.insns[7] = 0xAA1303E0u; // MOV X0,X19
        sc.insns[8] = 0xD4200000u; // BRK #0
        sc.insns[9] = 0xD503201Fu; // NOP
        sc.fn_dlopen  = (uint64_t)loader_dlopen_addr;
        sc.fn_dlerror = dlerror_addr ? (uint64_t)dlerror_addr : 0ULL;
        if (!ProcMem::write(sc_addr, &sc, sizeof(sc))) {
            zerr("remote_dlopen: write shellcode failed errno=%d", errno); return false;
        }
    }

    pt_regs orig, regs;
    get_regs(pid, &orig);
    memcpy(&regs, &orig, sizeof(regs));
    regs.pstate &= ~(uint64_t)(3u << 10);
    regs.regs[0] = remote_buf;
    regs.regs[1] = RTLD_NOW;
    if (!do_dlopen_target) regs.regs[2] = caller_addr_val;
    regs.pc = sc_addr;

    if (!set_regs(pid, &regs)) {
        zerr("remote_dlopen: set_regs failed errno=%d", errno); return false;
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

    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
    int status;
    waitpid(pid, &status, 0);

    // Re-apply ACE's hook instructions after shellcode stops at BRK #0.
    for (int i = 0; i < n_patches; i++) {
        if (!remote_poke_insn(pid, s_ace_patches[i].tgt_addr, s_ace_patches[i].ace))
            zerr("remote_dlopen: WARNING re-hook failed linker64+0x%lx",
                 (unsigned long)(s_ace_patches[i].tgt_addr - target_linker));
    }
    if (n_patches > 0)
        zerr("remote_dlopen: re-applied %d ACE hooks after shellcode", n_patches);

    // Capture handle+dlerror from BRK stop state BEFORE any register modifications.
    uintptr_t handle = 0, err_ptr = 0, stop_pc = 0;
    {
        pt_regs post; get_regs(pid, &post);
        handle  = (uintptr_t)post.regs[0];
        err_ptr = (uintptr_t)post.regs[1];
        stop_pc = (uintptr_t)post.pc;
    }
    zerr("remote_dlopen: handle=0x%lx dlerror_ptr=0x%lx stop_pc=0x%lx",
         (unsigned long)handle, (unsigned long)err_ptr, (unsigned long)stop_pc);

    // Close the fd kept open for ANDROID_DLEXT_USE_LIBRARY_FD
    if (saved_fd >= 0) {
        pt_regs rcl; get_regs(pid, &rcl);
        rcl.regs[8] = 57; rcl.regs[0] = (uint64_t)saved_fd;
        rcl.pc = find_svc_gadget(pid);
        if (rcl.pc && set_regs(pid, &rcl)) {
            ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);
            int cwst = 0; waitpid(pid, &cwst, 0);
            zerr("remote_dlopen: closed fd=%lld", (long long)saved_fd);
        }
    }

    set_regs(pid, &orig);

    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        zerr("remote_dlopen: bad stop sig=%d stop_pc=0x%lx",
             WSTOPSIG(status), (unsigned long)stop_pc);
        siginfo_t si = {};
        if (ptrace(PTRACE_GETSIGINFO, pid, nullptr, &si) == 0)
            zerr("remote_dlopen: SIGINFO si_signo=%d si_code=%d si_addr=0x%lx",
                 si.si_signo, si.si_code, (unsigned long)(uintptr_t)si.si_addr);
        return false;
    }
    if (err_ptr) {
        char err_str[256] = {};
        if (ProcMem::read(err_ptr, err_str, sizeof(err_str) - 1))
            zerr("remote_dlopen: dlerror=\"%s\"", err_str);
        else
            zerr("remote_dlopen: dlerror read failed (ptr=0x%lx)", (unsigned long)err_ptr);
    }

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
            if (strstr(mline, bname) || strstr(mline, "memfd:jit-zygote-cache")) { in_maps = true; break; }
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
    // Valid handle: non-zero (64-bit on Android 10+, no 32-bit limit)
    // OR library appeared in maps (memfd injection: handle is real but > 32 bits)
    bool ok = handle != 0 || in_maps;
    if (!ok)
        zerr("remote_dlopen: FAILED — handle=0x%lx in_maps=%d", (unsigned long)handle, in_maps);
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

        // Copy payload to /data/local/tmp/ — cross-UID dlopen in FF's linker context
        // may be blocked by SELinux when loading from our app's data dir, but
        // /data/local/tmp/ (shell_data_file context) is accessible to any process.
        {
            char tmp_path[256];
            snprintf(tmp_path, sizeof(tmp_path), "/data/local/tmp/libdns_%d.so", pid);
            int fi = open(payload_path, O_RDONLY);
            if (fi >= 0) {
                int fo = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
                if (fo >= 0) {
                    char cbuf[8192]; ssize_t n;
                    bool write_ok = true;
                    while ((n = read(fi, cbuf, sizeof(cbuf))) > 0)
                        if (write(fo, cbuf, (size_t)n) != n) { write_ok = false; break; }
                    close(fo);
                    if (write_ok) {
                        zerr("main: payload staged at %s", tmp_path);
                        strncpy(payload_path, tmp_path, sizeof(payload_path) - 1);
                        payload_path[sizeof(payload_path) - 1] = '\0';
                    } else {
                        zerr("main: copy write failed errno=%d, using original path", errno);
                        unlink(tmp_path);
                    }
                } else {
                    zerr("main: cannot create %s errno=%d, using original path", tmp_path, errno);
                }
                close(fi);
            } else {
                zerr("main: cannot open source %s errno=%d", payload_path, errno);
            }
        }

        if (!ptrace_attach(pid)) { ProcMem::close(); return 3; }
        freeze_threads(pid);       // stop anti-cheat threads during injection

        // Pre-patch tp_syscall_imp → MOV X0,XZR; RET  BEFORE dlopen fires constructors.
        // DobbySymbolResolver in constructor-100 takes ~50-100ms (full dl_iterate_phdr
        // scan), leaving a window where ACE can call tp_syscall_imp to send SIGKILL.
        // Writing a silent 8-byte trampoline here closes that window entirely — all
        // tp_syscall_imp calls return 0 until constructor-100 installs the Dobby hook.
        // libanort.so tp_syscall_imp is at ELF offset 0x146940 (binary-verified).
        {
            uintptr_t anort_base = ProcMem::findLibBase(pid, "libanort.so");
            zerr("main: libanort.so base=0x%lx", (unsigned long)anort_base);
            if (anort_base) {
                uintptr_t tp_addr = anort_base + 0x146940UL;
                // ARM64 LE: MOV X0,XZR=0xAA1F03E0  RET=0xD65F03C0
                bool p0 = remote_poke_insn(pid, tp_addr,     0xAA1F03E0u);
                bool p1 = remote_poke_insn(pid, tp_addr + 4, 0xD65F03C0u);
                if (p0 && p1)
                    zerr("main: tp_syscall_imp @ 0x%lx pre-patched MOV X0,XZR; RET",
                         (unsigned long)tp_addr);
                else
                    zerr("main: WARNING tp_syscall_imp pre-patch FAILED p0=%d p1=%d",
                         (int)p0, (int)p1);
            } else {
                zerr("main: WARNING libanort.so NOT FOUND — tp pre-patch skipped!");
            }
        }

        // Pre-patch libanogs.so direct-SVC kill stub (ELF offset 0x3f0270) and
        // scanner entries (0x1b9ce4, 0x1ba72c) BEFORE dlopen so they never fire.
        // Kill stub confirmed from run 5: "L29: direct SVC kill hooked @ base+0x3f0270".
        // Scanner NOP-patch closes the window before stealth_ext3 constructor runs.
        {
            uintptr_t anogs_base = ProcMem::findLibBase(pid, "libanogs.so");
            zerr("main: libanogs.so base=0x%lx", (unsigned long)anogs_base);
            if (anogs_base) {
                // Kill SVC stub at ELF offset 0x3f0270 — MOV X0,XZR; RET
                uintptr_t kill_stub = anogs_base + 0x3f0270UL;
                bool p0 = remote_poke_insn(pid, kill_stub,     0xAA1F03E0u); // MOV X0,XZR
                bool p1 = remote_poke_insn(pid, kill_stub + 4, 0xD65F03C0u); // RET
                if (p0 && p1)
                    zerr("main: libanogs kill stub @ 0x%lx pre-patched", (unsigned long)kill_stub);
                else
                    zerr("main: WARNING libanogs kill stub pre-patch FAILED p0=%d p1=%d", (int)p0, (int)p1);

                // openat SVC stub at 0x3f02b0 — same treatment
                uintptr_t openat_stub = anogs_base + 0x3f02b0UL;
                bool q0 = remote_poke_insn(pid, openat_stub,     0xAA1F03E0u);
                bool q1 = remote_poke_insn(pid, openat_stub + 4, 0xD65F03C0u);
                zerr("main: libanogs openat stub @ 0x%lx pre-patched q0=%d q1=%d",
                     (unsigned long)openat_stub, (int)q0, (int)q1);

                // read SVC stub at 0x3f02d0 — same treatment
                uintptr_t read_stub = anogs_base + 0x3f02d0UL;
                bool r0 = remote_poke_insn(pid, read_stub,     0xAA1F03E0u);
                bool r1 = remote_poke_insn(pid, read_stub + 4, 0xD65F03C0u);
                zerr("main: libanogs read stub @ 0x%lx pre-patched r0=%d r1=%d",
                     (unsigned long)read_stub, (int)r0, (int)r1);

                // Scanner entry points — NOP with RET so scan loop never executes
                uintptr_t scn1 = anogs_base + 0x1b9ce4UL;
                uintptr_t scn2 = anogs_base + 0x1ba72cUL;
                bool s1 = remote_poke_insn(pid, scn1, 0xD65F03C0u); // RET
                bool s2 = remote_poke_insn(pid, scn2, 0xD65F03C0u); // RET
                zerr("main: libanogs scanners pre-patched scn1=%d@0x%lx scn2=%d@0x%lx",
                     (int)s1, (unsigned long)scn1, (int)s2, (unsigned long)scn2);
            } else {
                zerr("main: WARNING libanogs.so not found — kill stub pre-patch skipped");
            }
        }

        bool ok = remote_dlopen(pid, payload_path);
        thaw_threads();
        ptrace_detach(pid);

        // Wipe the tmp file immediately after injection — payload is now inside
        // FF's process via memfd. The file on disk is no longer needed and ACE
        // scans /data/local/tmp for recognisable .so names.
        if (strstr(payload_path, "/data/local/tmp/")) {
            unlink(payload_path);
            zerr("main: tmp staging file removed");
        }

        if (!ok) { ERR("Injection failed"); ProcMem::close(); return 4; }

        payload_base = ProcMem::findLibBase(pid, "libzx_payload.so");
        LOG("Payload loaded at 0x%lx", payload_base);
    }

    // Send command to payload via shared memory flag.
    // Locate ctrl struct by scanning for the 16-byte magic tag placed before it
    // in __g_block (payload.cpp).  No symbol lookup — __g_sdktbl1 is private now.
    uintptr_t ctrl_addr = ProcMem::findCtrlByMagic(pid);
    if (ctrl_addr) {
        // Write enable (+4) and intensity (+8) before cmd (+0) so the payload never
        // reads a non-zero cmd with stale enable/intensity values (write-ordering fix)
        int enable_val    = enable ? 1 : 0;
        int intensity_val = intensity;
        ProcMem::write(ctrl_addr + 4, &enable_val,    sizeof(int));
        ProcMem::write(ctrl_addr + 8, &intensity_val, sizeof(int));
        ProcMem::write(ctrl_addr,     &cmd,           sizeof(int)); // cmd last as trigger
        LOG("Command sent: cmd=%d enable=%d intensity=%d", cmd, enable_val, intensity_val);

        // Stream payload ring-buffer log → stderr so ZxEngine shows it in the console.
        // ZxCtrlBlock layout (ctrl_addr = &ctrl.cmd = __g_block + 16):
        //   ctrl_addr + 0  = ctrl.cmd       (4 bytes)
        //   ctrl_addr + 4  = ctrl.enable    (4 bytes)
        //   ctrl_addr + 8  = ctrl.intensity (4 bytes)
        //   ctrl_addr + 12 = log_wp         (uint32_t monotonic write cursor)
        //   ctrl_addr + 16 = log_buf        (char[8192] circular ring)
        constexpr uint32_t LOG_BUF_SZ = 8192;
        char chunk[LOG_BUF_SZ];
        uint32_t last_wp = 0;
        ProcMem::read(ctrl_addr + 12, &last_wp, sizeof(last_wp));
        zerr("payload-log: start (wp=%u, polling 15s max)", last_wp);
        int idle = 0;
        for (int tick = 0; tick < 150; tick++) {    // 150 × 100ms = 15s max
            usleep(100000);
            uint32_t cur_wp = 0;
            if (!ProcMem::read(ctrl_addr + 12, &cur_wp, sizeof(cur_wp))) {
                zerr("payload-log: process gone");
                break;
            }
            if (cur_wp == last_wp) {
                // stop after 5s idle once we've been running >3s total
                if (++idle >= 50 && tick >= 30) { zerr("payload-log: idle stop"); break; }
                continue;
            }
            idle = 0;
            uint32_t n = cur_wp - last_wp;
            if (n > LOG_BUF_SZ) n = LOG_BUF_SZ;   // wrapped: read a full buffer's worth
            ProcMem::read(ctrl_addr + 16, chunk, LOG_BUF_SZ);
            for (uint32_t i = 0; i < n; i++) {
                char c = chunk[(last_wp + i) % LOG_BUF_SZ];
                fputc((c >= 0x20 || c == '\n' || c == '\t') ? c : '\n', stderr);
            }
            if (chunk[(last_wp + n - 1) % LOG_BUF_SZ] != '\n') fputc('\n', stderr);
            fflush(stderr);
            last_wp = cur_wp;
        }
        zerr("payload-log: end (wp=%u)", last_wp);
    }

    ProcMem::close();
    return 0;
}

#else // !__aarch64__

// ARM32 stub — injector targets a 64-bit FF process; not applicable on 32-bit ABI
int main(int /*argc*/, char ** /*argv*/) { return 1; }

#endif // __aarch64__
