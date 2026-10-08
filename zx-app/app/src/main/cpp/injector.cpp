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

// ACE anti-cheat hooks libdl.so's GOT entry for __loader_dlopen (confirmed via
// libanogs.so strings: "ms_set_inlie_hook", "ms_hook_opcode", "mprotect").
// It replaces GOT[__loader_dlopen] in the target process with its own filter
// that returns (void*)-4 for non-whitelisted libraries.
//
// Bypass: our injector process has NO ACE — its libdl.so GOT is unhooked.
// We decode our own dlopen PLT to find the real __loader_dlopen function pointer,
// compute its offset from our linker64 base, then apply to target's linker64 base.
// The shellcode then calls linker64's __loader_dlopen directly, bypassing libdl.so
// and the ACE-patched PLT entirely.
static uintptr_t find_real_loader_dlopen(int target_pid,
                                          uintptr_t *out_do_dlopen_local,
                                          uintptr_t *out_do_dlopen_target) {
    if (out_do_dlopen_local)  *out_do_dlopen_local  = 0;
    if (out_do_dlopen_target) *out_do_dlopen_target = 0;
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
    size_t alloc        = path_aligned + 56; // path + 56-byte shellcode

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

    // ACE hooks do_dlopen (linker64+0x31098) — NOT the __loader_dlopen thunk itself.
    // Strategy:
    //   1. find_real_loader_dlopen() locates both __loader_dlopen and do_dlopen in both
    //      our (unhooked) process and the target, by decoding the B at thunk+8.
    //   2. We PTRACE_PEEKTEXT do_dlopen[0] from target: if it differs from our copy,
    //      ACE's hook is there.
    //   3. Before calling the shellcode, we PTRACE_POKETEXT the original instruction back.
    //   4. After the shellcode returns (BRK #0 stop), we restore ACE's hook instruction.
    //   PTRACE_POKETEXT bypasses page protection on attached root processes; kernel handles
    //   ARM64 icache coherency automatically.
    uintptr_t do_dlopen_local = 0, do_dlopen_target = 0;
    uintptr_t loader_dlopen_addr = find_real_loader_dlopen(pid, &do_dlopen_local, &do_dlopen_target);
    if (!loader_dlopen_addr) {
        zerr("remote_dlopen: find_real_loader_dlopen failed — falling back to wrapper");
        loader_dlopen_addr = dlopen_addr;
    }
    zerr("remote_dlopen: loader_dlopen_addr=0x%lx do_dlopen_target=0x%lx",
         (unsigned long)loader_dlopen_addr, (unsigned long)do_dlopen_target);

    // Read first instructions from both our do_dlopen and target's (possibly hooked) do_dlopen
    uint32_t orig_insn = 0, ace_insn = 0;
    bool should_patch = false;
    if (do_dlopen_local && do_dlopen_target) {
        orig_insn = *(uint32_t*)do_dlopen_local;
        ProcMem::read(do_dlopen_target, &ace_insn, 4);
        zerr("remote_dlopen: do_dlopen local[0]=0x%08x target[0]=0x%08x",
             orig_insn, ace_insn);
        should_patch = (ace_insn != 0) && (orig_insn != ace_insn);
        zerr("remote_dlopen: ACE hook at do_dlopen? %s", should_patch ? "YES — patching" : "no");
    }

    // 56-byte shellcode calling __loader_dlopen(path, flags, fake_caller) directly.
    // X2 (fake_caller = dlopen_addr = address inside libdl.so) is pre-loaded in regs
    // before PTRACE_CONT and is NOT touched by __loader_dlopen at entry (only the
    // wrapper overwrites X2 with X30; __loader_dlopen reads it as its 3rd argument).
    //
    //   [+0 ] LDR X8, #40    — load loader_dlopen_addr from pool at +40
    //   [+4 ] NOP             — X2 already = dlopen_addr from pre-set regs (fake caller)
    //   [+8 ] BLR X8          — call __loader_dlopen(X0=path, X1=flags, X2=fake_caller)
    //   [+12] MOV X19, X0    — save handle (callee-saved)
    //   [+16] LDR X8, #32    — load dlerror_addr from pool at +48
    //   [+20] BLR X8          — call dlerror()
    //   [+24] MOV X1, X0     — dlerror_ptr → X1
    //   [+28] MOV X0, X19    — handle → X0
    //   [+32] BRK #0          — stop
    //   [+36] NOP             — align pool to 8-byte boundary
    //   [+40] fn_loader_dlopen (8 bytes)
    //   [+48] fn_dlerror       (8 bytes)
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
            ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);
            int wst = 0; waitpid(pid, &wst, 0);
            pt_regs rp; get_regs(pid, &rp);
            int64_t fd_ret = (int64_t)rp.regs[0];
            zerr("remote_dlopen: openat test fd=%lld (neg=errno, >=0=ok)", (long long)fd_ret);
            if (fd_ret >= 0) {
                // close fd via syscall
                rp.regs[8] = 57; rp.regs[0] = (uint64_t)fd_ret;
                rp.pc = find_svc_gadget(pid);
                if (rp.pc && set_regs(pid, &rp)) {
                    ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);
                    waitpid(pid, &wst, 0);
                }
            }
        }
        set_regs(pid, &ro);
    }
    uintptr_t sc_addr = remote_buf + path_aligned;
    struct { uint32_t insns[10]; uint64_t fn_dlopen; uint64_t fn_dlerror; } sc;
    sc.insns[0] = 0x58000148u; // LDR X8, #40  (PC=0, target=40, imm19=10)
    sc.insns[1] = 0xD503201Fu; // NOP           (X2 = dlopen_addr already set in regs)
    sc.insns[2] = 0xD63F0100u; // BLR X8        (__loader_dlopen(X0,X1,X2))
    sc.insns[3] = 0xAA0003F3u; // MOV X19, X0   (save handle in callee-saved reg)
    sc.insns[4] = 0x58000108u; // LDR X8, #32   (PC=16, target=48, imm19=8)
    sc.insns[5] = 0xD63F0100u; // BLR X8        (dlerror())
    sc.insns[6] = 0xAA0003E1u; // MOV X1, X0    (dlerror_ptr → X1)
    sc.insns[7] = 0xAA1303E0u; // MOV X0, X19   (handle → X0)
    sc.insns[8] = 0xD4200000u; // BRK #0
    sc.insns[9] = 0xD503201Fu; // NOP            (pool alignment)
    sc.fn_dlopen  = (uint64_t)loader_dlopen_addr;
    sc.fn_dlerror = dlerror_addr ? (uint64_t)dlerror_addr : 0ULL;

    if (!ProcMem::write(sc_addr, &sc, sizeof(sc))) {
        zerr("remote_dlopen: write shellcode failed errno=%d", errno); return false;
    }

    pt_regs orig, regs;
    get_regs(pid, &orig);
    memcpy(&regs, &orig, sizeof(regs));
    regs.pstate &= ~(uint64_t)(3u << 10); // clear PSTATE.BTYPE
    regs.regs[0] = remote_buf;   // __loader_dlopen arg0: path
    regs.regs[1] = RTLD_NOW;    // __loader_dlopen arg1: flags
    // caller_addr: use libmain.so+0x1000 (game namespace) so the linker resolves
    // the load request in the main app namespace rather than the linker's own namespace.
    // Fallback to dlopen_addr (libdl.so) if libmain_base is not available.
    {
        uintptr_t libmain_base = ProcMem::findLibBase(pid, "libmain.so");
        regs.regs[2] = libmain_base ? libmain_base + 0x1000 : dlopen_addr;
        zerr("remote_dlopen: caller_addr=0x%lx (libmain_base=0x%lx)",
             (unsigned long)regs.regs[2], (unsigned long)libmain_base);
    }
    regs.pc = sc_addr;

    if (!set_regs(pid, &regs)) {
        zerr("remote_dlopen: set_regs failed errno=%d", errno); return false;
    }

    // Patch ACE's hook out of do_dlopen just before the shellcode runs.
    // All secondary threads are frozen (freeze_threads called before remote_dlopen),
    // so there is no race with ACE re-patching during the window.
    if (should_patch) {
        if (remote_poke_insn(pid, do_dlopen_target, orig_insn))
            zerr("remote_dlopen: patched do_dlopen: 0x%08x → 0x%08x (ACE→orig)", ace_insn, orig_insn);
        else {
            zerr("remote_dlopen: poke failed — proceeding without patch (will likely get -4)");
            should_patch = false;
        }
    }

    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
    int status;
    waitpid(pid, &status, 0);

    // Restore ACE's hook immediately — MUST happen before set_regs restore
    // so the game's anti-cheat is functional again regardless of shellcode outcome.
    if (should_patch) {
        if (remote_poke_insn(pid, do_dlopen_target, ace_insn))
            zerr("remote_dlopen: restored ACE hook: 0x%08x", ace_insn);
        else
            zerr("remote_dlopen: WARNING: failed to restore ACE hook at 0x%lx!", (unsigned long)do_dlopen_target);
    }

    set_regs(pid, &orig);

    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        pt_regs crash; get_regs(pid, &crash);
        zerr("remote_dlopen: bad stop sig=%d crash_PC=0x%lx",
             WSTOPSIG(status), (unsigned long)crash.pc);
        siginfo_t si = {};
        if (ptrace(PTRACE_GETSIGINFO, pid, nullptr, &si) == 0)
            zerr("remote_dlopen: SIGINFO si_signo=%d si_code=%d si_addr=0x%lx",
                 si.si_signo, si.si_code, (unsigned long)(uintptr_t)si.si_addr);
        return false;
    }

    pt_regs post; get_regs(pid, &post);
    uintptr_t handle  = (uintptr_t)post.regs[0];
    uintptr_t err_ptr = (uintptr_t)post.regs[1];

    zerr("remote_dlopen: handle=0x%lx dlerror_ptr=0x%lx", (unsigned long)handle, (unsigned long)err_ptr);
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
    // Valid handle: non-zero AND fits in 32 bits (random obfuscated cookie on Android 10+)
    // OR the library simply appeared in maps (handle may be a cookie that looks like -4)
    bool ok = (handle != 0 && handle <= 0xFFFFFFFFULL) || in_maps;
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
            snprintf(tmp_path, sizeof(tmp_path), "/data/local/tmp/zxpl_%d.so", pid);
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
