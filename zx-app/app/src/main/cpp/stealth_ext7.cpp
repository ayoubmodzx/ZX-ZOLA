/*
 * stealth_ext7.cpp — Layers 54–61: Gap-closure after full libanogs.so analysis
 *
 * Analysis findings addressed here:
 *
 *   libanogs.so has NO .symtab — only .dynsym — so DobbySymbolResolver
 *   returns null for every internal symbol (inline_hook_opcode_dismatch,
 *   ms_scan_start, ms_hook_opcode, ms_set_inlie_hook). Layer 26 (stx3)
 *   already patches inline_hook_opcode_dismatch via string scan. Layer 56
 *   here extends that to ALL remaining scanner entry-points.
 *
 *   Remaining unhooked AnoSDK exports (confirmed via nm -D on 5.5MB binary):
 *     AnoSDKRegistInfoListener, AnoSDKSetUserInfoWithLicense,
 *     AnoSDKIoctlOld, AnoSDKForExport,
 *     AnoSDKDelReportData, AnoSDKDelReportData3, AnoSDKDelReportData4
 *
 *   inotify_add_watch is blocked (L47) but inotify_init succeeds, giving
 *   AnoSDK a valid fd it can then try to add_watch before our hook fires.
 *
 *   kill()/tgkill() with SIGKILL/SIGABRT to our own PID — not yet filtered.
 *   abort() / _exit() called from libanogs — not yet filtered.
 *
 *   /proc/self/fd readdir entries leak injected lib fd — opendir/readdir
 *   are not yet hooked (only readlink in L53).
 *
 *   chmod called from libanogs to manipulate permissions — not yet blocked.
 *
 * Layer 54: inotify_init / inotify_init1 → ENOSYS (kills inotify at root)
 * Layer 55: AnoSDK remaining export no-ops
 *             AnoSDKRegistInfoListener, AnoSDKSetUserInfoWithLicense,
 *             AnoSDKIoctlOld, AnoSDKForExport,
 *             AnoSDKDelReportData, AnoSDKDelReportData3, AnoSDKDelReportData4
 * Layer 56: Extended scanner NOP-patch — ms_scan_start / ms_hook_opcode /
 *             ms_set_inlie_hook entry-points patched to MOV W0,#0 / RET
 *             via deferred string-reference scan (mirrors L26 in stx3)
 * Layer 57: kill / tgkill SIGKILL / SIGABRT to own PID → EPERM
 * Layer 58: abort / _exit / exit from libanogs range → no-op
 * Layer 59: sigaction / signal for SIGABRT/SIGTRAP from libanogs → block
 * Layer 60: opendir / readdir64_r / closedir on /proc/self/fd — strip our fds
 * Layer 61: chmod / fchmod / fchmodat caller-filtered from libanogs → EPERM
 */

#include "stealth_ext7.hpp"
#include "dobby_stub.hpp"
#include <android/log.h>
#include "zx_logbuf.hpp"
#include <dlfcn.h>
#include <link.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <time.h>
#include <pthread.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cerrno>
#include <atomic>
#include <elf.h>

// Seccomp constants (guard against old NDK headers)
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif
#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC 1
#endif
#ifndef __NR_seccomp
#define __NR_seccomp 277
#endif
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW 0x7fff0000U
#endif
#ifndef SECCOMP_RET_ERRNO
#define SECCOMP_RET_ERRNO 0x00050000U
#endif

#define TAG "ZX-STX7"
#define LI(fmt, ...) LOGBUF_I(TAG, fmt, ##__VA_ARGS__)
#define LE(fmt, ...) LOGBUF_E(TAG, fmt, ##__VA_ARGS__)

// ─────────────────────────────────────────────────────────────────────────────
// pre-L54 — Seccomp BPF: block raw SVC kill/tgkill across all threads
//
// Raw SVC #0 with x8=129 (kill) or x8=131 (tgkill) bypasses every PLT hook,
// GOT patch, and DobbyHook in userspace. Only a seccomp BPF filter intercepts
// it at kernel entry before the syscall executes.
//
// SECCOMP_FILTER_FLAG_TSYNC is the critical piece: it atomically installs the
// filter on ALL threads in the process, including scanner threads in libanogs
// that were already running before our injection — the per-thread fallback
// only covers the calling thread and future children, leaving existing scanner
// threads uncovered.
//
// 22-instruction BPF filter. Built at runtime with our PID baked in:
//   blocks  kill(our_pid|0|-1,   SIGKILL|SIGABRT|SIGTERM)
//   blocks  tgkill(our_pid|0, *, SIGKILL|SIGABRT|SIGTERM)
//   allows  everything else
//
// ARM64 seccomp_data layout (little-endian, BPF_W reads low 32 bits):
//   offset  0: uint32  nr              — syscall number
//   offset  4: uint32  arch
//   offset  8: uint64  instruction_pointer
//   offset 16: uint64  args[0]         (pid for kill;  tgid for tgkill)
//   offset 24: uint64  args[1]         (sig for kill;  tid  for tgkill)
//   offset 32: uint64  args[2]         (              sig  for tgkill)
// ─────────────────────────────────────────────────────────────────────────────

static int install_seccomp_kill_block() {
    // NO_NEW_PRIVS required for seccomp filter without CAP_SYS_ADMIN.
    // Zygote sets this already, but be explicit for injected contexts.
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    pid_t my_pid = getpid();

    struct sock_filter f[] = {
        /* 0  */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),                          // load nr
        /* 1  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 129, 0, 9),                 // nr==kill? jt→2  jf→11
        /* 2  */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 16),                         // load args[0] (pid)
        /* 3  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)my_pid, 2, 0),   // pid==ours  jt→6
        /* 4  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0,           1, 0),          // pid==0     jt→6
        /* 5  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0xffffffffu, 0, 15),         // pid==-1    jt→6 jf→21
        /* 6  */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 24),                         // load args[1] (sig)
        /* 7  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 9,  2, 0),                  // SIGKILL    jt→10
        /* 8  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 6,  1, 0),                  // SIGABRT    jt→10
        /* 9  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 15, 0, 11),                 // SIGTERM    jt→10 jf→21
        /* 10 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),            // BLOCK kill
        /* 11 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),                          // reload nr
        /* 12 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 131, 0, 8),                 // nr==tgkill? jt→13 jf→21
        /* 13 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 16),                         // load args[0] (tgid)
        /* 14 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)my_pid, 1, 0),   // tgid==ours jt→16
        /* 15 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 5),                   // tgid==0    jt→16 jf→21
        /* 16 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 32),                         // load args[2] (sig)
        /* 17 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 9,  2, 0),                  // SIGKILL    jt→20
        /* 18 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 6,  1, 0),                  // SIGABRT    jt→20
        /* 19 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 15, 0, 1),                  // SIGTERM    jt→20 jf→21
        /* 20 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),            // BLOCK tgkill
        /* 21 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),                    // allow
    };
    struct sock_fprog prog = {
        (unsigned short)(sizeof(f) / sizeof(f[0])),
        f
    };

    // TSYNC: apply filter to ALL existing threads (covers pre-existing scanner threads).
    // Pre-4.17 kernels return the TID of the first un-syncable thread (positive value)
    // on partial failure rather than -1+errno. Bionic's syscall() sets errno=0 in that
    // case because the raw return was not in [-4096,-1]. Handle both.
    long raw_r = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                         SECCOMP_FILTER_FLAG_TSYNC, &prog);
    if (raw_r == 0) {
        LI("seccomp TSYNC ok pid=%d insns=%u", my_pid, (unsigned)prog.len);
        return 0;
    }
    if (raw_r > 0) {
        LI("seccomp TSYNC: TID=%ld refused (pre-4.17 kernel, NO_NEW_PRIVS missing on scanner threads) — per-thread fallback", raw_r);
    } else {
        LI("seccomp TSYNC errno=%d — per-thread fallback", errno);
    }

    // Per-thread fallback: only covers this thread and future children
    int pt_r = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
    if (pt_r == 0) {
        LI("seccomp per-thread ok pid=%d", my_pid);
        return 0;
    }
    LE("seccomp failed raw_r=%ld perthread_err=%d", raw_r, errno);
    return -1;
}

// ─────────────────────────────────────────────────────────────────────────────
// libanogs load-range (used by caller-checks in L57-61)
// ─────────────────────────────────────────────────────────────────────────────

struct LibRange7 { uintptr_t base, end; };
static LibRange7        g_ano_r7   = {0, 0};
static LibRange7        g_anort_r7 = {0, 0};
static pthread_mutex_t  g_range7_mu = PTHREAD_MUTEX_INITIALIZER;
static std::atomic<bool> g_range7_ready{false};

static void populate_range7(const char *name, LibRange7 &out) {
    int fd = (int)syscall(56 /*__NR_openat*/, AT_FDCWD,
                          "/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return;
    char buf[4096]; char line[256];
    int bb = 0;
    ssize_t n;
    while ((n = read(fd, buf + bb, sizeof(buf) - bb - 1)) > 0) {
        bb += (int)n; buf[bb] = '\0';
        char *p = buf;
        while (true) {
            char *nl = (char*)memchr(p, '\n', bb - (int)(p - buf));
            if (!nl) break;
            int ll = (int)(nl - p);
            if (ll < (int)sizeof(line)) {
                memcpy(line, p, ll); line[ll] = '\0';
                if (strstr(line, name)) {
                    uintptr_t s = 0, e = 0;
                    sscanf(line, "%lx-%lx", &s, &e);
                    if (out.base == 0 || s < out.base) out.base = s;
                    if (e > out.end) out.end = e;
                }
            }
            p = nl + 1;
        }
        memmove(buf, p, bb - (int)(p - buf));
        bb -= (int)(p - buf);
    }
    close(fd);
}

static void ensure_ranges7() {
    if (g_range7_ready.load(std::memory_order_acquire)) return;
    pthread_mutex_lock(&g_range7_mu);
    if (!g_range7_ready.load(std::memory_order_relaxed)) {
        populate_range7("libanogs.so", g_ano_r7);
        populate_range7("libanort.so", g_anort_r7);
        g_range7_ready.store(true, std::memory_order_release);
    }
    pthread_mutex_unlock(&g_range7_mu);
}

static inline bool caller_is_ano7(uintptr_t ra) {
    ensure_ranges7();
    return (g_ano_r7.base  && ra >= g_ano_r7.base  && ra < g_ano_r7.end)
        || (g_anort_r7.base && ra >= g_anort_r7.base && ra < g_anort_r7.end);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 54 — inotify_init / inotify_init1 → ENOSYS
// If inotify_init succeeds, AnoSDK gets a valid fd before Layer 47's
// inotify_add_watch hook fires, giving it a window to watch our files.
// Returning ENOSYS makes the entire inotify path dead at the root.
// ─────────────────────────────────────────────────────────────────────────────

using FnInotifyInit  = int(*)();
using FnInotifyInit1 = int(*)(int);
static FnInotifyInit  g_orig_inotify_init  = nullptr;
static FnInotifyInit1 g_orig_inotify_init1 = nullptr;

static int hook_inotify_init() {
    errno = ENOSYS;
    return -1;
}

static int hook_inotify_init1(int flags) {
    (void)flags;
    errno = ENOSYS;
    return -1;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 55 — Remaining AnoSDK export no-ops
// These exports were confirmed via nm -D on the 5.5MB libanogs.so binary
// but were missing from both anosdk_bypass.cpp and anti_detect.cpp Layer 3.
// ─────────────────────────────────────────────────────────────────────────────

static void  (*g_orig_AnoRegistListener)(void*, int)         = nullptr;
static int   (*g_orig_AnoSetUserLicense)(int,const char*,
                                         const char*,int)    = nullptr;
static int   (*g_orig_AnoIoctlOld)(int,void*)                = nullptr;
static void *(*g_orig_AnoForExport)(int,void*)               = nullptr;
static void *(*g_orig_AnoDelData)(int*)                      = nullptr;
static void *(*g_orig_AnoDelData3)(int,int*,int)             = nullptr;
static void *(*g_orig_AnoDelData4)(int,int*,int,int)         = nullptr;

static void  hook_AnoRegistListener(void *cb, int t)            { (void)cb; (void)t; }
static int   hook_AnoSetUserLicense(int t, const char *u,
                                    const char *lic, int l)
    { (void)t; (void)u; (void)lic; (void)l; return 0; }
static int   hook_AnoIoctlOld(int cmd, void *d)                 { (void)cmd; (void)d; return 0; }
static void *hook_AnoForExport(int t, void *d)                  { (void)t; (void)d; return nullptr; }
static void *hook_AnoDelData(int *len)                          { if (len) *len = 0; return nullptr; }
static void *hook_AnoDelData3(int t, int *len, int f)
    { (void)t; (void)f; if (len) *len = 0; return nullptr; }
static void *hook_AnoDelData4(int t, int *len, int f, int g)
    { (void)t; (void)f; (void)g; if (len) *len = 0; return nullptr; }

// ─────────────────────────────────────────────────────────────────────────────
// Layer 56 — Extended scanner NOP-patch
// Layer 26 (stealth_ext3.cpp) patches functions referencing
// "inline_hook_opcode_dismatch". Three more scanner entry-points reference
// distinct string literals in the same binary region and need the same
// MOV W0,#0 / RET treatment.
//
// Strings confirmed in libanogs.so .rodata:
//   "ms_scan_start"     @ file offset 0x0008cda0
//   "ms_hook_opcode"    @ file offset 0x00093e41
//   "ms_set_inlie_hook" @ file offset 0x00092315
//
// The scan is structurally identical to find_scanner_offsets() in stx3:
//   1. Find string in loaded binary
//   2. Scan text for ADRP Xn, <str_page>
//   3. Walk back to STP X29,X30 function entry
//   4. Patch: MOV W0,#0 + RET
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Safety helpers
// ─────────────────────────────────────────────────────────────────────────────

// Returns true if the function at `fn` has ≥ 4 non-trivial ARM64 instructions
// before the first RET/SVC — Dobby needs at least 16 bytes for its trampoline.
bool is_hookable_arm64(const void *fn) {
    if (!fn) return false;
    const uint32_t *w = (const uint32_t*)fn;
    if (w[0] == 0xD65F03C0u) return false;        // bare RET
    if ((w[0] & 0xFFE0001Fu) == 0xD4000001u) return false; // SVC #0
    int depth = 0;
    for (int i = 0; i < 8; i++) {
        if (w[i] == 0xD65F03C0u) break;
        depth++;
    }
    return depth >= 4;
}

// Patch libanogs.so's GOT entry for a named import symbol.
// More targeted than DobbyHook on the bionic global: only intercepts calls
// originating inside libanogs.so itself.
bool anogs_patch_got_import(uintptr_t ano_base, const char *sym_name, void *new_fn) {
    if (!ano_base || !sym_name || !new_fn) return false;
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr*)ano_base;
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 || ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 || ehdr->e_ident[EI_MAG3] != ELFMAG3 ||
        ehdr->e_ident[EI_CLASS] != ELFCLASS64) return false;

    const Elf64_Phdr *phdr = (const Elf64_Phdr*)(ano_base + ehdr->e_phoff);
    const Elf64_Dyn  *dyn  = nullptr;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = (const Elf64_Dyn*)(ano_base + phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return false;

    uintptr_t rela_ptr = 0, rela_sz = 0;
    uintptr_t jrel_ptr = 0, jrel_sz = 0;
    uintptr_t sym_ptr  = 0, str_ptr = 0;

    for (const Elf64_Dyn *d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_RELA:     rela_ptr = ano_base + d->d_un.d_ptr; break;
            case DT_RELASZ:   rela_sz  = d->d_un.d_val;            break;
            case DT_JMPREL:   jrel_ptr = ano_base + d->d_un.d_ptr; break;
            case DT_PLTRELSZ: jrel_sz  = d->d_un.d_val;            break;
            case DT_SYMTAB:   sym_ptr  = ano_base + d->d_un.d_ptr; break;
            case DT_STRTAB:   str_ptr  = ano_base + d->d_un.d_ptr; break;
            default: break;
        }
    }
    if (!sym_ptr || !str_ptr) return false;

    const Elf64_Sym *symtab = (const Elf64_Sym*)sym_ptr;
    const char      *strtab = (const char*)str_ptr;
    size_t           nlen   = strlen(sym_name);

    uintptr_t tbls[2] = { rela_ptr, jrel_ptr };
    size_t    szs[2]  = { rela_sz,  jrel_sz  };

    for (int t = 0; t < 2; t++) {
        if (!tbls[t] || !szs[t]) continue;
        size_t cnt = szs[t] / sizeof(Elf64_Rela);
        const Elf64_Rela *rel = (const Elf64_Rela*)tbls[t];
        for (size_t i = 0; i < cnt; i++) {
            uint32_t sidx = ELF64_R_SYM(rel[i].r_info);
            if (!sidx) continue;
            if (strncmp(strtab + symtab[sidx].st_name, sym_name, nlen + 1) != 0) continue;
            uintptr_t *got = (uintptr_t*)(ano_base + rel[i].r_offset);
            uintptr_t  pg  = (uintptr_t)got & ~(uintptr_t)0xFFF;
            if (mprotect((void*)pg, 0x2000, PROT_READ | PROT_WRITE) != 0) return false;
            *got = (uintptr_t)new_fn;
            __builtin___clear_cache((char*)got, (char*)(got + 1));
            mprotect((void*)pg, 0x2000, PROT_READ);
            return true;
        }
    }
    return false;
}

static bool patch_page_rwx(uintptr_t addr, uint32_t i0, uint32_t i1) {
    uintptr_t page = addr & ~(uintptr_t)0xFFF;
    if (mprotect((void*)page, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        return false;
    uint32_t *p = (uint32_t*)addr;
    p[0] = i0; p[1] = i1;
    __builtin___clear_cache((char*)addr, (char*)(addr + 8));
    mprotect((void*)page, 0x1000, PROT_READ | PROT_EXEC);
    return true;
}

static constexpr uint32_t kMovW0Zero = 0x52800000u;
static constexpr uint32_t kRet       = 0xD65F03C0u;

// Returns number of function offsets patched for marker string `marker`.
static int patch_scanner_by_marker(uintptr_t lib_base, size_t lib_sz,
                                    const char *marker) {
    size_t mlen = strlen(marker);

    // Limit scan to the r-x LOAD segment only.
    // The rw- segments and PROT_NONE guard pages between segments must NOT be
    // accessed — libanogs verifies that its guard pages remain PROT_NONE and
    // kills the process (SIGKILL) if they've been made accessible.
    // All code and rodata strings reside in the r-x segment, so this is safe.
    size_t rx_cap = 0;
    {
        const Elf64_Ehdr *ehdr = (const Elf64_Ehdr*)lib_base;
        if (ehdr->e_ident[EI_MAG0] == ELFMAG0 && ehdr->e_ident[EI_CLASS] == ELFCLASS64) {
            const Elf64_Phdr *phdr = (const Elf64_Phdr*)(lib_base + ehdr->e_phoff);
            for (int i = 0; i < ehdr->e_phnum; i++) {
                if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X)) {
                    size_t e = (size_t)(phdr[i].p_vaddr + phdr[i].p_filesz);
                    if (e > rx_cap) rx_cap = e;
                }
            }
        }
    }
    size_t scan_cap = rx_cap ? rx_cap
                             : (lib_sz < 8 * 1024 * 1024 ? lib_sz : 8 * 1024 * 1024);

    // Find marker string in the mapped library image (r-x range only)
    uintptr_t str_va = 0;
    for (size_t i = 0; i + mlen <= scan_cap; i++) {
        if (__builtin_memcmp((void*)(lib_base + i), marker, mlen) == 0) {
            str_va = lib_base + i;
            break;
        }
    }
    if (!str_va) return 0;
    uintptr_t str_page = str_va & ~(uintptr_t)0xFFF;

    // Scan full r-x segment for ADRP Xn, <str_page>.
    // Scanner functions that reference these strings live at HIGHER addresses
    // than the strings themselves — scanning only below str_va misses them all.
    uintptr_t code_lo = lib_base;
    uintptr_t code_hi = lib_base + scan_cap;

    uintptr_t offsets[4] = {};
    int found = 0;
    for (uintptr_t pc = code_lo; pc < code_hi && found < 4; pc += 4) {
        uint32_t insn;
        __builtin_memcpy(&insn, (void*)pc, 4);
        if ((insn & 0x9F000000u) != 0x90000000u) continue;
        // Decode ADRP immediate
        int64_t immlo = (int64_t)((insn >> 29) & 0x3u);
        int64_t immhi = (int64_t)((insn >>  5) & 0x7FFFFu);
        int64_t imm   = (immhi << 2) | immlo;
        if (imm & (1LL << 20)) imm |= ~((1LL << 21) - 1LL);
        uintptr_t tpage = (pc & ~(uintptr_t)0xFFF) + (uintptr_t)(imm << 12);
        if (tpage != str_page) continue;

        // Walk back to STP X29,X30,[SP,#imm] function entry
        // Mask: bits fixed for STP x29,x30 except imm7 field
        uintptr_t back = (pc >= lib_base + 0x600) ? pc - 0x600 : lib_base;
        for (uintptr_t q = pc; q >= back; q -= 4) {
            uint32_t qi;
            __builtin_memcpy(&qi, (void*)q, 4);
            if ((qi & 0xFFC07FFF) == 0xA9807BFD) {
                uintptr_t off = q - lib_base;
                bool dup = false;
                for (int k = 0; k < found; k++) if (offsets[k] == off) { dup = true; break; }
                if (!dup) offsets[found++] = off;
                break;
            }
        }
    }

    int patched = 0;
    for (int i = 0; i < found; i++) {
        uintptr_t fn = lib_base + offsets[i];
        uint32_t existing;
        __builtin_memcpy(&existing, (void*)fn, 4);
        if (existing == kMovW0Zero || existing == kRet) { patched++; continue; }
        if (patch_page_rwx(fn, kMovW0Zero, kRet)) {
            LI("L56: patched '%s' scanner @ base+0x%lx", marker, (unsigned long)offsets[i]);
            patched++;
        } else {
            LE("L56: patch failed '%s' @ base+0x%lx", marker, (unsigned long)offsets[i]);
        }
    }
    return patched;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 57 — kill / tgkill SIGKILL/SIGABRT to own PID → EPERM
// AnoSDK calls kill(getpid(), SIGKILL) or tgkill(tgid, tid, SIGABRT) to
// terminate the process after detecting a hook. SIGKILL cannot be caught
// via sigaction, so blocking it at the kill() PLT entry is the only option.
// ─────────────────────────────────────────────────────────────────────────────

using FnKill   = int(*)(pid_t, int);
using FnTgkill = int(*)(pid_t, pid_t, int);
static FnKill   g_orig_kill   = nullptr;
static FnTgkill g_orig_tgkill = nullptr;

static inline bool is_fatal_sig(int sig) {
    return sig == SIGKILL || sig == SIGABRT || sig == SIGTERM;
}

static int hook_kill(pid_t pid, int sig) {
    pid_t my_pid = getpid();
    if (is_fatal_sig(sig) && (pid == my_pid || pid == 0 || pid == -1)) {
        uintptr_t ra = (uintptr_t)__builtin_return_address(0);
        // Block ALL fatal kills to our PID regardless of caller origin.
        // caller_is_ano7 was too restrictive: external scanner library kills
        // from its own address range (not libanogs), bypassing the caller check
        // and reaching us at wp=6522 after skip+4 walk escaped to valid code.
        LI("L57: blocked kill(%d,%d) from_%s ra=%lx", pid, sig,
           caller_is_ano7(ra) ? "ano" : "ext", (unsigned long)ra);
        errno = EPERM;
        return -1;
    }
    return g_orig_kill ? g_orig_kill(pid, sig)
                       : (int)syscall(129 /*__NR_kill*/, pid, sig);
}

static int hook_tgkill(pid_t tgid, pid_t tid, int sig) {
    pid_t my_pid = getpid();
    if (is_fatal_sig(sig) && (tgid == my_pid || tgid == 0)) {
        uintptr_t ra = (uintptr_t)__builtin_return_address(0);
        LI("L57: blocked tgkill(%d,%d,%d) from_%s ra=%lx", tgid, tid, sig,
           caller_is_ano7(ra) ? "ano" : "ext", (unsigned long)ra);
        errno = EPERM;
        return -1;
    }
    return g_orig_tgkill ? g_orig_tgkill(tgid, tid, sig)
                         : (int)syscall(131 /*__NR_tgkill*/, tgid, tid, sig);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 58 — abort / _exit / exit from libanogs range → no-op
// AnoSDK calls abort() after a positive detection result. Intercepting it at
// the PLT entry with a caller-check prevents the process from dying.
// We return immediately; the calling thread's scanner loop then falls through.
// ─────────────────────────────────────────────────────────────────────────────

using FnAbort = void(*)();
using FnExit  = void(*)(int);
static FnAbort g_orig_abort  = nullptr;
static FnExit  g_orig__exit  = nullptr;
static FnExit  g_orig_exit   = nullptr;

static void hook_abort() {
    uintptr_t ra = (uintptr_t)__builtin_return_address(0);
    if (caller_is_ano7(ra)) {
        LI("L58: suppressed abort() from ano ra=%lx", (unsigned long)ra);
        return;
    }
    if (g_orig_abort) g_orig_abort();
    else syscall(129 /*__NR_kill*/, getpid(), SIGABRT);
}

static void hook__exit(int status) {
    uintptr_t ra = (uintptr_t)__builtin_return_address(0);
    if (caller_is_ano7(ra)) {
        LI("L58: suppressed _exit(%d) from ano ra=%lx", status, (unsigned long)ra);
        return;
    }
    if (g_orig__exit) g_orig__exit(status);
    else syscall(93 /*__NR_exit*/, status);
}

static void hook_exit(int status) {
    uintptr_t ra = (uintptr_t)__builtin_return_address(0);
    if (caller_is_ano7(ra)) {
        LI("L58: suppressed exit(%d) from ano ra=%lx", status, (unsigned long)ra);
        return;
    }
    if (g_orig_exit) g_orig_exit(status);
    else syscall(94 /*__NR_exit_group*/, status);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 59 — sigaction / signal for SIGABRT from libanogs → block
// AnoSDK might try to override our SIGABRT handler to reinstate default
// crash behaviour. A caller-aware sigaction hook prevents this.
// ─────────────────────────────────────────────────────────────────────────────

using FnSigaction = int(*)(int, const struct sigaction*, struct sigaction*);
using FnSignal    = sighandler_t(*)(int, sighandler_t);
static FnSigaction g_orig_sigaction = nullptr;
static FnSignal    g_orig_signal    = nullptr;

static inline bool sig_is_protected(int sig) {
    return sig == SIGABRT || sig == SIGKILL || sig == SIGTRAP
        || sig == SIGSEGV || sig == SIGBUS;
}

static int hook_sigaction(int signum, const struct sigaction *act,
                          struct sigaction *oldact) {
    if (sig_is_protected(signum) && act) {
        uintptr_t ra = (uintptr_t)__builtin_return_address(0);
        if (caller_is_ano7(ra)) {
            LI("L59: blocked sigaction(%d) from ano ra=%lx", signum, (unsigned long)ra);
            // Return success but don't install; fill oldact if requested
            if (oldact) memset(oldact, 0, sizeof(*oldact));
            return 0;
        }
    }
    return g_orig_sigaction ? g_orig_sigaction(signum, act, oldact)
                            : (int)syscall(134 /*__NR_rt_sigaction*/, signum, act, oldact, 8);
}

static sighandler_t hook_signal(int signum, sighandler_t handler) {
    if (sig_is_protected(signum)) {
        uintptr_t ra = (uintptr_t)__builtin_return_address(0);
        if (caller_is_ano7(ra)) {
            LI("L59: blocked signal(%d) from ano ra=%lx", signum, (unsigned long)ra);
            return SIG_DFL;
        }
    }
    return g_orig_signal ? g_orig_signal(signum, handler) : SIG_ERR;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 60 — opendir / fdopendir / readdir64 / closedir for /proc/self/fd
// Layer 53 (stx6) hooks readlink on individual fd symlinks; this closes the
// gap where a full directory listing reveals injected-lib fds by their name.
// We filter readdir entries whose d_name is a digit fd that resolves to a
// memfd/zx or injected-lib path.
// ─────────────────────────────────────────────────────────────────────────────

// File-descriptor entry filter: resolve the fd symlink and return true if
// it points to something we want to hide.
static bool fd_entry_should_hide(const char *d_name) {
    // Only digit-named entries (fd numbers) are interesting
    for (const char *c = d_name; *c; c++)
        if (*c < '0' || *c > '9') return false;

    char lpath[64], target[256];
    snprintf(lpath, sizeof(lpath), "/proc/self/fd/%s", d_name);
    ssize_t lr = (ssize_t)syscall(78 /*__NR_readlinkat*/,
                                   AT_FDCWD, lpath, target, sizeof(target) - 1);
    if (lr <= 0) return false;
    target[lr] = '\0';

    // Hide memfd and injected library fds
    const char *blocked[] = {
        "memfd:zx", "libzx_payload", "zx_payload", "zxpl_", nullptr
    };
    for (int i = 0; blocked[i]; i++)
        if (strstr(target, blocked[i])) return true;
    return false;
}

using FnOpendir    = DIR*(*)(const char*);
using FnFdopendir  = DIR*(*)(int);
using FnReaddir    = struct dirent*(*)(DIR*);
using FnReaddir64  = struct dirent64*(*)(DIR*);
using FnClosedir   = int(*)(DIR*);

static FnOpendir   g_orig_opendir   = nullptr;
static FnFdopendir g_orig_fdopendir = nullptr;
static FnReaddir   g_orig_readdir   = nullptr;
static FnReaddir64 g_orig_readdir64 = nullptr;
static FnClosedir  g_orig_closedir  = nullptr;

// Track whether a DIR* is watching /proc/self/fd
static constexpr int MAX_TRACKED_DIRS = 16;
struct DirEntry7 { DIR *dp; bool is_fd_dir; };
static DirEntry7        g_dirs[MAX_TRACKED_DIRS];
static pthread_mutex_t  g_dirs_mu = PTHREAD_MUTEX_INITIALIZER;

static void dir_register(DIR *dp, bool is_fd) {
    pthread_mutex_lock(&g_dirs_mu);
    for (int i = 0; i < MAX_TRACKED_DIRS; i++)
        if (!g_dirs[i].dp) { g_dirs[i] = {dp, is_fd}; break; }
    pthread_mutex_unlock(&g_dirs_mu);
}
static bool dir_is_fd_dir(DIR *dp) {
    pthread_mutex_lock(&g_dirs_mu);
    for (int i = 0; i < MAX_TRACKED_DIRS; i++)
        if (g_dirs[i].dp == dp) { bool r = g_dirs[i].is_fd_dir; pthread_mutex_unlock(&g_dirs_mu); return r; }
    pthread_mutex_unlock(&g_dirs_mu);
    return false;
}
static void dir_unregister(DIR *dp) {
    pthread_mutex_lock(&g_dirs_mu);
    for (int i = 0; i < MAX_TRACKED_DIRS; i++)
        if (g_dirs[i].dp == dp) { g_dirs[i] = {nullptr, false}; break; }
    pthread_mutex_unlock(&g_dirs_mu);
}

static bool path_is_proc_fd(const char *path) {
    if (!path) return false;
    return strstr(path, "/proc/self/fd") || strstr(path, "/proc/") != nullptr
        ? (strstr(path, "/fd") != nullptr)
        : false;
}

static DIR *hook_opendir(const char *name) {
    DIR *dp = g_orig_opendir ? g_orig_opendir(name) : nullptr;
    if (dp) dir_register(dp, path_is_proc_fd(name));
    return dp;
}

static DIR *hook_fdopendir(int fd) {
    // Peek at what fd points to
    char lpath[64], target[256];
    snprintf(lpath, sizeof(lpath), "/proc/self/fd/%d", fd);
    ssize_t lr = (ssize_t)syscall(78, AT_FDCWD, lpath, target, sizeof(target)-1);
    bool is_fd = (lr > 0 && (target[lr] = '\0', strstr(target, "/fd")));
    DIR *dp = g_orig_fdopendir ? g_orig_fdopendir(fd) : nullptr;
    if (dp) dir_register(dp, is_fd);
    return dp;
}

static struct dirent *hook_readdir(DIR *dp) {
    if (!g_orig_readdir) return nullptr;
    struct dirent *ent;
    while ((ent = g_orig_readdir(dp)) != nullptr) {
        if (dir_is_fd_dir(dp) && fd_entry_should_hide(ent->d_name))
            continue;
        return ent;
    }
    return nullptr;
}

static struct dirent64 *hook_readdir64(DIR *dp) {
    if (!g_orig_readdir64) return nullptr;
    struct dirent64 *ent;
    while ((ent = g_orig_readdir64(dp)) != nullptr) {
        if (dir_is_fd_dir(dp) && fd_entry_should_hide(ent->d_name))
            continue;
        return ent;
    }
    return nullptr;
}

static int hook_closedir(DIR *dp) {
    dir_unregister(dp);
    return g_orig_closedir ? g_orig_closedir(dp) : (errno = EBADF, -1);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 61 — chmod / fchmod / fchmodat caller-filter from libanogs
// AnoSDK uses chmod to lock down or expose files as a detection trigger.
// Block any permission change originating from ano address range.
// ─────────────────────────────────────────────────────────────────────────────

using FnChmod    = int(*)(const char*, mode_t);
using FnFchmod   = int(*)(int, mode_t);
using FnFchmodat = int(*)(int, const char*, mode_t, int);
static FnChmod    g_orig_chmod    = nullptr;
static FnFchmod   g_orig_fchmod   = nullptr;
static FnFchmodat g_orig_fchmodat = nullptr;

static int hook_chmod(const char *path, mode_t mode) {
    uintptr_t ra = (uintptr_t)__builtin_return_address(0);
    if (caller_is_ano7(ra)) {
        LI("L61: blocked chmod('%s',%o) from ano", path ? path : "?", (unsigned)mode);
        errno = EPERM; return -1;
    }
    return g_orig_chmod ? g_orig_chmod(path, mode) : (errno = ENOSYS, -1);
}

static int hook_fchmod(int fd, mode_t mode) {
    uintptr_t ra = (uintptr_t)__builtin_return_address(0);
    if (caller_is_ano7(ra)) {
        LI("L61: blocked fchmod(%d,%o) from ano", fd, (unsigned)mode);
        errno = EPERM; return -1;
    }
    return g_orig_fchmod ? g_orig_fchmod(fd, mode) : (errno = ENOSYS, -1);
}

static int hook_fchmodat(int dirfd, const char *path, mode_t mode, int flags) {
    uintptr_t ra = (uintptr_t)__builtin_return_address(0);
    if (caller_is_ano7(ra)) {
        LI("L61: blocked fchmodat('%s',%o) from ano", path ? path : "?", (unsigned)mode);
        errno = EPERM; return -1;
    }
    return g_orig_fchmodat ? g_orig_fchmodat(dirfd, path, mode, flags)
                           : (errno = ENOSYS, -1);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 56 deferred patch thread
// Runs after libanogs has loaded (mirrors scanner_patch_thread in stx3).
// Patches three additional scanner entry-points not covered by Layer 26.
// ─────────────────────────────────────────────────────────────────────────────

struct PhdrCtx7 { const char *name; uintptr_t base; size_t total_sz; };

static int phdr_find7(struct dl_phdr_info *info, size_t, void *data) {
    auto *ctx = (PhdrCtx7*)data;
    if (!info->dlpi_name || !strstr(info->dlpi_name, ctx->name)) return 0;
    ctx->base = (uintptr_t)info->dlpi_addr;
    for (int i = 0; i < info->dlpi_phnum; i++)
        if (info->dlpi_phdr[i].p_type == PT_LOAD) {
            size_t e = (size_t)(info->dlpi_phdr[i].p_vaddr + info->dlpi_phdr[i].p_memsz);
            if (e > ctx->total_sz) ctx->total_sz = e;
        }
    return 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// patch_raw_svc_kill — NOP out raw SVC kill/tgkill calls in a library.
//
// Seccomp TSYNC fails on pre-4.17 kernels (and on Android when scanner threads
// don't have NO_NEW_PRIVS=1) so we can't block raw SVC via seccomp on those
// threads. Instead we scan the r-x segment for the literal opcode sequence:
//   MOV X8, #129  (D2801028)  — __NR_kill
//   MOV X8, #131  (D2801068)  — __NR_tgkill
// within 4 instructions before any SVC #0 (D4000001) and replace the SVC
// with MOV X0, #0 (D2800000) — a fake "success" return.  The caller sees 0
// and assumes the kill succeeded, so it doesn't retry.
//
// Only the r-x segment is walked — PROT_NONE gap pages between LOAD segments
// are never touched (rx_cap is capped at the first executable LOAD segment's
// end, which is always below the first gap).
// ─────────────────────────────────────────────────────────────────────────────

static int patch_raw_svc_kill(uintptr_t lib_base, size_t lib_sz,
                               const char *lib_name) {
    if (!lib_base || !lib_sz) return 0;

    static constexpr uint32_t kSVC0          = 0xD4000001u;
    static constexpr uint32_t kMovX8Kill     = 0xD2801028u;  // MOV X8, #129
    static constexpr uint32_t kMovX8Tgkill   = 0xD2801068u;  // MOV X8, #131
    static constexpr uint32_t kMovX0Zero     = 0xD2800000u;  // MOV X0, #0

    // Restrict scan to first r-x LOAD segment to avoid PROT_NONE gaps
    size_t rx_cap = 0;
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr*)lib_base;
    if (ehdr->e_ident[EI_MAG0] == ELFMAG0 && ehdr->e_ident[EI_CLASS] == ELFCLASS64) {
        const Elf64_Phdr *phdr = (const Elf64_Phdr*)(lib_base + ehdr->e_phoff);
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X)) {
                size_t e = (size_t)(phdr[i].p_vaddr + phdr[i].p_filesz);
                if (e > rx_cap) rx_cap = e;
            }
        }
    }
    if (!rx_cap)
        rx_cap = lib_sz < 8 * 1024 * 1024 ? lib_sz : 8 * 1024 * 1024;

    int patched = 0;
    for (size_t off = 16; off + 4 <= rx_cap; off += 4) {
        uint32_t insn;
        __builtin_memcpy(&insn, (void*)(lib_base + off), 4);
        if (insn != kSVC0) continue;

        // Walk back up to 4 instructions looking for MOV X8, #kill/#tgkill
        for (int back = 1; back <= 4; back++) {
            uint32_t prev;
            __builtin_memcpy(&prev, (void*)(lib_base + off - (size_t)(back * 4)), 4);
            if (prev != kMovX8Kill && prev != kMovX8Tgkill) continue;

            // Found matching MOV X8 — replace SVC #0 with MOV X0, #0
            uintptr_t svc_addr = lib_base + off;
            uintptr_t pg       = svc_addr & ~(uintptr_t)0xFFF;
            if (mprotect((void*)pg, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
                uint32_t *p = (uint32_t*)svc_addr;
                *p = kMovX0Zero;
                __builtin___clear_cache((char*)p, (char*)(p + 1));
                mprotect((void*)pg, 0x1000, PROT_READ | PROT_EXEC);
                LI("L56+: SVC→MOV_X0_0 [%s] %s+0x%zx (back=%d)",
                   prev == kMovX8Kill ? "kill" : "tgkill", lib_name, off, back);
                patched++;
            }
            break;  // stop backtracking for this SVC site
        }
    }
    LI("L56+: raw SVC kill-block: %d sites patched in %s", patched, lib_name);
    return patched;
}

static void *ext7_scanner_thread(void*) {
    prctl(PR_SET_NAME, "kworker/u16:3", 0, 0, 0);

    uintptr_t ano_base = 0;
    size_t    lib_sz   = 0;
    for (int tries = 0; tries < 2000 && !ano_base; tries++) {
        PhdrCtx7 ctx{"libanogs.so", 0, 0};
        dl_iterate_phdr(phdr_find7, &ctx);
        if (ctx.base) { ano_base = ctx.base; lib_sz = ctx.total_sz; }
        if (!ano_base) { struct timespec ts{0, 5000000}; nanosleep(&ts, nullptr); }
    }
    if (!ano_base) {
        LE("L56: libanogs.so never appeared");
        return nullptr;
    }
    if (!lib_sz || lib_sz > 32 * 1024 * 1024) lib_sz = 8 * 1024 * 1024;

    // Populate ano range for caller checks once lib is loaded
    pthread_mutex_lock(&g_range7_mu);
    if (g_ano_r7.base == 0) {
        g_ano_r7 = {ano_base, ano_base + lib_sz};
    }
    pthread_mutex_unlock(&g_range7_mu);

    static const char *kMarkers[] = {
        "ms_scan_start",
        "ms_hook_opcode",
        "ms_set_inlie_hook",
        nullptr
    };
    int total = 0;
    for (int i = 0; kMarkers[i]; i++) {
        int n = patch_scanner_by_marker(ano_base, lib_sz, kMarkers[i]);
        if (n == 0)
            LE("L56: no function found for marker '%s'", kMarkers[i]);
        total += n;
    }
    LI("L56: extended scanner patch done — %d functions patched across 3 markers", total);

    // Scan and NOP raw SVC kill/tgkill call sites in libanogs and libanort.
    // TSYNC seccomp fails on this kernel (pre-4.17 TID return — existing scanner
    // threads don't have NO_NEW_PRIVS) so we eliminate the kill sites directly.
    patch_raw_svc_kill(ano_base, lib_sz, "libanogs");
    {
        PhdrCtx7 ctx{"libanort.so", 0, 0};
        dl_iterate_phdr(phdr_find7, &ctx);
        if (ctx.base) {
            size_t sz = ctx.total_sz ? ctx.total_sz : 4 * 1024 * 1024;
            if (sz > 32 * 1024 * 1024) sz = 4 * 1024 * 1024;
            patch_raw_svc_kill(ctx.base, sz, "libanort");
        }
    }

    // Update ranges for caller-check hooks now that lib is confirmed
    g_range7_ready.store(false, std::memory_order_release);
    ensure_ranges7();

    return nullptr;
}

static void launch_ext7_scanner() {
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &attr, ext7_scanner_thread, nullptr);
    pthread_attr_destroy(&attr);
}

// ─────────────────────────────────────────────────────────────────────────────
// install_stealth_ext7
// ─────────────────────────────────────────────────────────────────────────────

void install_stealth_ext7() {
    LI("L54-61 enter");

    // Install seccomp kill/tgkill block BEFORE anything else.
    // Raw SVC #0 with x8=129/131 bypasses every PLT hook and DobbyHook —
    // seccomp BPF with TSYNC is the only intercept that covers pre-existing
    // scanner threads already running in libanogs before injection.
    install_seccomp_kill_block();

    // Resolve libanogs.so and libanort.so base early — needed for GOT patching.
    uintptr_t ano_base = 0;
    size_t    ano_sz   = 0;
    {
        PhdrCtx7 ctx{"libanogs.so", 0, 0};
        dl_iterate_phdr(phdr_find7, &ctx);
        ano_base = ctx.base;
        ano_sz   = ctx.total_sz ? ctx.total_sz : 8 * 1024 * 1024;
    }
    LI("L54-61: ano_base=0x%lx sz=0x%lx", (unsigned long)ano_base, (unsigned long)ano_sz);

    uintptr_t anort_base = 0;
    size_t    anort_sz   = 0;
    {
        PhdrCtx7 ctx{"libanort.so", 0, 0};
        dl_iterate_phdr(phdr_find7, &ctx);
        anort_base = ctx.base;
        anort_sz   = ctx.total_sz ? ctx.total_sz : 4 * 1024 * 1024;
    }
    LI("L54-61: anort_base=0x%lx sz=0x%lx", (unsigned long)anort_base, (unsigned long)anort_sz);

    // ── Layer 54: inotify_init / inotify_init1 ───────────────────────────────
    // Both bionic wrappers are ≤ 12 bytes on arm64 — too short for Dobby inline
    // trampolines. Use GOT patching inside libanogs instead.
    if (ano_base) {
        bool pi0 = anogs_patch_got_import(ano_base, "inotify_init",  (void*)hook_inotify_init);
        bool pi1 = anogs_patch_got_import(ano_base, "inotify_init1", (void*)hook_inotify_init1);
        LI("L54: GOT patch inotify_init=%d inotify_init1=%d", (int)pi0, (int)pi1);
    } else {
        void *sym_ii  = dlsym(RTLD_DEFAULT, "inotify_init");
        void *sym_ii1 = dlsym(RTLD_DEFAULT, "inotify_init1");
        if (sym_ii  && is_hookable_arm64(sym_ii))
            DobbyHook(sym_ii,  (void*)hook_inotify_init,  (void**)&g_orig_inotify_init);
        else LI("L54: inotify_init not hookable sym=%p", sym_ii);
        if (sym_ii1 && is_hookable_arm64(sym_ii1))
            DobbyHook(sym_ii1, (void*)hook_inotify_init1, (void**)&g_orig_inotify_init1);
        else LI("L54: inotify_init1 not hookable sym=%p", sym_ii1);
    }
    LI("L54 done");

    // ── Layer 55: remaining AnoSDK exports ───────────────────────────────────
    LI("L55 start");
    void *ano = dlopen("libanogs.so", RTLD_LAZY | RTLD_NOLOAD);
    if (!ano) dlerror();

    auto try_ano = [&](const char *sym, void *rep, void **orig) {
        void *addr = ano ? dlsym(ano, sym) : nullptr;
        if (!addr) {
            char buf[128];
            snprintf(buf, sizeof(buf), "%s@@ANO", sym);
            addr = ano ? dlsym(ano, buf) : nullptr;
        }
        if (!addr) addr = DobbySymbolResolver("libanogs.so", sym);
        if (addr && is_hookable_arm64(addr)) DobbyHook(addr, rep, orig);
        else if (addr) LI("L55: sym %s too short for Dobby", sym);
        else           LI("L55: sym not found: %s", sym);
    };

    try_ano("AnoSDKRegistInfoListener",    (void*)hook_AnoRegistListener,  (void**)&g_orig_AnoRegistListener);
    try_ano("AnoSDKSetUserInfoWithLicense",(void*)hook_AnoSetUserLicense,  (void**)&g_orig_AnoSetUserLicense);
    try_ano("AnoSDKIoctlOld",              (void*)hook_AnoIoctlOld,        (void**)&g_orig_AnoIoctlOld);
    try_ano("AnoSDKForExport",             (void*)hook_AnoForExport,       (void**)&g_orig_AnoForExport);
    try_ano("AnoSDKDelReportData",         (void*)hook_AnoDelData,         (void**)&g_orig_AnoDelData);
    try_ano("AnoSDKDelReportData3",        (void*)hook_AnoDelData3,        (void**)&g_orig_AnoDelData3);
    try_ano("AnoSDKDelReportData4",        (void*)hook_AnoDelData4,        (void**)&g_orig_AnoDelData4);
    LI("L55 done");

    // ── Layer 56: deferred ms_scan_start / ms_hook_opcode NOP-patch ──────────
    launch_ext7_scanner();
    LI("L56 launched");

    // ── Layer 57: kill / tgkill ───────────────────────────────────────────────
    LI("L57 start");
    void *sym_kill   = dlsym(RTLD_DEFAULT, "kill");
    void *sym_tgkill = dlsym(RTLD_DEFAULT, "tgkill");
    if (sym_kill && is_hookable_arm64(sym_kill))
        DobbyHook(sym_kill, (void*)hook_kill, (void**)&g_orig_kill);
    else LI("L57: kill not hookable sym=%p", sym_kill);
    if (sym_tgkill && is_hookable_arm64(sym_tgkill))
        DobbyHook(sym_tgkill, (void*)hook_tgkill, (void**)&g_orig_tgkill);
    else LI("L57: tgkill not hookable sym=%p", sym_tgkill);
    LI("L57 done");

    // ── Layer 58: abort / _exit / exit ────────────────────────────────────────
    // bionic's _exit is 8-12 bytes — Dobby would corrupt adjacent code.
    // Patch libanogs.so's GOT entries directly so only libanogs calls are
    // intercepted. Store bionic originals for non-libanogs fallback paths.
    LI("L58 start");
    if (ano_base) {
        bool pa = anogs_patch_got_import(ano_base, "abort",  (void*)hook_abort);
        bool pe = anogs_patch_got_import(ano_base, "_exit",  (void*)hook__exit);
        bool px = anogs_patch_got_import(ano_base, "exit",   (void*)hook_exit);
        LI("L58: GOT abort=%d _exit=%d exit=%d", (int)pa, (int)pe, (int)px);
        if (!g_orig_abort)  g_orig_abort  = (FnAbort)dlsym(RTLD_DEFAULT, "abort");
        if (!g_orig__exit)  g_orig__exit  = (FnExit) dlsym(RTLD_DEFAULT, "_exit");
        if (!g_orig_exit)   g_orig_exit   = (FnExit) dlsym(RTLD_DEFAULT, "exit");
    } else {
        void *sym_abort = dlsym(RTLD_DEFAULT, "abort");
        void *sym__exit = dlsym(RTLD_DEFAULT, "_exit");
        void *sym_exit  = dlsym(RTLD_DEFAULT, "exit");
        LI("L58: no ano_base fallback abort=%p _exit=%p exit=%p", sym_abort, sym__exit, sym_exit);
        if (sym_abort && is_hookable_arm64(sym_abort))
            DobbyHook(sym_abort, (void*)hook_abort,  (void**)&g_orig_abort);
        if (sym__exit && is_hookable_arm64(sym__exit))
            DobbyHook(sym__exit, (void*)hook__exit,  (void**)&g_orig__exit);
        else LI("L58: _exit too short, skipping DobbyHook");
        if (sym_exit  && is_hookable_arm64(sym_exit))
            DobbyHook(sym_exit,  (void*)hook_exit,   (void**)&g_orig_exit);
    }
    LI("L58 done");

    // ── libanort.so belt-and-suspenders: GOT patch kill/tgkill/abort/_exit ───
    // libanort is the companion runtime library; it may also call kill/tgkill
    // via PLT (covered here) or raw SVC (covered by seccomp above).
    if (anort_base) {
        bool k0 = anogs_patch_got_import(anort_base, "kill",   (void*)hook_kill);
        bool t0 = anogs_patch_got_import(anort_base, "tgkill", (void*)hook_tgkill);
        bool a0 = anogs_patch_got_import(anort_base, "abort",  (void*)hook_abort);
        bool e0 = anogs_patch_got_import(anort_base, "_exit",  (void*)hook__exit);
        bool x0 = anogs_patch_got_import(anort_base, "exit",   (void*)hook_exit);
        LI("libanort GOT: kill=%d tgkill=%d abort=%d _exit=%d exit=%d",
           (int)k0, (int)t0, (int)a0, (int)e0, (int)x0);
    } else {
        LI("libanort.so not mapped — skipping GOT patches");
    }

    // ── Layer 59: sigaction / signal ─────────────────────────────────────────
    LI("L59 start");
    void *sym_sa = dlsym(RTLD_DEFAULT, "sigaction");
    void *sym_sg = dlsym(RTLD_DEFAULT, "signal");
    if (sym_sa && is_hookable_arm64(sym_sa))
        DobbyHook(sym_sa, (void*)hook_sigaction, (void**)&g_orig_sigaction);
    else LI("L59: sigaction not hookable sym=%p", sym_sa);
    if (sym_sg && is_hookable_arm64(sym_sg))
        DobbyHook(sym_sg, (void*)hook_signal, (void**)&g_orig_signal);
    else LI("L59: signal not hookable sym=%p", sym_sg);
    LI("L59 done");

    // ── Layer 60: opendir / fdopendir / readdir / closedir ───────────────────
    LI("L60 start");
    void *sym_od   = dlsym(RTLD_DEFAULT, "opendir");
    void *sym_fod  = dlsym(RTLD_DEFAULT, "fdopendir");
    void *sym_rd   = dlsym(RTLD_DEFAULT, "readdir");
    void *sym_rd64 = dlsym(RTLD_DEFAULT, "readdir64");
    void *sym_cd   = dlsym(RTLD_DEFAULT, "closedir");
    if (sym_od   && is_hookable_arm64(sym_od))
        DobbyHook(sym_od,   (void*)hook_opendir,   (void**)&g_orig_opendir);
    if (sym_fod  && is_hookable_arm64(sym_fod))
        DobbyHook(sym_fod,  (void*)hook_fdopendir, (void**)&g_orig_fdopendir);
    if (sym_rd   && is_hookable_arm64(sym_rd))
        DobbyHook(sym_rd,   (void*)hook_readdir,   (void**)&g_orig_readdir);
    if (sym_rd64 && is_hookable_arm64(sym_rd64))
        DobbyHook(sym_rd64, (void*)hook_readdir64, (void**)&g_orig_readdir64);
    if (sym_cd   && is_hookable_arm64(sym_cd))
        DobbyHook(sym_cd,   (void*)hook_closedir,  (void**)&g_orig_closedir);
    LI("L60 done");

    // ── Layer 61: chmod / fchmod / fchmodat ───────────────────────────────────
    LI("L61 start");
    void *sym_cmod    = dlsym(RTLD_DEFAULT, "chmod");
    void *sym_fcmod   = dlsym(RTLD_DEFAULT, "fchmod");
    void *sym_fcmodat = dlsym(RTLD_DEFAULT, "fchmodat");
    if (sym_cmod    && is_hookable_arm64(sym_cmod))
        DobbyHook(sym_cmod,    (void*)hook_chmod,    (void**)&g_orig_chmod);
    if (sym_fcmod   && is_hookable_arm64(sym_fcmod))
        DobbyHook(sym_fcmod,   (void*)hook_fchmod,   (void**)&g_orig_fchmod);
    if (sym_fcmodat && is_hookable_arm64(sym_fcmodat))
        DobbyHook(sym_fcmodat, (void*)hook_fchmodat, (void**)&g_orig_fchmodat);
    LI("L61 done");

    ensure_ranges7();

    LI("L54-61: all hooks installed");
}
