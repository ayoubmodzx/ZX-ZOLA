// dobby_impl.cpp — Minimal ARM64 inline hook, DobbyHook API compatible
// No external Dobby dependency needed — implements the subset used by ZX-ZOLA.

#include "dobby_stub.hpp"
// Zygisk module stubs — MemoryGuard handles hiding, no full anti_detect needed
static void zx_track_rwx_page(void*, size_t) {}
static void zx_register_scrub_target(void*) {}
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <cstring>
#include <cstdio>
#include <cstdint>
#include <cerrno>
#include <android/log.h>
#include <vector>
#include <mutex>

#define DTAG "ZX-HOOK"
#if defined(ZX_DEBUG_HOOK)
#define DI(...) __android_log_print(ANDROID_LOG_INFO,  DTAG, __VA_ARGS__)
#define DE(...) __android_log_print(ANDROID_LOG_ERROR, DTAG, __VA_ARGS__)
#else
#define DI(...) ((void)0)
#define DE(...) ((void)0)
#endif

// ── ARM64 16-byte absolute trampoline ─────────────────────────────────────────
// Layout (16 bytes total):
//   [0x00] 0x58000051  LDR X17, #8   — load 64-bit addr from PC+8
//   [0x04] 0xD61F0220  BR  X17       — branch to loaded address
//   [0x08] <8 bytes>   .quad target  — absolute 64-bit target address

static constexpr size_t TRAMP = 16;

static void write_jump(void *dst, const void *target) {
    uint32_t t[4];
    t[0] = 0x58000051u;
    t[1] = 0xD61F0220u;
    memcpy(&t[2], &target, 8);
    memcpy(dst, t, TRAMP);
    __builtin___clear_cache((char*)dst, (char*)dst + TRAMP);
}

static bool set_rwx(void *p, size_t n) {
    const size_t ps = (size_t)getpagesize();
    uintptr_t base = (uintptr_t)p & ~(ps - 1);
    size_t    sz   = (((uintptr_t)p + n + ps - 1) & ~(ps - 1)) - base;
    return mprotect((void*)base, sz, PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}

static bool has_pc_relative(const uint8_t *target) {
    for (int i = 0; i < 4; i++) {
        uint32_t insn;
        memcpy(&insn, target + i * 4, 4);
        if ((insn & 0x9F000000u) == 0x90000000u) return true;
        if ((insn & 0x9F000000u) == 0x10000000u) return true;
        if ((insn & 0x7C000000u) == 0x14000000u) return true;
        if ((insn & 0x3B000000u) == 0x18000000u) return true;
        if ((insn & 0x7E000000u) == 0x34000000u) return true;
        if ((insn & 0x7E000000u) == 0x36000000u) return true;
    }
    return false;
}

// ── Hook table ────────────────────────────────────────────────────────────────

struct Slot { void *target; uint8_t saved[TRAMP]; void *page; };
static std::vector<Slot> g_slots;
static std::mutex        g_mu;

int DobbyHook(void *addr, void *replace, void **origin) {
    if (!addr || !replace) return -1;
    std::lock_guard<std::mutex> lk(g_mu);

    // Dedup guard — re-hooking an already-hooked address corrupts the trampoline chain
    for (auto &s : g_slots)
        if (s.target == addr) return -1;

    if (has_pc_relative((const uint8_t*)addr)) {
        DE("DobbyHook: PC-relative instruction in first 16 bytes of %p — skipping", addr);
        return -1;
    }

    if (!set_rwx(addr, TRAMP)) {
        DE("mprotect RWX failed @ %p: %s", addr, strerror(errno));
        return -1;
    }

    Slot s{};
    s.target = addr;
    s.page   = nullptr;
    memcpy(s.saved, addr, TRAMP);

    if (origin) {
        *origin = nullptr;
        void *pg = mmap(nullptr, (size_t)getpagesize(),
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (pg != MAP_FAILED) {
            memcpy(pg, s.saved, TRAMP);
            write_jump((char*)pg + TRAMP, (char*)addr + TRAMP);
            __builtin___clear_cache((char*)pg, (char*)pg + TRAMP * 2);
            s.page  = pg;
            *origin = pg;
            zx_track_rwx_page(pg, (size_t)getpagesize());
            zx_register_scrub_target(pg);
        }
        // Abort if trampoline allocation failed — write_jump with null origin crashes
        if (!(*origin)) return -1;
    }

    write_jump(addr, replace);
    g_slots.push_back(s);
    return 0;
}

int DobbyDestroy(void *addr) {
    std::lock_guard<std::mutex> lk(g_mu);
    for (auto it = g_slots.begin(); it != g_slots.end(); ++it) {
        if (it->target != addr) continue;
        set_rwx(addr, TRAMP);
        memcpy(addr, it->saved, TRAMP);
        __builtin___clear_cache((char*)addr, (char*)addr + TRAMP);
        if (it->page) munmap(it->page, (size_t)getpagesize());
        g_slots.erase(it);
        return 0;
    }
    return -1;
}

// ── DobbySymbolResolver — ELF .symtab scan ────────────────────────────────────

struct PhdrQ { const char *name; uintptr_t base; const char *path; };

static int phdr_cb(dl_phdr_info *i, size_t, void *d) {
    auto *q = (PhdrQ*)d;
    if (!i->dlpi_name || !strstr(i->dlpi_name, q->name)) return 0;
    q->base = (uintptr_t)i->dlpi_addr;
    q->path = i->dlpi_name;
    return 1;
}

static void *elf_scan(const char *path, const char *sym, uintptr_t base) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return nullptr;

    struct stat st; fstat(fd, &st);
    const size_t fsz = (size_t)st.st_size;
    void *m = mmap(nullptr, fsz, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (m == MAP_FAILED) return nullptr;

    void *result = nullptr;
    auto *eh = (Elf64_Ehdr*)m;
    if (fsz < sizeof(Elf64_Ehdr) || memcmp(eh->e_ident, ELFMAG, 4) != 0) goto done;
    if (eh->e_shoff == 0 || eh->e_shnum == 0) goto done;

    {
        auto *sh  = (Elf64_Shdr*)((uint8_t*)m + eh->e_shoff);
        if ((uintptr_t)(sh + eh->e_shnum) > (uintptr_t)m + fsz) goto done;
        if (eh->e_shstrndx >= eh->e_shnum) goto done;

        for (uint16_t i = 0; i < eh->e_shnum && !result; i++) {
            if (sh[i].sh_type != SHT_SYMTAB && sh[i].sh_type != SHT_DYNSYM) continue;
            if (sh[i].sh_link >= eh->e_shnum) continue;

            auto *syms = (Elf64_Sym*)((uint8_t*)m + sh[i].sh_offset);
            int   cnt  = (int)(sh[i].sh_size / sizeof(Elf64_Sym));
            auto *sstr = (const char*)m + sh[sh[i].sh_link].sh_offset;

            for (int j = 0; j < cnt && !result; j++) {
                if (!syms[j].st_value) continue;
                char name[256];
                strncpy(name, sstr + syms[j].st_name, 255);
                name[255] = 0;
                char *at = strchr(name, '@');
                if (at) *at = 0;
                if (strcmp(name, sym) == 0)
                    result = (void*)(base + syms[j].st_value);
            }
        }
    }

done:
    munmap(m, fsz);
    return result;
}

void *DobbySymbolResolver(const char *lib, const char *sym) {
    void *h = dlopen(lib, RTLD_LAZY | RTLD_NOLOAD);
    if (!h) dlerror(); // consume RTLD_NOLOAD miss — prevents stale error in caller's dlerror buffer
    if (h) {
        void *a = dlsym(h, sym);
        if (a) return a;
        char buf[256]; snprintf(buf, sizeof(buf), "%s@@ANO", sym);
        a = dlsym(h, buf);
        if (a) return a;
    }

    // dl_iterate_phdr is the primary ELF scan path (namespace-aware on most Androids)
    PhdrQ q{lib, 0, nullptr};
    dl_iterate_phdr(phdr_cb, &q);
    if (q.base && q.path) {
        void *a = elf_scan(q.path, sym, q.base);
        if (a) { DI("resolved %s::%s @ %p", lib, sym, a); return a; }
    }

    // Namespace bypass: dl_iterate_phdr only sees the current linker namespace on some
    // Android versions.  /proc/self/maps shows ALL mapped segments regardless of namespace.
    // Parse it to get base + path, then run elf_scan from there.
    {
        uintptr_t maps_base = 0;
        unsigned long long maps_off = 0;
        char maps_path[512] = {};
        FILE *mf = fopen("/proc/self/maps", "r");
        if (mf) {
            char line[512];
            while (fgets(line, sizeof(line), mf)) {
                if (!strstr(line, lib)) continue;
                if (!strstr(line, "r--p") && !strstr(line, "r-xp")) continue;
                char perm[8] = {}, dev[16] = {};
                int ino = 0;
                sscanf(line, "%lx-%*lx %4s %llx %15s %d %511[^\n]",
                       &maps_base, perm, &maps_off, dev, &ino, maps_path);
                // Trim trailing whitespace
                int plen = (int)strlen(maps_path);
                while (plen > 0 && (maps_path[plen-1] == '\n' || maps_path[plen-1] == ' '))
                    maps_path[--plen] = '\0';
                break;
            }
            fclose(mf);
        }
        if (maps_base && maps_path[0] && maps_path[0] != '[') {
            // For APK-inline libs maps_off is the byte offset into the APK file.
            // elf_scan opens the file and mmaps from offset 0, so we compensate
            // by subtracting maps_off from the symbols' st_value-based addresses
            // only when maps_off != 0; simplest: open, seek, re-scan.
            if (maps_off == 0) {
                void *a = elf_scan(maps_path, sym, maps_base);
                if (a) { DI("resolved %s::%s @ %p (maps)", lib, sym, a); return a; }
            } else {
                // APK-inline: open file, mmap from maps_off, scan
                int fd2 = open(maps_path, O_RDONLY);
                if (fd2 >= 0) {
                    struct stat st2; fstat(fd2, &st2);
                    size_t sz2 = (size_t)((off_t)st2.st_size > (off_t)maps_off
                                          ? st2.st_size - (size_t)maps_off : 0);
                    if (sz2 > 0) {
                        void *m2 = mmap(nullptr, sz2, PROT_READ, MAP_PRIVATE, fd2, (off_t)maps_off);
                        if (m2 != MAP_FAILED) {
                            // Re-use elf_scan logic inline on the mmap'd buffer
                            void *res = nullptr;
                            auto *eh2 = (Elf64_Ehdr*)m2;
                            if (sz2 >= sizeof(Elf64_Ehdr) && memcmp(eh2->e_ident, ELFMAG, 4) == 0
                                && eh2->e_shoff && eh2->e_shnum) {
                                auto *sh2 = (Elf64_Shdr*)((uint8_t*)m2 + eh2->e_shoff);
                                if ((uintptr_t)(sh2 + eh2->e_shnum) <= (uintptr_t)m2 + sz2
                                    && eh2->e_shstrndx < eh2->e_shnum) {
                                    for (uint16_t ii = 0; ii < eh2->e_shnum && !res; ii++) {
                                        if (sh2[ii].sh_type != SHT_SYMTAB &&
                                            sh2[ii].sh_type != SHT_DYNSYM) continue;
                                        if (sh2[ii].sh_link >= eh2->e_shnum) continue;
                                        auto *s2 = (Elf64_Sym*)((uint8_t*)m2 + sh2[ii].sh_offset);
                                        int c2 = (int)(sh2[ii].sh_size / sizeof(Elf64_Sym));
                                        auto *ss2 = (const char*)m2 + sh2[sh2[ii].sh_link].sh_offset;
                                        for (int j2 = 0; j2 < c2 && !res; j2++) {
                                            if (!s2[j2].st_value) continue;
                                            char nm[256];
                                            strncpy(nm, ss2 + s2[j2].st_name, 255);
                                            nm[255] = 0;
                                            char *at2 = strchr(nm, '@'); if (at2) *at2 = 0;
                                            if (strcmp(nm, sym) == 0)
                                                res = (void*)(maps_base + s2[j2].st_value);
                                        }
                                    }
                                }
                            }
                            munmap(m2, sz2);
                            if (res) { DI("resolved %s::%s @ %p (apk)", lib, sym, res); return res; }
                        }
                    }
                    close(fd2);
                }
            }
        }
    }

    DE("DobbySymbolResolver: '%s' not found in '%s'", sym, lib);
    return nullptr;
}
