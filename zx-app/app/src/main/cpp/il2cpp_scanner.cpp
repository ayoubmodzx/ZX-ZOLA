#include "il2cpp_scanner.hpp"
#include "dobby_stub.hpp"
#include <dlfcn.h>
#include <cstring>
#include <android/log.h>
#include <unordered_map>
#include <string>
#include <pthread.h>
#include <link.h>
#include <cstdint>
#include <atomic>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#define TAG "ZX-IL2"
#ifndef ZX_RELEASE
#define LOG(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define ERR(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#else
#define LOG(...) ((void)0)
#define ERR(...) ((void)0)
#endif

// ── il2cpp function pointer table ────────────────────────────────────────────

using FnVoidPtr   = void*(*)();
using FnDomainGet = Il2CppDomain*(*)();

static Il2CppDomain* (*p_domain_get)()                                           = nullptr;
static const Il2CppAssembly** (*p_domain_assemblies)(Il2CppDomain*, size_t*)     = nullptr;
static Il2CppImage* (*p_asm_image)(const Il2CppAssembly*)                        = nullptr;
static const char*  (*p_image_name)(Il2CppImage*)                                = nullptr;
static uint32_t     (*p_image_class_count)(Il2CppImage*)                         = nullptr;
static Il2CppClass* (*p_image_get_class)(Il2CppImage*, uint32_t)                 = nullptr;
static Il2CppClass* (*p_class_from_name)(Il2CppImage*, const char*, const char*) = nullptr;
static const char*  (*p_class_get_name)(Il2CppClass*)                            = nullptr;
static const char*  (*p_class_get_ns)(Il2CppClass*)                              = nullptr;
static FieldInfo*   (*p_field_from_name)(Il2CppClass*, const char*)              = nullptr;
static FieldInfo*   (*p_class_fields)(Il2CppClass*, void**)                      = nullptr;  // iterator
static const char*  (*p_field_name)(FieldInfo*)                                   = nullptr;
static void*        (*p_field_type)(FieldInfo*)                                   = nullptr;
static int32_t      (*p_field_offset)(FieldInfo*)                                 = nullptr;
static MethodInfo*  (*p_method_from_name)(Il2CppClass*, const char*, int)        = nullptr;
static void         (*p_field_static_set)(FieldInfo*, void*)                     = nullptr;
static void         (*p_field_static_get)(FieldInfo*, void*)                     = nullptr;
static uint32_t     (*p_class_num_fields)(Il2CppClass*)                          = nullptr;
// For FindObjectOfType
static Il2CppClass*  (*p_unity_obj_class)(Il2CppImage*, const char*, const char*) = nullptr;
static Il2CppObject* (*p_runtime_invoke)(MethodInfo*, Il2CppObject*, void**, void**) = nullptr;
static Il2CppObject* (*p_object_new)(Il2CppClass*)                               = nullptr;
static void*         (*p_class_get_type)(Il2CppClass*)                           = nullptr;
static Il2CppObject* (*p_type_get_object)(void*)                                 = nullptr;
static Il2CppObject* (*p_string_new_utf8)(const char*)                           = nullptr;

static Il2CppImage *g_img    = nullptr;
static Il2CppImage *g_unity  = nullptr;  // UnityEngine.CoreModule
static std::unordered_map<std::string, Il2CppClass*> g_cls_cache;
static pthread_mutex_t g_cls_mu = PTHREAD_MUTEX_INITIALIZER;

// ── bind macros ───────────────────────────────────────────────────────────────
#define BIND(ptr, sym) \
    if (!(ptr)) (ptr) = (__typeof__(ptr))dlsym(h, (sym)); \
    if (!(ptr)) (ptr) = (__typeof__(ptr))DobbySymbolResolver("libil2cpp.so", (sym)); \
    if (!(ptr)) { ERR("stripped: %s", (sym)); }

#define BIND_OPT(ptr, sym) \
    if (!(ptr)) (ptr) = (__typeof__(ptr))dlsym(h, (sym)); \
    if (!(ptr)) (ptr) = (__typeof__(ptr))DobbySymbolResolver("libil2cpp.so", (sym));

// ── Approach 3: dlsym hook (captures il2cpp resolutions made after injection) ─

typedef void* (*dlsym_fn_t)(void*, const char*);
static dlsym_fn_t s_orig_dlsym    = nullptr;
static std::atomic<bool> s_init_complete{false};

struct DlsymBind { const char *sym; void **dest; };
static DlsymBind s_dlsym_tab[] = {
    { "il2cpp_domain_get",                    (void**)&p_domain_get          },
    { "il2cpp_domain_get_assemblies",          (void**)&p_domain_assemblies   },
    { "il2cpp_assembly_get_image",             (void**)&p_asm_image           },
    { "il2cpp_image_get_name",                 (void**)&p_image_name          },
    { "il2cpp_image_get_class_count",          (void**)&p_image_class_count   },
    { "il2cpp_image_get_class",                (void**)&p_image_get_class     },
    { "il2cpp_class_from_name",                (void**)&p_class_from_name     },
    { "il2cpp_class_get_name",                 (void**)&p_class_get_name      },
    { "il2cpp_class_get_namespace",            (void**)&p_class_get_ns        },
    { "il2cpp_class_get_field_from_name",      (void**)&p_field_from_name     },
    { "il2cpp_class_get_fields",               (void**)&p_class_fields        },
    { "il2cpp_field_get_name",                 (void**)&p_field_name          },
    { "il2cpp_field_get_type",                 (void**)&p_field_type          },
    { "il2cpp_field_get_offset",               (void**)&p_field_offset        },
    { "il2cpp_class_get_method_from_name",     (void**)&p_method_from_name    },
    { "il2cpp_field_static_set_value",         (void**)&p_field_static_set    },
    { "il2cpp_field_static_get_value",         (void**)&p_field_static_get    },
    { "il2cpp_class_num_fields",               (void**)&p_class_num_fields    },
    { "il2cpp_runtime_invoke",                 (void**)&p_runtime_invoke      },
    { "il2cpp_object_new",                     (void**)&p_object_new          },
    { "il2cpp_class_get_type",                 (void**)&p_class_get_type      },
    { "il2cpp_type_get_object",                (void**)&p_type_get_object     },
    { "il2cpp_string_new",                     (void**)&p_string_new_utf8     },
    { nullptr,                                  nullptr                        }
};

static void apply_dlsym_capture(const char *symbol, void *result) {
    if (!symbol || !result) return;
    for (int i = 0; s_dlsym_tab[i].sym; i++) {
        if (strcmp(symbol, s_dlsym_tab[i].sym) == 0) {
            void **dest = s_dlsym_tab[i].dest;
            if (!*dest) {
                *dest = result;
                LOG("dlsym-captured: %s @ %p", symbol, result);
            }
            return;
        }
    }
}

static void* hook_dlsym_il2cpp(void *handle, const char *symbol) {
    void *result = s_orig_dlsym(handle, symbol);
    if (result && symbol && strncmp(symbol, "il2cpp_", 7) == 0)
        apply_dlsym_capture(symbol, result);
    return result;
}

static void install_dlsym_hook() {
    if (s_orig_dlsym) return;
    void *fn = DobbySymbolResolver("libc.so", "dlsym");
    if (!fn) fn = (void*)&dlsym;
    if (fn) {
        DobbyHook(fn, (void*)hook_dlsym_il2cpp, (void**)&s_orig_dlsym);
        LOG("dlsym hook installed — watching for il2cpp resolutions");
    }
}

// ── Approach 4: scan libmain.so data section for already-resolved il2cpp ptrs ─
//
// libmain.so (6.6 KB) calls dlopen("libil2cpp.so") + dlsym at startup and stores
// the resolved function pointers in its .data section. We scan those pages for
// values that fall within libil2cpp.so's load range and identify each one.
//
// Identification by ARM64 prologue pattern (at the pointed-to address):
//   3-insn  ADRP+LDR+RET          → il2cpp_domain_get (only 3-insn il2cpp fn)
//   4-insn  ADRP+LDR+CBZ+RET      → il2cpp_domain_get_assemblies (or similar accessor)
//   STP x29,x30 at start           → function with frame — larger API function
//   Multiple STP + ADRP calls      → scanning / enumeration functions

struct LibRange { uintptr_t base, end; };

static int phdr_collect(dl_phdr_info *info, size_t, void *data) {
    const char *want = (const char*)data;
    if (!info->dlpi_name || !strstr(info->dlpi_name, want)) return 0;
    LibRange *r = new LibRange();
    r->base = (uintptr_t)info->dlpi_addr;
    r->end  = r->base;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) &ph = info->dlpi_phdr[i];
        if (ph.p_type == PT_LOAD) {
            uintptr_t se = r->base + ph.p_vaddr + ph.p_memsz;
            if (se > r->end) r->end = se;
        }
    }
    // store result pointer in data slot (hack: reuse pointer field)
    *(LibRange**)data = r; // caller must cast correctly
    return 1;
}

// Count ARM64 instructions until RET (max 64 insns)
static int arm64_fn_size(const uint32_t *code, size_t max_insns) {
    for (size_t i = 0; i < max_insns; i++) {
        if (code[i] == 0xD65F03C0) return (int)(i + 1); // RET
    }
    return (int)max_insns;
}

// Returns true if function at addr looks like il2cpp_domain_get:
//   ADRP Xn, #page | LDR Xn,[Xn,#off] | RET  (exactly 3 instructions)
static bool is_domain_get_pattern(const uint32_t *code) {
    if ((code[0] & 0x9F000000) != 0x90000000) return false; // ADRP
    if ((code[1] & 0xFFC00000) != 0xF9400000) return false; // LDR 64-bit
    return code[2] == 0xD65F03C0;                            // RET
}

// Returns true if function looks like il2cpp_domain_get_assemblies:
//   ADRP | LDR | CBZ/CBNZ | ... | STR/STP | RET  (4-10 insns, takes a size_t* arg)
static bool is_domain_assemblies_pattern(const uint32_t *code, int fn_size) {
    if (fn_size < 4 || fn_size > 20) return false;
    if ((code[0] & 0x9F000000) != 0x90000000) return false; // ADRP
    if ((code[1] & 0xFFC00000) != 0xF9400000) return false; // LDR
    // third insn: CBZ x0/x1 (null check on domain)
    return ((code[2] & 0x7F000000) == 0x34000000);
}

// Returns true if function has STP x29,x30,[sp,#N] frame setup (larger function).
// Bits[14:0]: Rt2(14:10)=x30=11110, Rn(9:5)=sp=11111, Rt(4:0)=x29=11101 → 0x7BFD
// Bits[31:30]: 10 = 64-bit STP; bit[26]=0 (integer, not SIMD)
static bool has_frame_setup(const uint32_t *code) {
    return (code[0] & 0xC0007FFF) == 0x80007BFD;
}

static void scan_libmain_for_il2cpp_ptrs() {
    // 1. Find libil2cpp.so range
    uintptr_t il2base = 0, il2end = 0;
    auto find_lib = [](const char *libname, uintptr_t &base, uintptr_t &end) {
        struct Ctx { const char *name; uintptr_t base, end; };
        Ctx ctx = { libname, 0, 0 };
        dl_iterate_phdr([](dl_phdr_info *info, size_t, void *d) -> int {
            Ctx *c = (Ctx*)d;
            if (!info->dlpi_name || !strstr(info->dlpi_name, c->name)) return 0;
            c->base = (uintptr_t)info->dlpi_addr;
            c->end  = c->base;
            for (int i = 0; i < info->dlpi_phnum; i++) {
                const ElfW(Phdr) &ph = info->dlpi_phdr[i];
                if (ph.p_type == PT_LOAD) {
                    uintptr_t se = c->base + ph.p_vaddr + ph.p_memsz;
                    if (se > c->end) c->end = se;
                }
            }
            return 1;
        }, &ctx);
        base = ctx.base; end = ctx.end;
    };

    find_lib("libil2cpp.so", il2base, il2end);
    if (!il2base) { ERR("libil2cpp.so not mapped yet"); return; }
    LOG("libil2cpp range: %p – %p (%.1f MB)", (void*)il2base, (void*)il2end,
        (double)(il2end - il2base) / (1024.0*1024.0));

    // 2. Find libmain.so RW data pages
    struct MainCtx {
        uintptr_t rw_start, rw_size;
        uintptr_t il2base, il2end;
        int        found;
    };
    MainCtx mctx = { 0, 0, il2base, il2end, 0 };

    dl_iterate_phdr([](dl_phdr_info *info, size_t, void *d) -> int {
        if (!info->dlpi_name || !strstr(info->dlpi_name, "libmain.so")) return 0;
        MainCtx *c = (MainCtx*)d;
        uintptr_t base = (uintptr_t)info->dlpi_addr;
        for (int i = 0; i < info->dlpi_phnum; i++) {
            const ElfW(Phdr) &ph = info->dlpi_phdr[i];
            if (ph.p_type != PT_LOAD) continue;
            if (!(ph.p_flags & PF_W)) continue; // RW only
            c->rw_start = base + ph.p_vaddr;
            c->rw_size  = ph.p_memsz;
            c->found    = 1;
        }
        return 1;
    }, &mctx);

    if (!mctx.rw_start || !mctx.found) { ERR("libmain.so data not found"); return; }
    LOG("libmain.so RW @ %p sz=%zu", (void*)mctx.rw_start, (size_t)mctx.rw_size);

    // 3. Scan for pointers into libil2cpp.so
    const uintptr_t *data = (const uintptr_t*)mctx.rw_start;
    size_t count = mctx.rw_size / sizeof(uintptr_t);
    int matched = 0;

    for (size_t i = 0; i < count; i++) {
        uintptr_t ptr = data[i];
        if (ptr < il2base || ptr >= il2end) continue;
        // ptr is a pointer into libil2cpp.so — try to identify it
        const uint32_t *code = (const uint32_t*)ptr;

        // Sanity: must be 4-byte aligned and in an executable region
        if (ptr & 3) continue;

        int fsz = arm64_fn_size(code, 64);

        if (fsz == 3 && is_domain_get_pattern(code)) {
            if (!p_domain_get) {
                p_domain_get = (Il2CppDomain*(*)())ptr;
                LOG("libmain-scan: il2cpp_domain_get @ %p", (void*)ptr);
                matched++;
            }
        } else if (fsz >= 4 && fsz <= 20 && is_domain_assemblies_pattern(code, fsz)) {
            if (!p_domain_assemblies) {
                p_domain_assemblies = (const Il2CppAssembly**(*)(Il2CppDomain*,size_t*))ptr;
                LOG("libmain-scan: il2cpp_domain_get_assemblies @ %p (candidate)", (void*)ptr);
                matched++;
            }
        } else if (has_frame_setup(code)) {
            // Larger function — log for manual mapping, don't blindly assign
            LOG("libmain-scan: il2cpp ptr with frame @ %p sz=%d insns", (void*)ptr, fsz);
        }
    }
    LOG("libmain-scan: %d il2cpp ptrs found in libmain.so data", matched);
}

// ── Approach 5: ARM64 pattern scan of libil2cpp.so text ──────────────────────
//
// Directly scan libil2cpp.so's executable segments for the il2cpp_domain_get
// pattern: ADRP Xn,# + LDR Xn,[Xn,#] + RET — a 3-instruction function.
// There are typically only 1-3 such functions in the entire il2cpp text, so
// false-positive rate is low.

static void scan_il2cpp_text_for_domain_get(uintptr_t text_base, size_t text_size) {
    if (p_domain_get) return;
    if (!text_base || text_size < 12) return;

    const uint32_t *insns = (const uint32_t*)text_base;
    size_t count = text_size / 4;
    int candidates = 0;
    uintptr_t last_candidate = 0;

    for (size_t i = 0; i + 2 < count; i++) {
        if (!is_domain_get_pattern(&insns[i])) continue;
        uintptr_t fn_addr = text_base + i * 4;

        // Decode ADRP: compute page address
        uint32_t adrp = insns[i];
        uint64_t immhi = (adrp >> 5)  & 0x7FFFFULL;
        uint64_t immlo = (adrp >> 29) & 0x3ULL;
        int64_t  imm21 = (int64_t)((immhi << 2) | immlo);
        if (imm21 & (1LL << 20)) imm21 -= (1LL << 21);
        uintptr_t page = (fn_addr & ~(uintptr_t)0xFFF) + (uintptr_t)((int64_t)imm21 << 12);

        // Decode LDR offset (unsigned scaled by 8 for 64-bit)
        uint32_t ldr = insns[i+1];
        uint32_t ldr_imm12 = (ldr >> 10) & 0xFFF;
        uintptr_t target = page + ldr_imm12 * 8;

        // Sanity: target must be readable writable data (could be .bss or .data)
        // Just check it's not in executable range and not obviously wild
        if (target == 0 || (target & 7)) continue;

        candidates++;
        last_candidate = fn_addr;
        LOG("text-scan: domain_get candidate @ %p → target %p", (void*)fn_addr, (void*)target);
    }

    if (candidates == 1 && last_candidate) {
        p_domain_get = (Il2CppDomain*(*)())last_candidate;
        LOG("text-scan: il2cpp_domain_get confirmed @ %p (sole candidate)", (void*)last_candidate);
    } else if (candidates > 1) {
        LOG("text-scan: %d domain_get candidates — need disambiguation", candidates);
    }
}

static void run_all_pattern_scans() {
    // Walk libil2cpp.so LOAD segments
    struct ScanCtx { int done; };
    ScanCtx sctx = {0};
    dl_iterate_phdr([](dl_phdr_info *info, size_t, void *d) -> int {
        if (!info->dlpi_name || !strstr(info->dlpi_name, "libil2cpp.so")) return 0;
        ScanCtx *sc = (ScanCtx*)d;
        uintptr_t base = (uintptr_t)info->dlpi_addr;
        for (int i = 0; i < info->dlpi_phnum; i++) {
            const ElfW(Phdr) &ph = info->dlpi_phdr[i];
            if (ph.p_type != PT_LOAD) continue;
            if (!(ph.p_flags & PF_X)) continue; // executable segments only
            uintptr_t seg_base = base + ph.p_vaddr;
            scan_il2cpp_text_for_domain_get(seg_base, ph.p_filesz);
        }
        sc->done = 1;
        return 1;
    }, &sctx);
    if (!sctx.done) ERR("text-scan: libil2cpp.so not mapped yet");
}

// ── Approach 6: retry thread ──────────────────────────────────────────────────
// If all pointer-resolution attempts fail (e.g. injected before il2cpp init),
// this thread retries Il2Cpp::init() every 200ms for up to 15 seconds.

static void *il2cpp_retry_thread(void *) {
    for (int attempt = 0; attempt < 75; attempt++) {
        usleep(200000); // 200ms
        if (s_init_complete.load(std::memory_order_acquire)) break;

        // Re-run scans and check for domain_get
        run_all_pattern_scans();
        scan_libmain_for_il2cpp_ptrs();

        if (!p_domain_get) continue;

        // Try to complete initialization
        LOG("retry[%d]: p_domain_get now @ %p — completing init", attempt, (void*)p_domain_get);
        Il2Cpp::init();
        if (g_img) {
            LOG("retry[%d]: Assembly-CSharp resolved — features now active", attempt);
            s_init_complete.store(true, std::memory_order_release);
            break;
        }
    }
    return nullptr;
}

// ── init ─────────────────────────────────────────────────────────────────────

bool Il2Cpp::init() {
    // Already fully resolved — skip rediscovery
    if (g_img) { s_init_complete.store(true, std::memory_order_release); return true; }

    void *h = dlopen("libil2cpp.so", RTLD_LAZY | RTLD_GLOBAL | RTLD_NOLOAD);
    if (!h) h = dlopen("libil2cpp.so", RTLD_LAZY | RTLD_GLOBAL);
    if (!h) { ERR("libil2cpp.so not found"); return false; }

    // ── Tier 1: dlsym + DobbySymbolResolver ────────────────────────────────
    BIND(p_domain_get,        "il2cpp_domain_get")
    BIND(p_domain_assemblies, "il2cpp_domain_get_assemblies")
    BIND(p_asm_image,         "il2cpp_assembly_get_image")
    BIND(p_image_name,        "il2cpp_image_get_name")
    BIND(p_image_class_count, "il2cpp_image_get_class_count")
    BIND(p_image_get_class,   "il2cpp_image_get_class")
    BIND(p_class_from_name,   "il2cpp_class_from_name")
    BIND(p_class_get_name,    "il2cpp_class_get_name")
    BIND(p_class_get_ns,      "il2cpp_class_get_namespace")
    BIND(p_field_from_name,   "il2cpp_class_get_field_from_name")
    BIND(p_class_fields,      "il2cpp_class_get_fields")
    BIND(p_field_name,        "il2cpp_field_get_name")
    BIND(p_field_type,        "il2cpp_field_get_type")
    BIND(p_field_offset,      "il2cpp_field_get_offset")
    BIND(p_method_from_name,  "il2cpp_class_get_method_from_name")
    BIND(p_field_static_set,  "il2cpp_field_static_set_value")
    BIND(p_field_static_get,  "il2cpp_field_static_get_value")
    BIND(p_class_num_fields,  "il2cpp_class_num_fields")
    BIND(p_runtime_invoke,    "il2cpp_runtime_invoke")
    BIND_OPT(p_object_new,       "il2cpp_object_new")
    BIND_OPT(p_class_get_type,   "il2cpp_class_get_type")
    BIND_OPT(p_type_get_object,  "il2cpp_type_get_object")
    BIND_OPT(p_string_new_utf8,  "il2cpp_string_new")

    // ── Tier 2: hook dlsym so any future resolutions are captured ──────────
    install_dlsym_hook();

    // ── Tier 3: scan libmain.so data section for already-stored il2cpp ptrs ─
    if (!p_domain_get) scan_libmain_for_il2cpp_ptrs();

    // ── Tier 4: ARM64 pattern scan of libil2cpp.so text ────────────────────
    if (!p_domain_get) run_all_pattern_scans();

    if (!p_domain_get || !p_domain_assemblies || !p_asm_image) {
        ERR("il2cpp symbols stripped — spawning retry thread (Tier 5)");
        // Spawn retry thread — will keep trying until il2cpp initializes
        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&tid, &attr, il2cpp_retry_thread, nullptr);
        pthread_attr_destroy(&attr);
        return true; // degraded but alive
    }

    // ── Resolve domain → assemblies → images ───────────────────────────────
    Il2CppDomain *dom = p_domain_get();
    if (!dom) {
        ERR("il2cpp domain not ready — retry thread will resolve");
        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&tid, &attr, il2cpp_retry_thread, nullptr);
        pthread_attr_destroy(&attr);
        return true;
    }

    size_t n = 0;
    const Il2CppAssembly **asms = p_domain_assemblies(dom, &n);
    if (!asms || n == 0) {
        ERR("no assemblies yet — retry thread will resolve");
        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&tid, &attr, il2cpp_retry_thread, nullptr);
        pthread_attr_destroy(&attr);
        return true;
    }

    for (size_t i = 0; i < n; i++) {
        if (!asms[i]) continue;
        Il2CppImage *img = p_asm_image(asms[i]);
        if (!img) continue;
        const char *nm = p_image_name ? p_image_name(img) : nullptr;
        if (!nm) continue;
        if (!g_img   && strstr(nm, "Assembly-CSharp.dll"))       g_img   = img;
        if (!g_unity && strstr(nm, "UnityEngine.CoreModule.dll")) g_unity = img;
        if (g_img && g_unity) break;
    }
    if (!g_img) {
        ERR("Assembly-CSharp not found (n=%zu) — retry thread active", n);
        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&tid, &attr, il2cpp_retry_thread, nullptr);
        pthread_attr_destroy(&attr);
        return true;
    }

    LOG("Assembly-CSharp: %p  (%u classes)", g_img,
        p_image_class_count ? p_image_class_count(g_img) : 0);
    s_init_complete.store(true, std::memory_order_release);
    return true;
}

// ── class/field/method lookup ─────────────────────────────────────────────────

Il2CppImage *Il2Cpp::mainImage() { return g_img; }

Il2CppClass *Il2Cpp::cls(const char *name, const char *ns) {
    if (!ns) ns = "";
    std::string key = std::string(ns) + "::" + name;

    pthread_mutex_lock(&g_cls_mu);
    auto it = g_cls_cache.find(key);
    if (it != g_cls_cache.end()) {
        Il2CppClass *cached = it->second;
        pthread_mutex_unlock(&g_cls_mu);
        return cached;
    }
    pthread_mutex_unlock(&g_cls_mu);

    if (!g_img || !p_class_from_name) return nullptr;
    Il2CppClass *c = p_class_from_name(g_img, ns, name);
    if (!c && g_unity) c = p_class_from_name(g_unity, ns, name);

    if (c) {
        pthread_mutex_lock(&g_cls_mu);
        g_cls_cache[key] = c;
        pthread_mutex_unlock(&g_cls_mu);
    } else {
        ERR("class not found: %s::%s", ns, name);
    }
    return c;
}

void Il2Cpp::enumClasses(std::function<bool(Il2CppClass*)> cb) {
    if (!g_img || !p_image_class_count || !p_image_get_class) return;
    uint32_t cnt = p_image_class_count(g_img);
    for (uint32_t i = 0; i < cnt; i++) {
        Il2CppClass *c = p_image_get_class(g_img, i);
        if (c && cb(c)) return;
    }
}

FieldInfo *Il2Cpp::getField(Il2CppClass *klass, const char *name) {
    if (!klass || !p_field_from_name) return nullptr;
    return p_field_from_name(klass, name);
}

MethodInfo *Il2Cpp::getMethod(Il2CppClass *klass, const char *name, int params) {
    if (!klass || !p_method_from_name) return nullptr;
    return p_method_from_name(klass, name, params);
}

void Il2Cpp::staticGet(FieldInfo *f, void *out) {
    if (f && p_field_static_get) p_field_static_get(f, out);
}
void Il2Cpp::staticSet(FieldInfo *f, void *in) {
    if (f && p_field_static_set) p_field_static_set(f, in);
}

const char *Il2Cpp::className(Il2CppClass *c)  { return c && p_class_get_name ? p_class_get_name(c)  : "?"; }
const char *Il2Cpp::fieldName (FieldInfo   *f)  { return f && p_field_name     ? p_field_name(f)      : "?"; }
int32_t     Il2Cpp::fieldOffset(FieldInfo  *f)  { return f && p_field_offset   ? p_field_offset(f)    : -1; }
uint32_t    Il2Cpp::classFieldCount(Il2CppClass *c) {
    return c && p_class_num_fields ? p_class_num_fields(c) : 0;
}

uint8_t Il2Cpp::fieldTypeId(FieldInfo *f) {
    if (!f || !p_field_type) return 0;
    auto *t = reinterpret_cast<Il2CppType*>(p_field_type(f));
    return t ? t->type : 0;
}

// ── FindObjectOfType shim ─────────────────────────────────────────────────────

Il2CppObject *Il2Cpp::findObject(Il2CppClass *klass) {
    if (!klass || !g_unity || !p_class_from_name || !p_method_from_name || !p_runtime_invoke)
        return nullptr;

    static Il2CppClass  *s_objCls = nullptr;
    static MethodInfo   *s_findFn = nullptr;

    if (!s_objCls) {
        s_objCls = p_class_from_name(g_unity, "UnityEngine", "Object");
    }
    if (!s_objCls) return nullptr;
    if (!s_findFn) {
        s_findFn = p_method_from_name(s_objCls, "FindObjectOfType", 0);
    }
    if (!s_findFn) return nullptr;

    (void)klass;
    return nullptr;
}

Il2CppObject *Il2Cpp::invoke0(MethodInfo *m, Il2CppObject *obj) {
    if (!m || !p_runtime_invoke) return nullptr;
    void *exc = nullptr;
    Il2CppObject *result = p_runtime_invoke(m, obj, nullptr, &exc);
    if (exc) { ERR("invoke0 exception on %s", m->name ? m->name : "?"); return nullptr; }
    return result;
}

Il2CppObject *Il2Cpp::invoke1(MethodInfo *m, Il2CppObject *obj, void *arg0) {
    if (!m || !p_runtime_invoke) return nullptr;
    void *exc = nullptr;
    void *params[1] = { arg0 };
    Il2CppObject *result = p_runtime_invoke(m, obj, params, &exc);
    if (exc) { ERR("invoke1 exception on %s", m->name ? m->name : "?"); return nullptr; }
    return result;
}

Il2CppObject *Il2Cpp::newString(const char *str) {
    if (!str || !p_string_new_utf8) return nullptr;
    return p_string_new_utf8(str);
}

bool Il2Cpp::getFieldBool(Il2CppObject *obj, FieldInfo *field) {
    if (!obj || !field) return false;
    int32_t off = fieldOffset(field);
    if (off <= 0) return false;
    return readField<bool>(obj, off);
}

void Il2Cpp::findObjectsOfType(Il2CppClass *klass, Il2CppObject ***arr, int *count) {
    *arr   = nullptr;
    *count = 0;
    if (!klass || !g_unity || !p_class_from_name || !p_runtime_invoke) return;
    if (!p_class_get_type || !p_type_get_object) return;

    static Il2CppClass *s_objCls = nullptr;
    static MethodInfo  *s_findFn = nullptr;
    if (!s_objCls) s_objCls = p_class_from_name(g_unity, "UnityEngine", "Object");
    if (!s_objCls) return;
    if (!s_findFn) s_findFn = p_method_from_name(s_objCls, "FindObjectsOfType", 1);
    if (!s_findFn) return;

    void         *type    = p_class_get_type(klass);
    if (!type) return;
    Il2CppObject *typeObj = p_type_get_object(type);
    if (!typeObj) return;

    void         *exc       = nullptr;
    void         *params[1] = { typeObj };
    Il2CppObject *res       = p_runtime_invoke(s_findFn, nullptr, params, &exc);
    if (exc || !res) return;

    struct Array {
        Il2CppObject hdr;
        void        *bounds;
        uintptr_t    max_length;
    };
    auto *a = reinterpret_cast<Array*>(res);
    int   n = (int)a->max_length;
    if (n <= 0) return;

    Il2CppObject **out = (Il2CppObject**)malloc(sizeof(Il2CppObject*) * (size_t)n);
    if (!out) return;
    auto *raw = reinterpret_cast<Il2CppObject**>(a + 1);
    for (int i = 0; i < n; i++) out[i] = raw[i];

    *arr   = out;
    *count = n;
}

Il2CppObject *Il2Cpp::getLocalInstance(Il2CppClass *klass) {
    Il2CppObject **arr   = nullptr;
    int            count = 0;
    findObjectsOfType(klass, &arr, &count);
    if (!arr) return nullptr;

    Il2CppObject *result = nullptr;
    FieldInfo    *localF = getField(klass, "IsLocalPlayer");
    for (int i = 0; i < count; i++) {
        if (!arr[i]) continue;
        if (localF) {
            if (getFieldBool(arr[i], localF)) { result = arr[i]; break; }
        } else {
            result = arr[i];
            break;
        }
    }
    free(arr);
    return result;
}
