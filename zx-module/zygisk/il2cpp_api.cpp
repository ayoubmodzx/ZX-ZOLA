#include "il2cpp_api.hpp"
#include <android/log.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <elf.h>

#define TAG "ZX-IL2CPP"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Cached function pointers — resolved once via ELF parsing, no dlopen needed
il2cpp_domain_get_t                  il2cpp_domain_get                  = nullptr;
il2cpp_domain_get_assemblies_t       il2cpp_domain_get_assemblies       = nullptr;
il2cpp_assembly_get_image_t          il2cpp_assembly_get_image          = nullptr;
il2cpp_image_get_name_t              il2cpp_image_get_name              = nullptr;
il2cpp_class_from_name_t             il2cpp_class_from_name             = nullptr;
il2cpp_class_get_method_from_name_t  il2cpp_class_get_method_from_name  = nullptr;
il2cpp_class_get_field_from_name_t   il2cpp_class_get_field_from_name   = nullptr;
il2cpp_field_get_offset_t            il2cpp_field_get_offset            = nullptr;
il2cpp_field_static_get_value_t      il2cpp_field_static_get_value      = nullptr;
il2cpp_field_static_set_value_t      il2cpp_field_static_set_value      = nullptr;
il2cpp_string_new_t                  il2cpp_string_new                  = nullptr;
il2cpp_string_chars_t                il2cpp_string_chars                = nullptr;
il2cpp_object_new_t                  il2cpp_object_new                  = nullptr;
il2cpp_array_new_t                   il2cpp_array_new                   = nullptr;

// Method iterator — not critical if absent; checked before use
using il2cpp_class_get_methods_t = MethodInfo *(*)(Il2CppClass *, void **);
static il2cpp_class_get_methods_t il2cpp_class_get_methods_fn = nullptr;

// ── /proc/self/maps scanner ───────────────────────────────────────────────────
// Returns the runtime load bias (first mapped address) of libname, or 0.
static uintptr_t findLibBase(const char *libname) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[1024];
    uintptr_t result = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, libname)) continue;
        // Only care about executable segments (the first one carries the ELF header)
        if (!strstr(line, "r-xp") && !strstr(line, "r--p")) continue;
        result = (uintptr_t)strtoull(line, nullptr, 16);
        break;
    }
    fclose(f);
    return result;
}

// ── GNU-hash helper ───────────────────────────────────────────────────────────
static uint32_t gnu_hash(const char *name) {
    uint32_t h = 5381;
    for (; *name; name++) h = (h << 5) + h + (uint8_t)*name;
    return h;
}

// ── SYSV-hash helper ──────────────────────────────────────────────────────────
static uint32_t sysv_hash(const char *name) {
    uint32_t h = 0;
    for (; *name; name++) {
        h = (h << 4) + (uint8_t)*name;
        uint32_t g = h & 0xf0000000u;
        if (g) h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

// ── ELF symbol resolver ───────────────────────────────────────────────────────
// Parses the already-mapped ELF at `base` and returns the runtime address of
// `sym_name`, or nullptr if not found.  No dlopen — reads the game's own copy.
static void *resolveSymbol(uintptr_t base, const char *sym_name) {
    if (!base) return nullptr;

    // Validate ELF magic
    auto *ehdr = reinterpret_cast<const Elf64_Ehdr *>(base);
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr->e_ident[EI_MAG3] != ELFMAG3) return nullptr;

    // Find PT_DYNAMIC program header
    auto *phdrs = reinterpret_cast<const Elf64_Phdr *>(base + ehdr->e_phoff);
    const Elf64_Dyn *dyn = nullptr;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            dyn = reinterpret_cast<const Elf64_Dyn *>(base + phdrs[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return nullptr;

    // Extract pointers from the dynamic section.
    // d_un.d_ptr values are load-relative VMAs; add base to get runtime address.
    const Elf64_Sym *symtab    = nullptr;
    const char      *strtab    = nullptr;
    const uint32_t  *gnu_htab  = nullptr;
    const uint32_t  *sysv_htab = nullptr;

    for (const Elf64_Dyn *d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_SYMTAB:   symtab    = reinterpret_cast<const Elf64_Sym *>(base + d->d_un.d_ptr); break;
            case DT_STRTAB:   strtab    = reinterpret_cast<const char *>     (base + d->d_un.d_ptr); break;
            case DT_GNU_HASH: gnu_htab  = reinterpret_cast<const uint32_t *> (base + d->d_un.d_ptr); break;
            case DT_HASH:     sysv_htab = reinterpret_cast<const uint32_t *> (base + d->d_un.d_ptr); break;
        }
    }
    if (!symtab || !strtab) return nullptr;

    // ── GNU hash lookup (used by almost all modern Android .so) ──────────────
    if (gnu_htab) {
        uint32_t nbuckets   = gnu_htab[0];
        uint32_t sym_offset = gnu_htab[1];
        uint32_t bloom_size = gnu_htab[2];
        uint32_t bloom_shift = gnu_htab[3];
        auto *bloom   = reinterpret_cast<const uint64_t *>(gnu_htab + 4);
        auto *buckets = reinterpret_cast<const uint32_t *>(bloom + bloom_size);
        auto *chains  = buckets + nbuckets;

        uint32_t h = gnu_hash(sym_name);

        // Bloom filter early-out
        uint64_t word = bloom[(h / 64) % bloom_size];
        uint64_t mask = (1ULL << (h % 64)) | (1ULL << ((h >> bloom_shift) % 64));
        if ((word & mask) != mask) return nullptr;

        uint32_t bucket = buckets[h % nbuckets];
        if (bucket < sym_offset) return nullptr;

        for (uint32_t idx = bucket; ; idx++) {
            uint32_t chain_val = chains[idx - sym_offset];
            if ((chain_val & ~1u) == (h & ~1u)) {
                const Elf64_Sym &sym = symtab[idx];
                if (sym.st_value && strcmp(strtab + sym.st_name, sym_name) == 0)
                    return reinterpret_cast<void *>(base + sym.st_value);
            }
            if (chain_val & 1u) break;  // end of chain
        }
        return nullptr;
    }

    // ── SYSV hash fallback ────────────────────────────────────────────────────
    if (sysv_htab) {
        uint32_t nbuckets = sysv_htab[0];
        uint32_t nchain   = sysv_htab[1];
        uint32_t h        = sysv_hash(sym_name);
        for (uint32_t idx = sysv_htab[2 + (h % nbuckets)];
             idx != 0 && idx < nchain;
             idx = sysv_htab[2 + nbuckets + idx]) {
            const Elf64_Sym &sym = symtab[idx];
            if (sym.st_value && strcmp(strtab + sym.st_name, sym_name) == 0)
                return reinterpret_cast<void *>(base + sym.st_value);
        }
        return nullptr;
    }

    return nullptr;
}

#define RESOLVE(name) \
    name = reinterpret_cast<name##_t>(resolveSymbol(base, #name)); \
    if (!name) { LOGE("Failed to resolve " #name); return false; }

// ── Public API ────────────────────────────────────────────────────────────────

bool Il2CppApi::init() {
    uintptr_t base = findLibBase("libil2cpp.so");
    if (!base) {
        LOGE("libil2cpp.so not in /proc/self/maps yet");
        return false;
    }
    LOGI("libil2cpp.so base=0x%lx — resolving via ELF", base);

    RESOLVE(il2cpp_domain_get)
    RESOLVE(il2cpp_domain_get_assemblies)
    RESOLVE(il2cpp_assembly_get_image)
    RESOLVE(il2cpp_image_get_name)
    RESOLVE(il2cpp_class_from_name)
    RESOLVE(il2cpp_class_get_method_from_name)
    RESOLVE(il2cpp_class_get_field_from_name)
    RESOLVE(il2cpp_field_get_offset)
    RESOLVE(il2cpp_field_static_get_value)
    RESOLVE(il2cpp_field_static_set_value)
    RESOLVE(il2cpp_string_new)
    RESOLVE(il2cpp_string_chars)
    RESOLVE(il2cpp_object_new)
    RESOLVE(il2cpp_array_new)

    // Optional — don't fail init if absent
    il2cpp_class_get_methods_fn = reinterpret_cast<il2cpp_class_get_methods_t>(
        resolveSymbol(base, "il2cpp_class_get_methods"));
    if (il2cpp_class_get_methods_fn)
        LOGI("il2cpp_class_get_methods resolved");
    else
        LOGI("il2cpp_class_get_methods NOT found — method scanner disabled");

    LOGI("Il2Cpp API resolved successfully (no dlopen)");
    return true;
}

Il2CppImage *Il2CppApi::getImage(const char *assembly_name) {
    if (!il2cpp_domain_get) return nullptr;

    Il2CppDomain *domain = il2cpp_domain_get();
    if (!domain) return nullptr;

    size_t count = 0;
    const Il2CppAssembly **assemblies = il2cpp_domain_get_assemblies(domain, &count);
    if (!assemblies) return nullptr;

    for (size_t i = 0; i < count; i++) {
        Il2CppImage *img = il2cpp_assembly_get_image(assemblies[i]);
        if (!img) continue;
        const char *name = il2cpp_image_get_name(img);
        if (name && strstr(name, assembly_name))
            return img;
    }
    return nullptr;
}

Il2CppClass *Il2CppApi::getClass(Il2CppImage *image,
                                  const char *ns,
                                  const char *class_name) {
    if (!image || !il2cpp_class_from_name) return nullptr;
    return il2cpp_class_from_name(image, ns, class_name);
}

MethodInfo *Il2CppApi::getMethod(Il2CppClass *klass,
                                  const char *method_name,
                                  int         param_count) {
    if (!klass || !il2cpp_class_get_method_from_name) return nullptr;
    return il2cpp_class_get_method_from_name(klass, method_name, param_count);
}

FieldInfo *Il2CppApi::getField(Il2CppClass *klass, const char *field_name) {
    if (!klass || !il2cpp_class_get_field_from_name) return nullptr;
    return il2cpp_class_get_field_from_name(klass, field_name);
}

size_t Il2CppApi::fieldOffset(FieldInfo *field) {
    if (!field || !il2cpp_field_get_offset) return 0;
    return il2cpp_field_get_offset(field);
}

void Il2CppApi::getStaticValue(FieldInfo *field, void *out) {
    if (field && il2cpp_field_static_get_value)
        il2cpp_field_static_get_value(field, out);
}

void Il2CppApi::setStaticValue(MethodInfo * /*unused*/, FieldInfo *field, void *val) {
    if (field && il2cpp_field_static_set_value)
        il2cpp_field_static_set_value(field, val);
}

void Il2CppApi::forEachMethod(Il2CppClass *klass,
                               void (*cb)(const char *name, MethodInfo *info, void *ctx),
                               void *ctx) {
    if (!klass || !il2cpp_class_get_methods_fn || !cb) return;
    void *iter = nullptr;
    MethodInfo *mth = nullptr;
    while ((mth = il2cpp_class_get_methods_fn(klass, &iter)) != nullptr) {
        if (!mth->name) continue;
        cb(mth->name, mth, ctx);
    }
}

MethodInfo *Il2CppApi::scanMethods(Il2CppClass *klass, const char *filter) {
    if (!klass || !filter) return nullptr;
    if (!il2cpp_class_get_methods_fn) {
        LOGE("[SCAN] il2cpp_class_get_methods not available — cannot scan");
        return nullptr;
    }
    MethodInfo *found = nullptr;
    void *iter = nullptr;
    MethodInfo *mth = nullptr;
    int total = 0;
    while ((mth = il2cpp_class_get_methods_fn(klass, &iter)) != nullptr) {
        total++;
        if (!mth->name) continue;
        if (strstr(mth->name, filter)) {
            LOGI("[SCAN] MATCH '%s' params=%d ptr=%p",
                 mth->name,
                 mth->parameters_count,
                 mth->methodPointer);
            if (!found) found = mth;
        }
    }
    LOGI("[SCAN] scan done: filter='%s' total_methods=%d found=%s",
         filter, total, found ? found->name : "NONE");
    return found;
}
