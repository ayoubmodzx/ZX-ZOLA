#include "il2cpp_scanner.hpp"
#include <dlfcn.h>
#include <cstring>
#include <android/log.h>
#include <unordered_map>
#include <string>

#define TAG "ZX-IL2"
#define LOG(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define ERR(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Function pointer types
using FnDomainGet          = Il2CppDomain*(*)();
using FnDomainAssemblies   = const Il2CppAssembly**(*)(Il2CppDomain*, size_t*);
using FnAssemblyGetImage   = Il2CppImage*(*)(const Il2CppAssembly*);
using FnImageGetName       = const char*(*)(Il2CppImage*);
using FnClassFromName      = Il2CppClass*(*)(Il2CppImage*, const char*, const char*);
using FnClassGetField      = FieldInfo*(*)(Il2CppClass*, const char*);
using FnClassGetMethod     = MethodInfo*(*)(Il2CppClass*, const char*, int);
using FnFieldStaticSet     = void(*)(FieldInfo*, void*);
using FnFieldStaticGet     = void(*)(FieldInfo*, void*);

static FnDomainGet        il2cpp_domain_get;
static FnDomainAssemblies il2cpp_domain_get_assemblies;
static FnAssemblyGetImage il2cpp_assembly_get_image;
static FnImageGetName     il2cpp_image_get_name;
static FnClassFromName    il2cpp_class_from_name;
static FnClassGetField    il2cpp_class_get_field_from_name;
static FnClassGetMethod   il2cpp_class_get_method_from_name;
static FnFieldStaticSet   il2cpp_field_static_set_value;
static FnFieldStaticGet   il2cpp_field_static_get_value;

static Il2CppImage *g_assembly_csharp = nullptr;
static std::unordered_map<std::string, Il2CppClass*> g_class_cache;

#define BIND(fn) \
    fn = (decltype(fn))dlsym(h, #fn); \
    if (!fn) { ERR("Missing " #fn); return false; }

bool Il2Cpp::init() {
    void *h = dlopen("libil2cpp.so", RTLD_LAZY | RTLD_GLOBAL);
    if (!h) { ERR("libil2cpp.so not found"); return false; }

    BIND(il2cpp_domain_get)
    BIND(il2cpp_domain_get_assemblies)
    BIND(il2cpp_assembly_get_image)
    BIND(il2cpp_image_get_name)
    BIND(il2cpp_class_from_name)
    BIND(il2cpp_class_get_field_from_name)
    BIND(il2cpp_class_get_method_from_name)
    BIND(il2cpp_field_static_set_value)
    BIND(il2cpp_field_static_get_value)

    // Cache Assembly-CSharp image
    Il2CppDomain *domain = il2cpp_domain_get();
    size_t count = 0;
    const Il2CppAssembly **asms = il2cpp_domain_get_assemblies(domain, &count);
    for (size_t i = 0; i < count; i++) {
        Il2CppImage *img = il2cpp_assembly_get_image(asms[i]);
        if (!img) continue;
        const char *name = il2cpp_image_get_name(img);
        if (name && strstr(name, "Assembly-CSharp")) {
            g_assembly_csharp = img;
            LOG("Assembly-CSharp found");
            break;
        }
    }
    return g_assembly_csharp != nullptr;
}

Il2CppClass *Il2Cpp::cls(const char *class_name) {
    auto it = g_class_cache.find(class_name);
    if (it != g_class_cache.end()) return it->second;

    if (!g_assembly_csharp || !il2cpp_class_from_name) return nullptr;
    Il2CppClass *c = il2cpp_class_from_name(g_assembly_csharp, "", class_name);
    if (c) g_class_cache[class_name] = c;
    return c;
}

FieldInfo *Il2Cpp::getField(Il2CppClass *klass, const char *name) {
    if (!klass || !il2cpp_class_get_field_from_name) return nullptr;
    return il2cpp_class_get_field_from_name(klass, name);
}

MethodInfo *Il2Cpp::getMethod(Il2CppClass *klass, const char *name, int params) {
    if (!klass || !il2cpp_class_get_method_from_name) return nullptr;
    return il2cpp_class_get_method_from_name(klass, name, params);
}

void Il2Cpp::setStaticFloat(FieldInfo *f, float val) {
    if (f && il2cpp_field_static_set_value)
        il2cpp_field_static_set_value(f, &val);
}
void Il2Cpp::setStaticBool(FieldInfo *f, bool val) {
    if (f && il2cpp_field_static_set_value)
        il2cpp_field_static_set_value(f, &val);
}
void Il2Cpp::setStaticInt(FieldInfo *f, int val) {
    if (f && il2cpp_field_static_set_value)
        il2cpp_field_static_set_value(f, &val);
}
