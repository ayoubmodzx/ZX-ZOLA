#include "il2cpp_api.hpp"
#include <dlfcn.h>
#include <android/log.h>
#include <cstring>

#define TAG "ZX-IL2CPP"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static void *g_il2cpp_handle = nullptr;

// Cached function pointers — resolved once, reused forever
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

#define RESOLVE(name) \
    name = reinterpret_cast<name##_t>(dlsym(g_il2cpp_handle, #name)); \
    if (!name) { LOGE("Failed to resolve " #name); return false; }

bool Il2CppApi::init() {
    g_il2cpp_handle = dlopen("libil2cpp.so", RTLD_LAZY | RTLD_GLOBAL);
    if (!g_il2cpp_handle) {
        LOGE("dlopen libil2cpp.so failed: %s", dlerror());
        return false;
    }

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

    LOGI("Il2Cpp API resolved successfully");
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
        if (name && strstr(name, assembly_name)) {
            return img;
        }
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

void Il2CppApi::setStaticValue(MethodInfo *method, FieldInfo *field, void *val) {
    if (field && il2cpp_field_static_set_value)
        il2cpp_field_static_set_value(field, val);
}
