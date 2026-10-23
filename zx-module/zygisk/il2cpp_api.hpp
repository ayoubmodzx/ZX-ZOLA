#pragma once
#include "../include/il2cpp_types.hpp"

// Stateless API — all functions are free functions operating on resolved symbols.
// Resolved once in init(), zero overhead afterwards.
namespace Il2CppApi {
    bool        init();
    Il2CppImage *getImage(const char *assembly_name);
    Il2CppClass *getClass(Il2CppImage *image, const char *ns, const char *class_name);
    MethodInfo  *getMethod(Il2CppClass *klass, const char *method_name, int param_count = -1);
    FieldInfo   *getField(Il2CppClass *klass, const char *field_name);
    size_t       fieldOffset(FieldInfo *field);
    void         getStaticValue(FieldInfo *field, void *out);
    void         setStaticValue(MethodInfo *method, FieldInfo *field, void *val);
    // Scans all methods of klass; logs every method whose name contains filter (case-sensitive).
    // Returns the first matching MethodInfo* or nullptr.
    MethodInfo  *scanMethods(Il2CppClass *klass, const char *filter);
    // Iterates every method on klass; calls cb(name, info) for each — returns false from cb to stop.
    void         forEachMethod(Il2CppClass *klass, void (*cb)(const char *name, MethodInfo *info, void *ctx), void *ctx);
}
