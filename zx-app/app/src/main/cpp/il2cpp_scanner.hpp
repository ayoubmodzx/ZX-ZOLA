#pragma once
#include <cstddef>
#include <cstdint>

struct FieldInfo  { const char *name; void *type; void *parent; int32_t offset; uint32_t token; };
struct MethodInfo { const char *name; void *ptr;  void *invoker; void *klass;   void *ret_type;
                    uint32_t token; uint16_t flags; uint16_t iflags; uint16_t slot; uint8_t param_count; };
struct Il2CppClass; struct Il2CppImage; struct Il2CppDomain; struct Il2CppAssembly;

namespace Il2Cpp {
    bool init();

    Il2CppClass *cls(const char *class_name);
    FieldInfo   *getField(Il2CppClass *klass, const char *name);
    MethodInfo  *getMethod(Il2CppClass *klass, const char *name, int params = -1);

    void setStaticFloat(FieldInfo *f, float val);
    void setStaticBool(FieldInfo *f, bool val);
    void setStaticInt(FieldInfo *f, int val);
}
