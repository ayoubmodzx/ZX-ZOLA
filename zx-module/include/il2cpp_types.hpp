#pragma once
#include <cstdint>
#include <cstddef>

// Il2Cpp runtime type definitions
struct Il2CppDomain;
struct Il2CppAssembly;
struct Il2CppImage;
struct Il2CppClass;
struct Il2CppObject;
struct Il2CppString;
struct Il2CppArray;

struct FieldInfo {
    const char *name;
    void       *type;
    Il2CppClass *parent;
    int32_t     offset;
    uint32_t    token;
};

struct MethodInfo {
    const char  *name;
    void        *methodPointer;
    void        *invoker_method;
    Il2CppClass *klass;
    void        *return_type;
    uint32_t     token;
    uint16_t     flags;
    uint16_t     iflags;
    uint16_t     slot;
    uint8_t      parameters_count;
};

// Il2Cpp exported function signatures
using il2cpp_domain_get_t          = Il2CppDomain*(*)();
using il2cpp_domain_get_assemblies_t = const Il2CppAssembly**(*)(Il2CppDomain*, size_t*);
using il2cpp_assembly_get_image_t  = Il2CppImage*(*)(const Il2CppAssembly*);
using il2cpp_image_get_name_t      = const char*(*)(Il2CppImage*);
using il2cpp_class_from_name_t     = Il2CppClass*(*)(Il2CppImage*, const char*, const char*);
using il2cpp_class_get_method_from_name_t = MethodInfo*(*)(Il2CppClass*, const char*, int);
using il2cpp_class_get_field_from_name_t  = FieldInfo*(*)(Il2CppClass*, const char*);
using il2cpp_field_get_offset_t    = size_t(*)(FieldInfo*);
using il2cpp_field_static_get_value_t = void(*)(FieldInfo*, void*);
using il2cpp_field_static_set_value_t = void(*)(FieldInfo*, void*);
using il2cpp_string_new_t          = Il2CppString*(*)(const char*);
using il2cpp_string_chars_t        = uint16_t*(*)(Il2CppString*);
using il2cpp_object_new_t          = Il2CppObject*(*)(Il2CppClass*);
using il2cpp_array_new_t           = Il2CppArray*(*)(Il2CppClass*, size_t);
