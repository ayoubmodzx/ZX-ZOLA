#pragma once
#include <cstdint>
#include <cstddef>
#include <functional>

// Real il2cpp struct layout for Unity 2019+ (confirmed from libil2cpp.so ELF analysis)
struct FieldInfo {
    const char  *name;
    void        *type;
    void        *parent;      // Il2CppClass*
    int32_t      offset;      // THREAD_STATIC_FIELD_OFFSET (-1) for thread-static
    uint32_t     token;
};

struct ParameterInfo {
    const char *name;
    int32_t     position;
    uint32_t    token;
    void       *parameter_type;
};

struct MethodInfo {
    void              *methodPointer;   // native code ptr — MUST be first
    void              *invoker_method;
    const char        *name;
    void              *klass;           // Il2CppClass*
    void              *return_type;
    const ParameterInfo *parameters;
    union {
        void *rgctx_data;
        void *methodDefinition;
    };
    uint32_t  token;
    uint16_t  flags;
    uint16_t  iflags;
    uint16_t  slot;
    uint8_t   parameters_count;
    // bit flags follow; we only care about the above
};

struct Il2CppClass;
struct Il2CppImage;
struct Il2CppDomain;
struct Il2CppAssembly;
struct Il2CppString;
struct Il2CppObject { void *klass; void *monitor; /* data follows */ };

// Field-type id helpers (matches il2cpp TYPE_* constants we care about)
enum Il2CppTypeEnum : uint8_t {
    IL2CPP_TYPE_BOOLEAN = 0x02,
    IL2CPP_TYPE_I4      = 0x08,
    IL2CPP_TYPE_U4      = 0x09,
    IL2CPP_TYPE_R4      = 0x0C, // float
    IL2CPP_TYPE_R8      = 0x0D, // double
    IL2CPP_TYPE_CLASS   = 0x12,
    IL2CPP_TYPE_OBJECT  = 0x1C,
};

// Minimal Il2CppType layout we need
struct Il2CppType {
    void    *data;
    uint32_t attrs;
    uint8_t  type;   // Il2CppTypeEnum
    // more bit fields we don't read
};

namespace Il2Cpp {
    bool init();

    // Returns cached Assembly-CSharp image pointer
    Il2CppImage *mainImage();

    // Class lookup
    Il2CppClass *cls(const char *name, const char *ns = "");

    // Enumerate ALL classes in Assembly-CSharp; callback returns true to stop
    void enumClasses(std::function<bool(Il2CppClass*)> cb);

    // Field and method lookup
    FieldInfo  *getField (Il2CppClass *klass, const char *name);
    MethodInfo *getMethod(Il2CppClass *klass, const char *name, int params = -1);

    // Field type query
    uint8_t fieldTypeId(FieldInfo *f);

    // Static field access
    void staticGet(FieldInfo *f, void *out);
    void staticSet(FieldInfo *f, void *in);

    // Helpers
    inline void setStaticFloat(FieldInfo *f, float v) { if(f) staticSet(f, &v); }
    inline void setStaticBool (FieldInfo *f, bool  v) { if(f) staticSet(f, &v); }
    inline void setStaticInt  (FieldInfo *f, int   v) { if(f) staticSet(f, &v); }
    inline float getStaticFloat(FieldInfo *f) {
        float v = 0.f; if(f) staticGet(f, &v); return v;
    }

    // Instance field read/write via offset (NO il2cpp call, direct memory)
    template<typename T>
    inline T  readField (void *obj, int32_t off) {
        T v{}; if(obj && off > 0) __builtin_memcpy(&v, (char*)obj+off, sizeof(T)); return v;
    }
    template<typename T>
    inline void writeField(void *obj, int32_t off, T v) {
        if(obj && off > 0) __builtin_memcpy((char*)obj+off, &v, sizeof(T));
    }

    // Class/field metadata queries
    const char  *className(Il2CppClass *c);
    const char  *fieldName (FieldInfo   *f);
    int32_t      fieldOffset(FieldInfo  *f);
    uint32_t     classFieldCount(Il2CppClass *c);

    // FindObjectOfType shim — calls UnityEngine Object.FindObjectOfType(Type)
    Il2CppObject *findObject(Il2CppClass *klass);

    // Runtime invoke with no args
    Il2CppObject *invoke0(MethodInfo *m, Il2CppObject *obj);

    Il2CppObject* findObjectsOfType(Il2CppClass* klass);
    Il2CppObject* getLocalInstance(Il2CppClass* klass);
    void*         invoke1(Il2CppObject* obj, const char* method, void* arg0);
    Il2CppString* newString(const char* str);
    bool          getFieldBool(Il2CppObject* obj, FieldInfo* field);
    template<typename T>
    T invoke0(Il2CppObject* obj, const char* method);
}
