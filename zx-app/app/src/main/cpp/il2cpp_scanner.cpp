#include "il2cpp_scanner.hpp"
#include <dlfcn.h>
#include <cstring>
#include <android/log.h>
#include "zx_logbuf.hpp"
#include <unordered_map>
#include <string>
#include <pthread.h>

#define TAG "ZX-IL2"
#define LOG(fmt, ...) LOGBUF_I(TAG, fmt, ##__VA_ARGS__)
#define ERR(fmt, ...) LOGBUF_E(TAG, fmt, ##__VA_ARGS__)

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

struct Il2CppThread;
static Il2CppThread* (*p_thread_attach)(Il2CppDomain*)  = nullptr;
static void          (*p_thread_detach)(Il2CppThread*)  = nullptr;

static Il2CppImage *g_img    = nullptr;
static Il2CppImage *g_unity  = nullptr;  // UnityEngine.CoreModule
static std::unordered_map<std::string, Il2CppClass*> g_cls_cache;
static pthread_mutex_t g_cls_mu = PTHREAD_MUTEX_INITIALIZER;

// ── bind macro ───────────────────────────────────────────────────────────────

#define BIND(ptr, sym) \
    (ptr) = (__typeof__(ptr))dlsym(h, (sym)); \
    if (!(ptr)) { ERR("missing: %s", (sym)); return false; }

#define BIND_OPT(ptr, sym) \
    (ptr) = (__typeof__(ptr))dlsym(h, (sym));

// ── init ─────────────────────────────────────────────────────────────────────

bool Il2Cpp::init() {
    void *h = dlopen("libil2cpp.so", RTLD_LAZY | RTLD_GLOBAL | RTLD_NOLOAD);
    if (!h) h = dlopen("libil2cpp.so", RTLD_LAZY | RTLD_GLOBAL);
    if (!h) { ERR("libil2cpp.so not found"); return false; }

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
    BIND_OPT(p_thread_attach,    "il2cpp_thread_attach")
    BIND_OPT(p_thread_detach,    "il2cpp_thread_detach")

    Il2CppDomain *dom = p_domain_get();
    if (!dom) { ERR("il2cpp domain not ready"); return false; }
    size_t n = 0;
    const Il2CppAssembly **asms = p_domain_assemblies(dom, &n);
    if (!asms) { ERR("no assemblies"); return false; }

    for (size_t i = 0; i < n; i++) {
        Il2CppImage *img = p_asm_image(asms[i]);
        if (!img) continue;
        const char *nm = p_image_name(img);
        if (!nm) continue;
        if (!g_img   && strstr(nm, "Assembly-CSharp.dll"))       g_img   = img;
        if (!g_unity && strstr(nm, "UnityEngine.CoreModule.dll")) g_unity = img;
        if (g_img && g_unity) break;
    }
    if (!g_img) { ERR("Assembly-CSharp not found (n=%zu)", n); return false; }
    LOG("Assembly-CSharp: %p  (%u classes)", g_img, p_image_class_count(g_img));
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
// Calls UnityEngine.Object::FindObjectOfType(Type) which returns first active instance

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

    // il2cpp_runtime_invoke requires a Type object for the generic arg
    // Easier: search all live objects by walking il2cpp GC heap, but that's risky.
    // Instead we enumerate all classes looking for a singleton pattern (checked caller sets this up).
    (void)klass;  // caller resolves singleton via static getter method
    return nullptr;
}

Il2CppObject *Il2Cpp::invoke0(MethodInfo *m, Il2CppObject *obj) {
    if (!m || !p_runtime_invoke) return nullptr;
    void *exc = nullptr;
    Il2CppObject *result = p_runtime_invoke(m, obj, nullptr, &exc);
    if (exc) { ERR("invoke0 exception on %s", m->name ? m->name : "?"); return nullptr; }
    return result;
}

// ── invoke1 ───────────────────────────────────────────────────────────────────
Il2CppObject *Il2Cpp::invoke1(MethodInfo *m, Il2CppObject *obj, void *arg0) {
    if (!m || !p_runtime_invoke) return nullptr;
    void *exc = nullptr;
    void *params[1] = { arg0 };
    Il2CppObject *result = p_runtime_invoke(m, obj, params, &exc);
    if (exc) { ERR("invoke1 exception on %s", m->name ? m->name : "?"); return nullptr; }
    return result;
}

// ── newString ─────────────────────────────────────────────────────────────────
Il2CppObject *Il2Cpp::newString(const char *str) {
    if (!str || !p_string_new_utf8) return nullptr;
    return p_string_new_utf8(str);
}

// ── thread attach/detach ──────────────────────────────────────────────────────
// Must be called on any background pthread before il2cpp_runtime_invoke.
// The GC scans only attached threads; an unattached thread calling managed code
// causes a segfault when the GC walks the (unknown) stack.
Il2CppThread *Il2Cpp::attachThread() {
    if (!p_thread_attach || !p_domain_get) return nullptr;
    Il2CppDomain *dom = p_domain_get();
    if (!dom) return nullptr;
    return p_thread_attach(dom);
}
void Il2Cpp::detachThread(Il2CppThread *t) {
    if (p_thread_detach && t) p_thread_detach(t);
}

// ── getFieldBool ──────────────────────────────────────────────────────────────
bool Il2Cpp::getFieldBool(Il2CppObject *obj, FieldInfo *field) {
    if (!obj || !field) return false;
    int32_t off = fieldOffset(field);
    if (off <= 0) return false;
    return readField<bool>(obj, off);
}

// ── findObjectsOfType ─────────────────────────────────────────────────────────
// Calls UnityEngine.Object::FindObjectsOfType(Type); caller must free(*arr).
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

    // Il2CppArray: Il2CppObject hdr (16B) | void* bounds (8B) | uintptr_t max_length (8B) | data
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

// ── getLocalInstance ──────────────────────────────────────────────────────────
// Tries IsLocalPlayer field; falls back to first valid instance.
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
