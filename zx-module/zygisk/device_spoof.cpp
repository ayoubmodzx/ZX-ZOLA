#include "device_spoof.hpp"
#include <android/log.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/system_properties.h>
#include <dlfcn.h>
#include <pthread.h>
#include "hook_engine.hpp"

#define TAG "ZX-SPOOF"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ---------------------------------------------------------------------------
// Spoofed ID storage
// ---------------------------------------------------------------------------

static char s_android_id[33]   = {};  // 16 hex bytes (32 chars) + null
static char s_serial[33]       = {};
static char s_mac_wlan0[18]    = {};  // "aa:bb:cc:dd:ee:ff"
static char s_mac_bt[18]       = {};
static bool s_initialized      = false;
static pthread_mutex_t s_lock  = PTHREAD_MUTEX_INITIALIZER;

// ---------------------------------------------------------------------------
// Deterministic ID generation from a stable seed
// ---------------------------------------------------------------------------

static uint64_t splitmix64(uint64_t &x) {
    x += 0x9e3779b97f4a7c15ULL;
    uint64_t z = x;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static void seed_from_build(uint64_t &seed) {
    // Mix build fingerprint so IDs are stable across game restarts on same ROM
    char fp[PROP_VALUE_MAX] = {};
    __system_property_get("ro.build.fingerprint", fp);
    if (!fp[0]) __system_property_get("ro.build.description", fp);
    for (int i = 0; fp[i]; ++i)
        seed ^= (uint64_t)(unsigned char)fp[i] << ((i & 7) * 8);
    // Add a constant twist so IDs differ from the original even on same ROM
    seed ^= 0xDEADBEEF12345678ULL;
}

static void generate_ids() {
    uint64_t seed = 0x5A5A5A5A5A5A5A5AULL;
    seed_from_build(seed);

    uint64_t a = splitmix64(seed);
    uint64_t b = splitmix64(seed);

    // Android ID: 16 lowercase hex chars
    snprintf(s_android_id, sizeof(s_android_id), "%08x%08x",
             (uint32_t)(a >> 32), (uint32_t)(a & 0xFFFFFFFF));

    // Serial: 12 uppercase alphanum
    static const char hex_up[] = "0123456789ABCDEF";
    for (int i = 0; i < 12; ++i)
        s_serial[i] = hex_up[(b >> (i * 4)) & 0xF];
    s_serial[12] = '\0';

    uint64_t c = splitmix64(seed);
    // MAC wlan0 — set locally-administered bit (bit 1 of first octet)
    uint8_t m[6];
    for (int i = 0; i < 6; ++i) m[i] = (uint8_t)(c >> (i * 8));
    m[0] = (m[0] & 0xFE) | 0x02;  // locally administered, unicast
    snprintf(s_mac_wlan0, sizeof(s_mac_wlan0),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);

    uint64_t d = splitmix64(seed);
    for (int i = 0; i < 6; ++i) m[i] = (uint8_t)(d >> (i * 8));
    m[0] = (m[0] & 0xFE) | 0x02;
    snprintf(s_mac_bt, sizeof(s_mac_bt),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);

    s_initialized = true;
    LOGI("Generated IDs — android_id=%s serial=%s mac=%s",
         s_android_id, s_serial, s_mac_wlan0);
}

// ---------------------------------------------------------------------------
// Hook: __system_property_get
// ---------------------------------------------------------------------------

using PropGetFn = int (*)(const char *, char *);
static PropGetFn s_orig_prop_get = nullptr;

static int hooked_prop_get(const char *name, char *value) {
    int ret = s_orig_prop_get(name, value);
    if (!name || !value || !s_initialized) return ret;

    if (strcmp(name, "ro.serialno")        == 0 ||
        strcmp(name, "ro.boot.serialno")   == 0 ||
        strcmp(name, "persist.sys.serialno") == 0) {
        strncpy(value, s_serial, PROP_VALUE_MAX - 1);
        value[PROP_VALUE_MAX - 1] = '\0';
        return (int)strlen(value);
    }
    if (strcmp(name, "ro.boot.wifi_macaddr") == 0) {
        strncpy(value, s_mac_wlan0, PROP_VALUE_MAX - 1);
        value[PROP_VALUE_MAX - 1] = '\0';
        return (int)strlen(value);
    }
    return ret;
}

// ---------------------------------------------------------------------------
// Hook: open — intercept sysfs MAC paths
// ---------------------------------------------------------------------------

using OpenFn = int (*)(const char *, int, ...);
static OpenFn s_orig_open = nullptr;

static bool is_mac_path(const char *path) {
    if (!path) return false;
    // /sys/class/net/wlan0/address  or  /sys/class/bluetooth/hci0/address
    if (strstr(path, "/sys/class/net/")       && strstr(path, "/address")) return true;
    if (strstr(path, "/sys/class/bluetooth/") && strstr(path, "/address")) return true;
    return false;
}

static bool is_wlan_path(const char *path) {
    return path && strstr(path, "wlan");
}

// We serve the MAC from an in-memory memfd so the caller gets a normal fd.
static int make_mac_memfd(const char *mac_str) {
    char buf[20];
    snprintf(buf, sizeof(buf), "%s\n", mac_str);
    int fd = (int)syscall(319 /* __NR_memfd_create */, "mac", 0);
    if (fd < 0) fd = (int)syscall(385 /* arm64 memfd_create */, "mac", 0);
    if (fd < 0) return -1;
    write(fd, buf, strlen(buf));
    lseek(fd, 0, SEEK_SET);
    return fd;
}

static int hooked_open(const char *path, int flags, ...) {
    if (s_initialized && is_mac_path(path)) {
        const char *mac = is_wlan_path(path) ? s_mac_wlan0 : s_mac_bt;
        int mfd = make_mac_memfd(mac);
        if (mfd >= 0) {
            LOGI("MAC intercept: %s → %s", path, mac);
            return mfd;
        }
    }
    // Fall through to original (variadic mode arg)
    // We pass 0 for mode — open() with O_CREAT masked out doesn't use it.
    return s_orig_open(path, flags, 0);
}

// ---------------------------------------------------------------------------
// JNI spoofing — android_id via Settings.Secure.getString
// ---------------------------------------------------------------------------
// We hook the JNI vtable entry for CallStaticObjectMethodV in the target process.
// Settings.Secure.getString is a static Java call → goes through JNI.
// We detect: class = Settings$Secure, methodID name = "getString", key = "android_id".
//
// Because CallStaticObjectMethodV is called millions of times, we cache the
// target jmethodID on first match and fast-path everything else.

using CallStaticObjectMethodVFn =
    jobject (*)(JNIEnv *, jclass, jmethodID, va_list);

static CallStaticObjectMethodVFn s_orig_call_static_obj_v = nullptr;
static jmethodID                 s_android_id_mid         = nullptr;
static jclass                    s_settings_secure_cls    = nullptr;
static jmethodID                 s_string_new_mid         = nullptr;  // String ctor
static jclass                    s_string_cls             = nullptr;
static bool                      s_jni_resolved           = false;

static void resolve_jni_targets(JNIEnv *env) {
    if (s_jni_resolved) return;
    s_jni_resolved = true;

    jclass cls = env->FindClass("android/provider/Settings$Secure");
    if (!cls) return;
    s_settings_secure_cls = (jclass)env->NewGlobalRef(cls);
    env->DeleteLocalRef(cls);

    s_android_id_mid = env->GetStaticMethodID(
        s_settings_secure_cls, "getString",
        "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;");

    jclass scls = env->FindClass("java/lang/String");
    if (scls) {
        s_string_cls = (jclass)env->NewGlobalRef(scls);
        env->DeleteLocalRef(scls);
    }
    LOGI("JNI resolve — Settings.Secure.getString mid=%p", (void*)s_android_id_mid);
}

// Key string "android_id" as jstring is what the caller passes.
// We compare the Java string value cheaply.
static bool jstr_equals(JNIEnv *env, jstring js, const char *ascii) {
    if (!js) return false;
    const char *c = env->GetStringUTFChars(js, nullptr);
    if (!c) return false;
    bool eq = (strcmp(c, ascii) == 0);
    env->ReleaseStringUTFChars(js, c);
    return eq;
}

static jobject hooked_call_static_obj_v(JNIEnv *env, jclass clazz,
                                         jmethodID mid, va_list args) {
    // Fast path: not the target method
    if (mid != s_android_id_mid || !s_initialized) {
        return s_orig_call_static_obj_v(env, clazz, mid, args);
    }
    // mid == getString(ContentResolver, String) — peek at second arg (the key)
    va_list args_copy;
    va_copy(args_copy, args);
    /*ContentResolver*/ va_arg(args_copy, jobject);  // skip first arg
    jstring key = va_arg(args_copy, jstring);
    va_end(args_copy);

    if (jstr_equals(env, key, "android_id")) {
        LOGI("JNI intercept: android_id → %s", s_android_id);
        return env->NewStringUTF(s_android_id);
    }
    return s_orig_call_static_obj_v(env, clazz, mid, args);
}

// ---------------------------------------------------------------------------
// JNIEnv vtable hook helper
// ---------------------------------------------------------------------------
// JNIEnv* → points to JNINativeInterface_ → function pointer table.
// CallStaticObjectMethodV is at a fixed vtable index per Android JNI spec.
// Index 115 (0-based from JNINativeInterface_) = CallStaticObjectMethodV.
static constexpr int kCallStaticObjV_idx = 115;

static bool hook_jni_vtable(JNIEnv *env) {
    if (!env) return false;
    void **vtable = *reinterpret_cast<void ***>(env);  // JNIEnv* → JNINativeInterface_*
    void **slot   = &vtable[kCallStaticObjV_idx];

    s_orig_call_static_obj_v =
        reinterpret_cast<CallStaticObjectMethodVFn>(*slot);
    if (!s_orig_call_static_obj_v) return false;

    // mprotect the page containing the slot
    uintptr_t page = (uintptr_t)slot & ~(uintptr_t)(getpagesize() - 1);
    mprotect(reinterpret_cast<void *>(page), getpagesize(), PROT_READ | PROT_WRITE);
    *slot = reinterpret_cast<void *>(hooked_call_static_obj_v);
    mprotect(reinterpret_cast<void *>(page), getpagesize(), PROT_READ);

    LOGI("JNI vtable[%d] patched — CallStaticObjectMethodV hooked", kCallStaticObjV_idx);
    return true;
}

// ---------------------------------------------------------------------------
// Public entry
// ---------------------------------------------------------------------------

void DeviceSpoof::install(JNIEnv *env) {
    pthread_mutex_lock(&s_lock);
    if (s_initialized) { pthread_mutex_unlock(&s_lock); return; }
    generate_ids();
    pthread_mutex_unlock(&s_lock);

    // Hook __system_property_get in libc.so
    void *prop_sym = dlsym(RTLD_DEFAULT, "__system_property_get");
    if (prop_sym) {
        HookEngine::get().hookAddr(prop_sym,
            reinterpret_cast<void *>(hooked_prop_get),
            reinterpret_cast<void **>(&s_orig_prop_get),
            "SPOOF-prop_get");
        LOGI("__system_property_get hooked");
    }

    // Hook open() for MAC sysfs paths
    void *open_sym = dlsym(RTLD_DEFAULT, "open");
    if (open_sym) {
        HookEngine::get().hookAddr(open_sym,
            reinterpret_cast<void *>(hooked_open),
            reinterpret_cast<void **>(&s_orig_open),
            "SPOOF-open");
        LOGI("open() hooked for MAC paths");
    }

    // JNI vtable hook for android_id
    if (env) {
        resolve_jni_targets(env);
        hook_jni_vtable(env);
    }

    LOGI("DeviceSpoof installed — android_id=%s serial=%s mac=%s",
         s_android_id, s_serial, s_mac_wlan0);
}

void DeviceSpoof::setCustomAndroidId(const char *id16hex) {
    if (!id16hex || strlen(id16hex) < 16) return;
    pthread_mutex_lock(&s_lock);
    strncpy(s_android_id, id16hex, 32);
    s_android_id[32] = '\0';
    pthread_mutex_unlock(&s_lock);
    LOGI("Custom android_id set: %s", s_android_id);
}
