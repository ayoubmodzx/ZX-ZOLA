/*
 * features.cpp — ZX-ZOLA payload features
 * Active features: anti-recoil, no-spread, rapid-fire, aim-assist, wide-pov, ESP, headshot-assist
 */

#include "features.hpp"
#include "esp_renderer.hpp"
#include "il2cpp_scanner.hpp"
#include "dobby_stub.hpp"
#include <android/log.h>
#include <dlfcn.h>
#include <atomic>
#include <cstring>

#define TAG "ZX-FEAT"
#define LOG(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define ERR(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ─────────────────────────────────────────────────────────────────────────────
// Game class cache
// ─────────────────────────────────────────────────────────────────────────────

struct GameClasses {
    Il2CppClass *playerState = nullptr;  // "CSPlayerState" — unobfuscated
    Il2CppClass *weaponFire  = nullptr;  // fireRate + recoil floats

    int32_t offFireRate = -1;
    int32_t offRecoilH  = -1;
    int32_t offRecoilV  = -1;
    int32_t offSpread   = -1;

    bool ready = false;
};
static GameClasses g_cls;

// ─────────────────────────────────────────────────────────────────────────────
// Hook state flags
// ─────────────────────────────────────────────────────────────────────────────

static std::atomic<bool>  g_noRecoil{false};
static std::atomic<bool>  g_noSpread{false};
static std::atomic<bool>  g_rapidFire{false};
static std::atomic<float> g_fovOverride{0.f};

static void *g_origFireMethod = nullptr;

// ─────────────────────────────────────────────────────────────────────────────
// Camera FOV icall hook
// ─────────────────────────────────────────────────────────────────────────────

using FnSetFOV = void(*)(void*, float);
static FnSetFOV g_origSetFOV = nullptr;
static void hookSetFOV(void *self, float fov) {
    float ov = g_fovOverride.load(std::memory_order_relaxed);
    g_origSetFOV(self, ov > 0.f ? ov : fov);
}

// ─────────────────────────────────────────────────────────────────────────────
// Field pattern scanner
// ─────────────────────────────────────────────────────────────────────────────

struct FieldPattern { const char *name; int *outOff; };

static Il2CppClass *findClassByFields(const FieldPattern *p, int n, const char *hint) {
    Il2CppClass *found = nullptr;
    Il2Cpp::enumClasses([&](Il2CppClass *c) -> bool {
        if (Il2Cpp::classFieldCount(c) < (uint32_t)n) return false;
        int ok = 0;
        for (int i = 0; i < n; i++) {
            FieldInfo *f = Il2Cpp::getField(c, p[i].name);
            if (!f || Il2Cpp::fieldTypeId(f) != IL2CPP_TYPE_R4) break;
            ok++;
        }
        if (ok == n) {
            found = c;
            LOG("Found '%s' for %s", Il2Cpp::className(c), hint);
            for (int i = 0; i < n; i++) {
                FieldInfo *f = Il2Cpp::getField(c, p[i].name);
                if (f && p[i].outOff) *p[i].outOff = Il2Cpp::fieldOffset(f);
            }
            return true;
        }
        return false;
    });
    return found;
}

// ─────────────────────────────────────────────────────────────────────────────
// Discovery
// ─────────────────────────────────────────────────────────────────────────────

static void discoverClasses() {
    g_cls.playerState = Il2Cpp::cls("CSPlayerState");
    if (g_cls.playerState) LOG("CSPlayerState OK");
    else ERR("CSPlayerState not found");

    static const char *kFireNames[][3] = {
        {"fireRate",    "recoilX",    "recoilY"},
        {"FireRate",    "RecoilX",    "RecoilY"},
        {"m_fireRate",  "m_recoilH",  "m_recoilV"},
        {"fireInterval","kickX",      "kickY"},
        {nullptr, nullptr, nullptr}
    };
    for (int i = 0; kFireNames[i][0] && !g_cls.weaponFire; i++) {
        FieldPattern pat[] = {
            {kFireNames[i][0], &g_cls.offFireRate},
            {kFireNames[i][1], &g_cls.offRecoilH},
            {kFireNames[i][2], &g_cls.offRecoilV},
        };
        g_cls.weaponFire = findClassByFields(pat, 3, "weaponFire");
        if (g_cls.weaponFire) {
            static const char *kS[] = {"spread","Spread","bulletSpread","disperseAngle",nullptr};
            for (const char **s = kS; *s; s++) {
                FieldInfo *f = Il2Cpp::getField(g_cls.weaponFire, *s);
                if (f && Il2Cpp::fieldTypeId(f) == IL2CPP_TYPE_R4) {
                    g_cls.offSpread = Il2Cpp::fieldOffset(f); break;
                }
            }
        }
    }

    g_cls.ready = true;
    LOG("Discovery done. playerState=%p weaponFire=%p", g_cls.playerState, g_cls.weaponFire);
}

// ─────────────────────────────────────────────────────────────────────────────
// Unity icall hooks
// ─────────────────────────────────────────────────────────────────────────────

static void hookUnityIcalls() {
    void *lib = dlopen("libil2cpp.so", RTLD_LAZY | RTLD_NOLOAD);
    if (!lib) return;

    using FnResolve = void*(*)(const char*);
    auto resolve = (FnResolve)dlsym(lib, "il2cpp_resolve_icall");
    if (!resolve) { ERR("il2cpp_resolve_icall missing"); return; }

    void *setFOV = resolve("UnityEngine.Camera::set_fieldOfView(System.Single)");
    if (!setFOV) setFOV = resolve("UnityEngine.Camera::set_fieldOfView(float)");
    if (setFOV) {
        DobbyHook(setFOV, (void*)hookSetFOV, (void**)&g_origSetFOV);
        LOG("Hooked Camera::set_fieldOfView");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Weapon fire hook (recoil / spread / rapid-fire)
// ─────────────────────────────────────────────────────────────────────────────

using FnFireWeapon = void(*)(void*, void*, void*);
static FnFireWeapon g_origFire = nullptr;
static void hookFireWeapon(void *self, void *a, void *b) {
    if (g_noRecoil) {
        if (g_cls.offRecoilH > 0) Il2Cpp::writeField<float>(self, g_cls.offRecoilH, 0.f);
        if (g_cls.offRecoilV > 0) Il2Cpp::writeField<float>(self, g_cls.offRecoilV, 0.f);
    }
    if (g_noSpread && g_cls.offSpread > 0)
        Il2Cpp::writeField<float>(self, g_cls.offSpread, 0.f);
    if (g_rapidFire && g_cls.offFireRate > 0)
        Il2Cpp::writeField<float>(self, g_cls.offFireRate, 0.02f);
    g_origFire(self, a, b);
}

static void hookWeaponFire() {
    if (!g_cls.weaponFire) return;
    static const char *kM[] = {
        "Fire","OnFire","Shoot","OnShoot","DoFire","StartFire","FireBullet","SpawnBullet",nullptr};
    for (const char **mn = kM; *mn; mn++) {
        MethodInfo *m = Il2Cpp::getMethod(g_cls.weaponFire, *mn, -1);
        if (m && m->methodPointer && !g_origFireMethod) {
            DobbyHook(m->methodPointer, (void*)hookFireWeapon, &g_origFireMethod);
            g_origFire = (FnFireWeapon)g_origFireMethod;
            LOG("Hooked weapon: %s @ %p", *mn, m->methodPointer);
            break;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public init
// ─────────────────────────────────────────────────────────────────────────────

void Features::init() {
    discoverClasses();
    hookUnityIcalls();
    hookWeaponFire();
}

// ─────────────────────────────────────────────────────────────────────────────
// Feature implementations
// ─────────────────────────────────────────────────────────────────────────────

static void antiRecoil(bool on) {
    g_noRecoil = on;
    if (g_cls.weaponFire) {
        static const char *kH[] = {"recoilX","recoilH","kickH","m_recoilH",nullptr};
        static const char *kV[] = {"recoilY","recoilV","kickV","m_recoilV",nullptr};
        for (const char **n = kH; *n; n++) {
            FieldInfo *f = Il2Cpp::getField(g_cls.weaponFire, *n);
            if (f) { Il2Cpp::setStaticFloat(f, on ? 0.f : 1.f); break; }
        }
        for (const char **n = kV; *n; n++) {
            FieldInfo *f = Il2Cpp::getField(g_cls.weaponFire, *n);
            if (f) { Il2Cpp::setStaticFloat(f, on ? 0.f : 1.f); break; }
        }
    }
    LOG("AntiRecoil %s", on ? "ON" : "OFF");
}

static void noSpread(bool on) {
    g_noSpread = on;
    if (g_cls.weaponFire) {
        static const char *kS[] = {"spread","Spread","bulletSpread","disperseAngle",nullptr};
        for (const char **n = kS; *n; n++) {
            FieldInfo *f = Il2Cpp::getField(g_cls.weaponFire, *n);
            if (f) { Il2Cpp::setStaticFloat(f, on ? 0.f : 1.f); break; }
        }
    }
    LOG("NoSpread %s", on ? "ON" : "OFF");
}

static void rapidFire(bool on) {
    g_rapidFire = on;
    if (g_cls.weaponFire) {
        static const char *kR[] = {"fireRate","FireRate","fireInterval","m_fireRate",nullptr};
        for (const char **n = kR; *n; n++) {
            FieldInfo *f = Il2Cpp::getField(g_cls.weaponFire, *n);
            if (f) { Il2Cpp::setStaticFloat(f, on ? 0.01f : 0.3f); break; }
        }
    }
    LOG("RapidFire %s", on ? "ON" : "OFF");
}

static void aimAssist(bool on) {
    if (g_cls.playerState) {
        static const char *kA[] = {"aimAssistAngle","AimAssistAngle","autoAimAngle","magnetAngle",nullptr};
        for (const char **n = kA; *n; n++) {
            FieldInfo *f = Il2Cpp::getField(g_cls.playerState, *n);
            if (f) { Il2Cpp::setStaticFloat(f, on ? 30.f : 5.f); break; }
        }
    }
    LOG("AimAssist %s", on ? "ON" : "OFF");
}

static void widePov(bool on) {
    g_fovOverride.store(on ? 90.f : 0.f, std::memory_order_relaxed);
    static const char *kCam[] = {"CameraController","CamController","FPSCamera","PlayerCamera",nullptr};
    for (const char **cn = kCam; *cn; cn++) {
        Il2CppClass *c = Il2Cpp::cls(*cn);
        if (!c) continue;
        static const char *kFov[] = {"fieldOfView","fov","FOV","m_fov",nullptr};
        for (const char **fn = kFov; *fn; fn++) {
            FieldInfo *f = Il2Cpp::getField(c, *fn);
            if (f) { Il2Cpp::setStaticFloat(f, on ? 90.f : 60.f); break; }
        }
        break;
    }
    LOG("WidePOV %s", on ? "ON" : "OFF");
}

// ─────────────────────────────────────────────────────────────────────────────
// Dispatch
// ─────────────────────────────────────────────────────────────────────────────

void Features::apply(int cmd, bool enable) {
    if (!g_cls.ready) Features::init();

    switch (cmd) {
        case CMD_ANTI_RECOIL:     antiRecoil(enable);              break;
        case CMD_NO_SPREAD:       noSpread(enable);                break;
        case CMD_RAPID_FIRE:      rapidFire(enable);               break;
        case CMD_AIM_ASSIST:      aimAssist(enable);               break;
        case CMD_WIDE_POV:        widePov(enable);                 break;
        case CMD_ESP:             ESP::setEnabled(enable);         break;
        case CMD_HEADSHOT_ASSIST: ESP::setHeadshotAssist(enable);  break;
        default: LOG("Unknown cmd: %d", cmd);
    }
}
