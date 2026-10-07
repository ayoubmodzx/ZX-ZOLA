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

// Risk feature state
static std::atomic<bool>  g_speedHack{false};
static std::atomic<float> g_speedMult{1.f};      // 1.0 = normal, up to 3.0
static std::atomic<bool>  g_highJump{false};
static std::atomic<float> g_jumpMult{1.f};
static std::atomic<bool>  g_vehicleSpeed{false};
static std::atomic<float> g_vehicleMult{1.f};
static std::atomic<bool>  g_rapidFireRisk{false};
static std::atomic<float> g_rapidIntensity{0.02f}; // fire interval: lower = faster

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
    if (g_rapidFireRisk && g_cls.offFireRate > 0)
        Il2Cpp::writeField<float>(self, g_cls.offFireRate,
            g_rapidIntensity.load(std::memory_order_relaxed));
    if (!g_origFire) return;
    g_origFire(self, a, b);
}

// ─────────────────────────────────────────────────────────────────────────────
// Risk: speed + jump hooks via IL2CPP move-speed / jump-force fields
// ─────────────────────────────────────────────────────────────────────────────

struct RiskClasses {
    Il2CppClass *playerMove  = nullptr;
    int32_t offMoveSpeed     = -1;
    int32_t offJumpForce     = -1;
    Il2CppClass *vehicleCls  = nullptr;
    int32_t offVehicleSpeed  = -1;
};
static RiskClasses g_risk;

static void discoverRiskClasses() {
    static const char *kMoveNames[][2] = {
        {"moveSpeed", "jumpForce"}, {"MoveSpeed", "JumpForce"},
        {"m_moveSpeed", "m_jumpForce"}, {"speed", "jumpHeight"},
        {nullptr, nullptr}
    };
    for (int i = 0; kMoveNames[i][0] && !g_risk.playerMove; i++) {
        FieldPattern pat[] = {
            {kMoveNames[i][0], &g_risk.offMoveSpeed},
            {kMoveNames[i][1], &g_risk.offJumpForce},
        };
        g_risk.playerMove = findClassByFields(pat, 2, "playerMove");
    }

    static const char *kVeh[][2] = {
        {"maxSpeed","enginePower"}, {"MaxSpeed","EnginePower"},
        {"vehicleSpeed","vehicleAccel"}, {nullptr, nullptr}
    };
    for (int i = 0; kVeh[i][0] && !g_risk.vehicleCls; i++) {
        FieldPattern pat[] = {
            {kVeh[i][0], &g_risk.offVehicleSpeed},
            {kVeh[i][1], nullptr},
        };
        g_risk.vehicleCls = findClassByFields(pat, 2, "vehicleCls");
    }
}

using FnMoveUpdate = void(*)(void*);
static FnMoveUpdate g_origMoveUpdate = nullptr;
static void hookMoveUpdate(void *self) {
    if (g_speedHack && g_risk.offMoveSpeed > 0) {
        float base = Il2Cpp::readField<float>(self, g_risk.offMoveSpeed);
        float target = base * g_speedMult.load(std::memory_order_relaxed);
        Il2Cpp::writeField<float>(self, g_risk.offMoveSpeed, target);
    }
    if (g_highJump && g_risk.offJumpForce > 0) {
        float base = Il2Cpp::readField<float>(self, g_risk.offJumpForce);
        float target = base * g_jumpMult.load(std::memory_order_relaxed);
        Il2Cpp::writeField<float>(self, g_risk.offJumpForce, target);
    }
    if (g_origMoveUpdate) g_origMoveUpdate(self);
}

static void hookVehicleUpdate(void *self) { // patched in separately
    if (g_vehicleSpeed && g_risk.offVehicleSpeed > 0) {
        float base = Il2Cpp::readField<float>(self, g_risk.offVehicleSpeed);
        Il2Cpp::writeField<float>(self, g_risk.offVehicleSpeed,
            base * g_vehicleMult.load(std::memory_order_relaxed));
    }
}

static void hookRiskFeatures() {
    discoverRiskClasses();
    if (g_risk.playerMove) {
        static const char *kUpd[] = {"Update","FixedUpdate","Move","OnMove",nullptr};
        for (const char **mn = kUpd; *mn; mn++) {
            MethodInfo *m = Il2Cpp::getMethod(g_risk.playerMove, *mn, -1);
            if (m && m->methodPointer) {
                void *orig = nullptr;
                DobbyHook(m->methodPointer, (void*)hookMoveUpdate, &orig);
                g_origMoveUpdate = (FnMoveUpdate)orig;
                LOG("Hooked move/jump: %s @ %p", *mn, m->methodPointer);
                break;
            }
        }
    }
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
    hookRiskFeatures();
}

// ─────────────────────────────────────────────────────────────────────────────
// Feature implementations
// ─────────────────────────────────────────────────────────────────────────────

static void antiRecoil(bool on) {
    g_noRecoil = on;
    // hookFireWeapon writes correct per-instance offsets on every fire event.
    // setStaticFloat on these fields is wrong (they are instance fields) and
    // triggers IL2CPP metadata mismatch detectable by anti-cheat.
    LOG("AntiRecoil %s", on ? "ON" : "OFF");
}

static void noSpread(bool on) {
    g_noSpread = on;
    LOG("NoSpread %s", on ? "ON" : "OFF");
}

static void rapidFire(bool on) {
    g_rapidFire = on;
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
    static std::atomic<bool> g_init_done{false};
    if (!g_init_done.exchange(true)) {
        Features::init();
    }

    switch (cmd) {
        case CMD_ANTI_RECOIL:     antiRecoil(enable);              break;
        case CMD_NO_SPREAD:       noSpread(enable);                break;
        case CMD_RAPID_FIRE:      rapidFire(enable);               break;
        case CMD_AIM_ASSIST:      aimAssist(enable);               break;
        case CMD_WIDE_POV:        widePov(enable);                 break;
        case CMD_ESP:             ESP::setEnabled(enable);         break;
        case CMD_HEADSHOT_ASSIST: ESP::setHeadshotAssist(enable);  break;
        case CMD_SPEED_HACK:
            g_speedHack = enable;
            if (!enable) g_speedMult.store(1.f, std::memory_order_relaxed);
            LOG("SpeedHack %s", enable ? "ON" : "OFF");
            break;
        case CMD_HIGH_JUMP:
            g_highJump = enable;
            if (!enable) g_jumpMult.store(1.f, std::memory_order_relaxed);
            LOG("HighJump %s", enable ? "ON" : "OFF");
            break;
        case CMD_VEHICLE_SPEED:
            g_vehicleSpeed = enable;
            if (!enable) g_vehicleMult.store(1.f, std::memory_order_relaxed);
            LOG("VehicleSpeed %s", enable ? "ON" : "OFF");
            break;
        case CMD_RAPID_FIRE_RISK:
            g_rapidFireRisk = enable;
            if (!enable) g_rapidIntensity.store(0.02f, std::memory_order_relaxed);
            LOG("RapidFireRisk %s", enable ? "ON" : "OFF");
            break;
        default: LOG("Unknown cmd: %d", cmd);
    }
}

void Features::applyIntensity(int cmd, int intensity) {
    // intensity 0-100 → scale feature multiplier
    float t = intensity / 100.f; // 0.0 to 1.0
    switch (cmd) {
        case CMD_SPEED_HACK:
            // 0% = normal (1.0), 100% = 3x speed
            g_speedMult.store(1.f + t * 2.f, std::memory_order_relaxed);
            break;
        case CMD_HIGH_JUMP:
            // 0% = normal (1.0), 100% = 4x jump
            g_jumpMult.store(1.f + t * 3.f, std::memory_order_relaxed);
            break;
        case CMD_VEHICLE_SPEED:
            // 0% = normal (1.0), 100% = 3.5x vehicle speed
            g_vehicleMult.store(1.f + t * 2.5f, std::memory_order_relaxed);
            break;
        case CMD_RAPID_FIRE_RISK:
            // 0% = stock interval, 100% = near-instant (0.001)
            // fireRate interval: lower = faster. 0.02 is stock
            g_rapidIntensity.store(0.02f - t * 0.019f, std::memory_order_relaxed);
            break;
        default: break;
    }
}
