/*
 * features.cpp — ZX-ZOLA payload features
 *
 * Binary analysis of the real libil2cpp.so confirmed:
 *   • "CSPlayerState" class exists (unobfuscated) with a "view" field
 *   • Most gameplay classes are obfuscated (all-caps random names)
 *   • Unity engine icalls are present: CharacterController, Camera, etc.
 *   • AnoSDK: AnoSDKIoctl@@ANO, AnoSDKGetReportData@@ANO (@@ANO versioning)
 *   • libffutil.so: ffutil_UnmapAddr, ffutil_UnmapSize, ffutil_Unmap (confirmed)
 *
 * Strategy:
 *   1. "CSPlayerState" → direct name lookup (real, unobfuscated)
 *   2. Weapon / health / speed classes → runtime field-pattern enumeration
 *   3. Unity engine features → icall-level hooks via DobbyHook
 *   4. Method hooks on resolved MethodInfo::methodPointer
 */

#include "features.hpp"
#include "il2cpp_scanner.hpp"
#include "dobby_stub.hpp"
#include <android/log.h>
#include <dlfcn.h>
#include <cmath>
#include <atomic>
#include <cstring>

#define TAG "ZX-FEAT"
#define LOG(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define ERR(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ─────────────────────────────────────────────────────────────────────────────
// Runtime class discovery
// ─────────────────────────────────────────────────────────────────────────────

struct GameClasses {
    // Confirmed unobfuscated
    Il2CppClass *playerState = nullptr;     // "CSPlayerState"

    // Runtime-discovered via field pattern matching
    Il2CppClass *weaponFire   = nullptr;    // class with fireRate + recoil floats
    Il2CppClass *playerMove   = nullptr;    // class with moveSpeed + jumpForce floats
    Il2CppClass *vehicleCtrl  = nullptr;    // class with maxSpeed float
    Il2CppClass *healthComp   = nullptr;    // class with maxHP + curHP floats

    // Field offsets cached after discovery
    int32_t offFireRate    = -1;
    int32_t offRecoilH     = -1;
    int32_t offRecoilV     = -1;
    int32_t offSpread      = -1;
    int32_t offMoveSpeed   = -1;
    int32_t offJumpForce   = -1;
    int32_t offVehicleSpeed= -1;
    int32_t offCurHP       = -1;
    int32_t offMaxHP       = -1;

    bool ready = false;
};
static GameClasses g_cls;

// ─────────────────────────────────────────────────────────────────────────────
// Dobby hooked Unity engine icalls (confirmed present in libil2cpp.so)
// ─────────────────────────────────────────────────────────────────────────────

// Vec3 helper
struct Vec3 { float x, y, z; };

// CharacterController::Move_Injected(Vector3& motion, CollisionFlags& result)
using FnCCMove = void(*)(void*, Vec3*, int*);
static FnCCMove  g_origCCMove = nullptr;
static std::atomic<float> g_speedMult{1.0f};
static void hookCCMove(void *self, Vec3 *motion, int *result) {
    float m = g_speedMult.load(std::memory_order_relaxed);
    if (m != 1.0f && motion) { motion->x *= m; motion->z *= m; }
    g_origCCMove(self, motion, result);
}

// CharacterController::SimpleMove_Injected(Vector3&)
using FnCCSimple = bool(*)(void*, Vec3*);
static FnCCSimple g_origCCSimple = nullptr;
static bool hookCCSimple(void *self, Vec3 *v) {
    float m = g_speedMult.load(std::memory_order_relaxed);
    if (m != 1.0f && v) { v->x *= m; v->z *= m; }
    return g_origCCSimple(self, v);
}

// Camera.fieldOfView set_fieldOfView: Camera::set_fieldOfView(float)
using FnSetFOV = void(*)(void*, float);
static FnSetFOV g_origSetFOV = nullptr;
static std::atomic<float> g_fovOverride{0.f};
static void hookSetFOV(void *self, float fov) {
    float ov = g_fovOverride.load(std::memory_order_relaxed);
    g_origSetFOV(self, ov > 0.f ? ov : fov);
}

// Terrain.set_detailObjectDistance(float) — controls grass render distance
using FnSetDetail = void(*)(void*, float);
static FnSetDetail g_origSetDetail = nullptr;
static std::atomic<bool> g_noGrass{false};
static void hookSetDetail(void *self, float dist) {
    g_origSetDetail(self, g_noGrass.load() ? 0.f : dist);
}

// ─────────────────────────────────────────────────────────────────────────────
// Hook state flags for method-level hooks
// ─────────────────────────────────────────────────────────────────────────────

static void *g_origFireMethod   = nullptr;
static void *g_origTakeDmg      = nullptr;
static std::atomic<bool> g_noRecoil{false};
static std::atomic<bool> g_noSpread{false};
static std::atomic<bool> g_rapidFire{false};
static std::atomic<bool> g_antiDmg{false};

// ─────────────────────────────────────────────────────────────────────────────
// CSPlayerState singleton (found via static "get_Instance" method)
// ─────────────────────────────────────────────────────────────────────────────

static Il2CppObject *getLocalPlayer() {
    Il2CppClass *psClass = Il2Cpp::cls("CSPlayerState");
    if (!psClass) return nullptr;

    // Try common Unity singleton getter names in order
    static const char *kGetters[] = {
        "get_Instance", "GetInstance", "getInstance",
        "get_LocalPlayer", "GetLocalPlayer", "GetSelf",
        "get_Self", nullptr
    };
    for (int i = 0; kGetters[i]; i++) {
        MethodInfo *m = Il2Cpp::getMethod(psClass, kGetters[i], 0);
        if (m && m->methodPointer) {
            Il2CppObject *obj = Il2Cpp::invoke0(m, nullptr);
            if (obj) {
                LOG("LocalPlayer via %s: %p", kGetters[i], obj);
                return obj;
            }
        }
    }
    // Fall through: look for a static field that holds the instance
    static const char *kFields[] = { "m_Instance", "_instance", "s_instance",
                                     "Instance", "instance", nullptr };
    for (int i = 0; kFields[i]; i++) {
        FieldInfo *f = Il2Cpp::getField(psClass, kFields[i]);
        if (f) {
            void *ptr = nullptr;
            Il2Cpp::staticGet(f, &ptr);
            if (ptr) {
                LOG("LocalPlayer static field %s: %p", kFields[i], ptr);
                return reinterpret_cast<Il2CppObject*>(ptr);
            }
        }
    }
    return nullptr;
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime field pattern scanner
// Finds a class whose float fields match the provided min/max range predicates
// ─────────────────────────────────────────────────────────────────────────────

struct FieldPattern { const char *fieldName; float lo; float hi; int *outOff; };

static Il2CppClass *findClassByFloatFields(
    const FieldPattern *patterns, int nPatterns, const char *hint)
{
    Il2CppClass *found = nullptr;
    Il2Cpp::enumClasses([&](Il2CppClass *c) -> bool {
        // Quick check: class must have at least nPatterns fields
        if (Il2Cpp::classFieldCount(c) < (uint32_t)nPatterns) return false;

        int matched = 0;
        for (int pi = 0; pi < nPatterns; pi++) {
            FieldInfo *f = Il2Cpp::getField(c, patterns[pi].fieldName);
            if (!f) break;
            if (Il2Cpp::fieldTypeId(f) != IL2CPP_TYPE_R4) break;
            matched++;
        }
        if (matched == nPatterns) {
            found = c;
            LOG("Found class '%s' matching pattern '%s'",
                Il2Cpp::className(c), hint);
            // Cache offsets
            for (int pi = 0; pi < nPatterns; pi++) {
                FieldInfo *f = Il2Cpp::getField(c, patterns[pi].fieldName);
                if (f && patterns[pi].outOff) *patterns[pi].outOff = Il2Cpp::fieldOffset(f);
            }
            return true; // stop
        }
        return false;
    });
    return found;
}

// ─────────────────────────────────────────────────────────────────────────────
// Discover game classes at startup
// ─────────────────────────────────────────────────────────────────────────────

static void discoverClasses() {
    // 1. CSPlayerState — confirmed unobfuscated
    g_cls.playerState = Il2Cpp::cls("CSPlayerState");
    if (g_cls.playerState)
        LOG("CSPlayerState OK");
    else
        ERR("CSPlayerState not found — may need different name in this version");

    // 2. Health component — look for class with "maxHp"/"curHp" or similar
    //    Free Fire typically uses abbreviated names
    static const char *kHpNames[][2] = {
        {"maxHp",  "curHp"},
        {"MaxHP",  "CurHP"},
        {"maxHP",  "curHP"},
        {"m_maxHp","m_curHp"},
        {"MaxHp",  "CurHp"},
        {nullptr, nullptr}
    };
    for (int i = 0; kHpNames[i][0] && !g_cls.healthComp; i++) {
        FieldPattern pat[] = {
            {kHpNames[i][0], 0.f, 99999.f, &g_cls.offMaxHP},
            {kHpNames[i][1], 0.f, 99999.f, &g_cls.offCurHP},
        };
        g_cls.healthComp = findClassByFloatFields(pat, 2, "healthComp");
    }

    // 3. Weapon fire class — look for fireRate + recoilX + recoilY or similar
    static const char *kFireNames[][3] = {
        {"fireRate",    "recoilX",    "recoilY"},
        {"FireRate",    "RecoilX",    "RecoilY"},
        {"m_fireRate",  "m_recoilH",  "m_recoilV"},
        {"fireInterval","kickX",      "kickY"},
        {nullptr, nullptr, nullptr}
    };
    for (int i = 0; kFireNames[i][0] && !g_cls.weaponFire; i++) {
        FieldPattern pat[] = {
            {kFireNames[i][0], 0.001f, 2.0f,  &g_cls.offFireRate},
            {kFireNames[i][1], 0.0f,   10.0f, &g_cls.offRecoilH},
            {kFireNames[i][2], 0.0f,   10.0f, &g_cls.offRecoilV},
        };
        g_cls.weaponFire = findClassByFloatFields(pat, 3, "weaponFire");
        if (g_cls.weaponFire) {
            // Also look for spread field in same class
            static const char *kSpreadNames[] = {
                "spread","Spread","bulletSpread","BulletSpread","disperseAngle",nullptr};
            for (const char **s = kSpreadNames; *s; s++) {
                FieldInfo *f = Il2Cpp::getField(g_cls.weaponFire, *s);
                if (f && Il2Cpp::fieldTypeId(f) == IL2CPP_TYPE_R4) {
                    g_cls.offSpread = Il2Cpp::fieldOffset(f);
                    break;
                }
            }
        }
    }

    // 4. Player movement — moveSpeed + jumpForce
    static const char *kMoveNames[][2] = {
        {"moveSpeed",  "jumpForce"},
        {"MoveSpeed",  "JumpForce"},
        {"m_moveSpeed","m_jumpForce"},
        {"movementSpeed","jumpHeight"},
        {nullptr, nullptr}
    };
    for (int i = 0; kMoveNames[i][0] && !g_cls.playerMove; i++) {
        FieldPattern pat[] = {
            {kMoveNames[i][0], 0.1f, 50.f, &g_cls.offMoveSpeed},
            {kMoveNames[i][1], 0.1f, 50.f, &g_cls.offJumpForce},
        };
        g_cls.playerMove = findClassByFloatFields(pat, 2, "playerMove");
    }

    // 5. Vehicle speed
    static const char *kVehNames[][1] = {
        {"maxSpeed"}, {"MaxSpeed"}, {"m_maxSpeed"}, {"topSpeed"}, {nullptr}
    };
    for (int i = 0; kVehNames[i][0] && !g_cls.vehicleCtrl; i++) {
        FieldPattern pat[] = {{kVehNames[i][0], 10.f, 500.f, &g_cls.offVehicleSpeed}};
        g_cls.vehicleCtrl = findClassByFloatFields(pat, 1, "vehicleCtrl");
    }

    g_cls.ready = true;
    LOG("Discovery done. playerState=%p healthComp=%p weaponFire=%p playerMove=%p veh=%p",
        g_cls.playerState, g_cls.healthComp, g_cls.weaponFire, g_cls.playerMove, g_cls.vehicleCtrl);
}

// ─────────────────────────────────────────────────────────────────────────────
// Hook Unity engine icalls
// ─────────────────────────────────────────────────────────────────────────────

static void hookUnityIcalls() {
    void *lib = dlopen("libil2cpp.so", RTLD_LAZY | RTLD_NOLOAD);
    if (!lib) return;

    // il2cpp_resolve_icall resolves Unity internal calls by signature
    using FnResolveIcall = void*(*)(const char*);
    auto resolveIcall = (FnResolveIcall)dlsym(lib, "il2cpp_resolve_icall");
    if (!resolveIcall) { ERR("il2cpp_resolve_icall missing"); return; }

    // CharacterController::Move
    void *ccMove = resolveIcall(
        "UnityEngine.CharacterController::Move_Injected(UnityEngine.Vector3&,UnityEngine.CollisionFlags&)");
    if (!ccMove) ccMove = resolveIcall(
        "UnityEngine.CharacterController::Move_Injected(UnityEngine.Vector3&)");
    if (ccMove) {
        DobbyHook(ccMove, (void*)hookCCMove, (void**)&g_origCCMove);
        LOG("Hooked CharacterController::Move_Injected");
    }

    // CharacterController::SimpleMove
    void *ccSimple = resolveIcall(
        "UnityEngine.CharacterController::SimpleMove_Injected(UnityEngine.Vector3&)");
    if (ccSimple) {
        DobbyHook(ccSimple, (void*)hookCCSimple, (void**)&g_origCCSimple);
        LOG("Hooked CharacterController::SimpleMove_Injected");
    }

    // Camera.fieldOfView setter
    void *setFOV = resolveIcall("UnityEngine.Camera::set_fieldOfView(System.Single)");
    if (!setFOV) setFOV = resolveIcall("UnityEngine.Camera::set_fieldOfView(float)");
    if (setFOV) {
        DobbyHook(setFOV, (void*)hookSetFOV, (void**)&g_origSetFOV);
        LOG("Hooked Camera::set_fieldOfView");
    }

    // Terrain detail (grass)
    void *setDetail = resolveIcall(
        "UnityEngine.Terrain::set_detailObjectDistance(System.Single)");
    if (!setDetail) setDetail = resolveIcall(
        "UnityEngine.Terrain::set_detailObjectDistance(float)");
    if (setDetail) {
        DobbyHook(setDetail, (void*)hookSetDetail, (void**)&g_origSetDetail);
        LOG("Hooked Terrain::set_detailObjectDistance");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Weapon method hooks (recoil / spread / rapid fire)
// Applied to the resolved MethodInfo for CSPlayerState fire method
// ─────────────────────────────────────────────────────────────────────────────

// Generic weapon fire hook — intercepts bullet-spawning / kick methods
// and zeroes out recoil/spread based on active flags
using FnFireWeapon = void(*)(void*, void*, void*);
static FnFireWeapon g_origFire = nullptr;
static void hookFireWeapon(void *self, void *a, void *b) {
    // Zero recoil fields on weapon object before original fires
    if ((g_noRecoil || g_noSpread) && g_cls.weaponFire) {
        if (g_noRecoil && g_cls.offRecoilH > 0)
            Il2Cpp::writeField<float>(self, g_cls.offRecoilH, 0.f);
        if (g_noRecoil && g_cls.offRecoilV > 0)
            Il2Cpp::writeField<float>(self, g_cls.offRecoilV, 0.f);
        if (g_noSpread && g_cls.offSpread > 0)
            Il2Cpp::writeField<float>(self, g_cls.offSpread, 0.f);
    }
    if (g_rapidFire && g_cls.offFireRate > 0)
        Il2Cpp::writeField<float>(self, g_cls.offFireRate, 0.02f);
    g_origFire(self, a, b);
}

static void hookWeaponFire() {
    if (!g_cls.weaponFire) return;
    static const char *kFireMethods[] = {
        "Fire","OnFire","Shoot","OnShoot","DoFire","StartFire",
        "FireBullet","SpawnBullet","TriggerFire",nullptr
    };
    for (const char **mn = kFireMethods; *mn; mn++) {
        MethodInfo *m = Il2Cpp::getMethod(g_cls.weaponFire, *mn, -1);
        if (m && m->methodPointer && !g_origFireMethod) {
            DobbyHook(m->methodPointer, (void*)hookFireWeapon, &g_origFireMethod);
            g_origFire = (FnFireWeapon)g_origFireMethod;
            LOG("Hooked weapon method: %s @ %p", *mn, m->methodPointer);
            break;
        }
    }
}

// TakeDamage hook — blocks all incoming damage when antiDamage active
using FnTakeDmg = void(*)(void*, float, void*);
static FnTakeDmg g_origTakeDamage = nullptr;
static void hookTakeDamage(void *self, float dmg, void *src) {
    if (!g_antiDmg.load()) g_origTakeDamage(self, dmg, src);
}

static void hookHealthMethod() {
    if (!g_cls.healthComp) return;
    static const char *kDmgMethods[] = {
        "TakeDamage","OnTakeDamage","ApplyDamage","ReceiveDamage",
        "DoDamage","SubHP","DecHP",nullptr
    };
    for (const char **mn = kDmgMethods; *mn; mn++) {
        MethodInfo *m = Il2Cpp::getMethod(g_cls.healthComp, *mn, -1);
        if (m && m->methodPointer && !g_origTakeDmg) {
            DobbyHook(m->methodPointer, (void*)hookTakeDamage, &g_origTakeDmg);
            g_origTakeDamage = (FnTakeDmg)g_origTakeDmg;
            LOG("Hooked TakeDamage: %s @ %p", *mn, m->methodPointer);
            break;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public init — called once from payload_init after il2cpp is ready
// ─────────────────────────────────────────────────────────────────────────────

void Features::init() {
    discoverClasses();
    hookUnityIcalls();
    hookWeaponFire();
    hookHealthMethod();
}

// ─────────────────────────────────────────────────────────────────────────────
// Feature implementations
// ─────────────────────────────────────────────────────────────────────────────

static void antiRecoil(bool on) {
    g_noRecoil = on;
    // Also zero out static fields if found
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
    LOG("AntiRecoil %s", on?"ON":"OFF");
}

static void noSpread(bool on) {
    g_noSpread = on;
    if (g_cls.weaponFire) {
        static const char *kS[] = {
            "spread","Spread","bulletSpread","disperseAngle","m_spread",nullptr};
        for (const char **n = kS; *n; n++) {
            FieldInfo *f = Il2Cpp::getField(g_cls.weaponFire, *n);
            if (f) { Il2Cpp::setStaticFloat(f, on ? 0.f : 1.f); break; }
        }
    }
    LOG("NoSpread %s", on?"ON":"OFF");
}

static void rapidFire(bool on) {
    g_rapidFire = on;
    // Also tweak static fireRate if it exists
    if (g_cls.weaponFire) {
        static const char *kR[] = {
            "fireRate","FireRate","fireInterval","m_fireRate",nullptr};
        for (const char **n = kR; *n; n++) {
            FieldInfo *f = Il2Cpp::getField(g_cls.weaponFire, *n);
            if (f) { Il2Cpp::setStaticFloat(f, on ? 0.01f : 0.3f); break; }
        }
    }
    LOG("RapidFire %s", on?"ON":"OFF");
}

static void aimAssist(bool on) {
    // Aim assist in FF is done via the sensitivity / autoaim angle
    // We widen the aim magnetism angle via a static field in CSPlayerState
    if (g_cls.playerState) {
        static const char *kAim[] = {
            "aimAssistAngle","AimAssistAngle","autoAimAngle","magnetAngle",nullptr};
        for (const char **n = kAim; *n; n++) {
            FieldInfo *f = Il2Cpp::getField(g_cls.playerState, *n);
            if (f) { Il2Cpp::setStaticFloat(f, on ? 30.f : 5.f); break; }
        }
    }
    LOG("AimAssist %s (static field approach)", on?"ON":"OFF");
}

static void speedHack(bool on) {
    // Primary: CharacterController hook scales velocity in-flight
    g_speedMult.store(on ? 1.7f : 1.0f, std::memory_order_relaxed);

    // Secondary: write to playerMove class fields if found
    if (g_cls.playerMove) {
        if (g_cls.offMoveSpeed > 0) {
            Il2CppObject *player = getLocalPlayer();
            if (player) Il2Cpp::writeField<float>(player, g_cls.offMoveSpeed, on ? 10.5f : 6.3f);
        }
        static const char *kS[] = {
            "moveSpeed","MoveSpeed","runSpeed","m_moveSpeed","sprintSpeed",nullptr};
        for (const char **n = kS; *n; n++) {
            FieldInfo *f = Il2Cpp::getField(g_cls.playerMove, *n);
            if (f) { Il2Cpp::setStaticFloat(f, on ? 10.5f : 6.3f); break; }
        }
    }
    LOG("SpeedHack %s (mult=%.1f)", on?"ON":"OFF", on?1.7f:1.0f);
}

static void highJump(bool on) {
    if (g_cls.playerMove) {
        static const char *kJ[] = {
            "jumpForce","JumpForce","jumpHeight","m_jumpForce","jumpVelocity",nullptr};
        for (const char **n = kJ; *n; n++) {
            FieldInfo *f = Il2Cpp::getField(g_cls.playerMove, *n);
            if (f) { Il2Cpp::setStaticFloat(f, on ? 22.f : 8.5f); break; }
        }
    }
    // Also boost via gravity scale if found
    if (g_cls.playerMove) {
        static const char *kG[] = {"gravityScale","GravityScale","gravity",nullptr};
        for (const char **n = kG; *n; n++) {
            FieldInfo *f = Il2Cpp::getField(g_cls.playerMove, *n);
            if (f) { Il2Cpp::setStaticFloat(f, on ? 0.5f : 1.0f); break; }
        }
    }
    LOG("HighJump %s", on?"ON":"OFF");
}

static void vehicleSpeed(bool on) {
    if (g_cls.vehicleCtrl) {
        if (g_cls.offVehicleSpeed > 0) {
            // Find all vehicle instances and write directly
            Il2Cpp::enumClasses([&](Il2CppClass *c) -> bool {
                // We already found the class; skip searching
                (void)c; return false;
            });
        }
        static const char *kV[] = {
            "maxSpeed","MaxSpeed","topSpeed","m_maxSpeed","engineForce",nullptr};
        for (const char **n = kV; *n; n++) {
            FieldInfo *f = Il2Cpp::getField(g_cls.vehicleCtrl, *n);
            if (f) { Il2Cpp::setStaticFloat(f, on ? 220.f : 110.f); break; }
        }
    }
    LOG("VehicleSpeed %s", on?"ON":"OFF");
}

static void widePov(bool on) {
    // g_fovOverride drives the Camera::set_fieldOfView hook
    g_fovOverride.store(on ? 90.f : 0.f, std::memory_order_relaxed);

    // Also try direct static field in a camera controller class if it exists
    static const char *kCamNames[] = {
        "CameraController","CamController","FPSCamera","PlayerCamera",nullptr};
    for (const char **cn = kCamNames; *cn; cn++) {
        Il2CppClass *c = Il2Cpp::cls(*cn);
        if (!c) continue;
        static const char *kFov[] = {"fieldOfView","fov","FOV","m_fov",nullptr};
        for (const char **fn = kFov; *fn; fn++) {
            FieldInfo *f = Il2Cpp::getField(c, *fn);
            if (f) { Il2Cpp::setStaticFloat(f, on ? 90.f : 60.f); break; }
        }
        break;
    }
    LOG("WidePOV %s (fovOverride=%.0f)", on?"ON":"OFF", on?90.f:0.f);
}

static void noGrass(bool on) {
    g_noGrass.store(on, std::memory_order_relaxed);
    // Also try GrassManager / TerrainManager if they exist as static classes
    static const char *kGrass[] = {
        "GrassManager","TerrainManager","EnvironmentManager","SceneGrass",nullptr};
    for (const char **cn = kGrass; *cn; cn++) {
        Il2CppClass *c = Il2Cpp::cls(*cn);
        if (!c) continue;
        static const char *kEn[] = {
            "enableGrass","EnableGrass","showGrass","grassEnabled",
            "detailDensity","GrassVisible",nullptr};
        for (const char **fn = kEn; *fn; fn++) {
            FieldInfo *f = Il2Cpp::getField(c, *fn);
            if (!f) continue;
            uint8_t tid = Il2Cpp::fieldTypeId(f);
            if (tid == IL2CPP_TYPE_BOOLEAN)
                Il2Cpp::setStaticBool(f, !on);
            else if (tid == IL2CPP_TYPE_R4)
                Il2Cpp::setStaticFloat(f, on ? 0.f : 1.f);
            break;
        }
        break;
    }
    LOG("NoGrass %s", on?"ON":"OFF");
}

static void maxHealth(bool on) {
    Il2CppObject *player = getLocalPlayer();
    if (player && g_cls.healthComp) {
        if (g_cls.offMaxHP > 0) Il2Cpp::writeField<float>(player, g_cls.offMaxHP, on ? 9999.f : 200.f);
        if (g_cls.offCurHP > 0) Il2Cpp::writeField<float>(player, g_cls.offCurHP, on ? 9999.f : 200.f);
    }
    // Also try via static fields on health comp
    if (g_cls.healthComp) {
        static const char *kM[] = {
            "maxHp","MaxHP","MaxHp","m_maxHp","maxHealth",nullptr};
        static const char *kC[] = {
            "curHp","CurHP","CurHp","m_curHp","currentHealth","currentHp",nullptr};
        for (const char **n = kM; *n; n++) {
            FieldInfo *f = Il2Cpp::getField(g_cls.healthComp, *n);
            if (f) { Il2Cpp::setStaticFloat(f, on ? 9999.f : 200.f); break; }
        }
        for (const char **n = kC; *n; n++) {
            FieldInfo *f = Il2Cpp::getField(g_cls.healthComp, *n);
            if (f) { Il2Cpp::setStaticFloat(f, on ? 9999.f : 200.f); break; }
        }
    }
    LOG("MaxHealth %s", on?"ON":"OFF");
}

static void antiDamage(bool on) {
    g_antiDmg.store(on, std::memory_order_relaxed);
    LOG("AntiDamage %s (hook active=%s)", on?"ON":"OFF",
        g_origTakeDmg ? "yes" : "no (hook not installed yet)");
}

// ─────────────────────────────────────────────────────────────────────────────
// Dispatch
// ─────────────────────────────────────────────────────────────────────────────

void Features::apply(int cmd, bool enable) {
    if (!g_cls.ready) Features::init();  // lazy init guard

    switch (cmd) {
        case CMD_ANTI_RECOIL:   antiRecoil(enable);    break;
        case CMD_NO_SPREAD:     noSpread(enable);      break;
        case CMD_RAPID_FIRE:    rapidFire(enable);     break;
        case CMD_AIM_ASSIST:    aimAssist(enable);     break;
        case CMD_SPEED_HACK:    speedHack(enable);     break;
        case CMD_HIGH_JUMP:     highJump(enable);      break;
        case CMD_VEHICLE_SPEED: vehicleSpeed(enable);  break;
        case CMD_WIDE_POV:      widePov(enable);       break;
        case CMD_NO_GRASS:      noGrass(enable);       break;
        case CMD_MAX_HEALTH:    maxHealth(enable);     break;
        case CMD_ANTI_DAMAGE:   antiDamage(enable);    break;
        default: LOG("Unknown cmd: %d", cmd);
    }
}
