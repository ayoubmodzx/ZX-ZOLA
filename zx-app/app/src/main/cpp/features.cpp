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

// Aim system state
static std::atomic<bool>  g_aimEnabled{false};
static std::atomic<int>   g_aimBone{0};    // 0=AI, 1=NECK, 2=HEAD
static std::atomic<float> g_aimFov{35.f};  // degrees
static std::atomic<float> g_aimSmooth{0.6f}; // 0.0-1.0

// Risk feature state
static std::atomic<bool>  g_speedHack{false};
static std::atomic<float> g_speedMult{1.f};      // 1.0 = normal, up to 3.0
static std::atomic<bool>  g_highJump{false};
static std::atomic<float> g_jumpMult{1.f};
static std::atomic<bool>  g_vehicleSpeed{false};
static std::atomic<float> g_vehicleMult{1.f};
static std::atomic<bool>  g_rapidFireRisk{false};
static std::atomic<float> g_rapidIntensity{0.02f}; // fire interval: lower = faster
static std::atomic<bool>  g_noGrass{false};
static std::atomic<bool>  g_antiDamage{false};
static std::atomic<float> g_damageMult{0.5f}; // 1.0=normal, 0.0=immune

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

// ─────────────────────────────────────────────────────────────────────────────
// Aim system: bone-targeted magnetism hook on Camera/AimController
// ─────────────────────────────────────────────────────────────────────────────

struct AimClasses {
    Il2CppClass *aimCtrl    = nullptr;
    Il2CppClass *boneCtrl   = nullptr;
    int32_t offAimAngle     = -1;
    int32_t offAimSmooth    = -1;
    int32_t offBoneIndex    = -1;
};
static AimClasses g_aim;

static void discoverAimClasses() {
    static const char *kAim[] = {
        "AimController","AimAssist","AimAssistController","AutoAim",
        "PlayerAimHelper","AimHelper","AimSystem", nullptr
    };
    for (const char **cn = kAim; *cn && !g_aim.aimCtrl; cn++) {
        Il2CppClass *c = Il2Cpp::cls(*cn);
        if (!c) continue;
        g_aim.aimCtrl = c;
        static const char *kAngle[] = {"aimAngle","assistAngle","magnetAngle","lockAngle",nullptr};
        for (const char **fn = kAngle; *fn; fn++) {
            FieldInfo *f = Il2Cpp::getField(c, *fn);
            if (f) { g_aim.offAimAngle = Il2Cpp::fieldOffset(f); break; }
        }
        static const char *kSmooth[] = {"smoothFactor","aimSmooth","smoothSpeed","lerpSpeed",nullptr};
        for (const char **fn = kSmooth; *fn; fn++) {
            FieldInfo *f = Il2Cpp::getField(c, *fn);
            if (f) { g_aim.offAimSmooth = Il2Cpp::fieldOffset(f); break; }
        }
        static const char *kBone[] = {"boneIndex","targetBone","aimBone","targetBoneIndex",nullptr};
        for (const char **fn = kBone; *fn; fn++) {
            FieldInfo *f = Il2Cpp::getField(c, *fn);
            if (f) { g_aim.offBoneIndex = Il2Cpp::fieldOffset(f); break; }
        }
    }
}

using FnAimUpdate = void(*)(void*);
static FnAimUpdate g_origAimUpdate = nullptr;

// Bone index map: FF uses HumanBodyBones enum
// HEAD=5, NECK=4, CHEST=6 — approximate; game-specific offsets vary
static constexpr int kBoneHead  = 5;
static constexpr int kBoneNeck  = 4;
static constexpr int kBoneChest = 6; // AI default: chest → smoothest tracking

static void hookAimUpdate(void *self) {
    if (g_aimEnabled) {
        float fov    = g_aimFov.load(std::memory_order_relaxed);
        float smooth = g_aimSmooth.load(std::memory_order_relaxed);
        int   bone   = g_aimBone.load(std::memory_order_relaxed);

        if (g_aim.offAimAngle  > 0) Il2Cpp::writeField<float>(self, g_aim.offAimAngle, fov);
        if (g_aim.offAimSmooth > 0) Il2Cpp::writeField<float>(self, g_aim.offAimSmooth, smooth);
        if (g_aim.offBoneIndex > 0) {
            int boneId = (bone == 2) ? kBoneHead
                       : (bone == 1) ? kBoneNeck
                       :               kBoneChest;
            Il2Cpp::writeField<int>(self, g_aim.offBoneIndex, boneId);
        }
    }
    if (g_origAimUpdate) g_origAimUpdate(self);
}

static void hookAimSystem() {
    discoverAimClasses();
    if (!g_aim.aimCtrl) return;
    static const char *kUpd[] = {"Update","LateUpdate","OnAimUpdate","Tick",nullptr};
    for (const char **mn = kUpd; *mn; mn++) {
        MethodInfo *m = Il2Cpp::getMethod(g_aim.aimCtrl, *mn, -1);
        if (m && m->methodPointer) {
            void *orig = nullptr;
            DobbyHook(m->methodPointer, (void*)hookAimUpdate, &orig);
            g_origAimUpdate = (FnAimUpdate)orig;
            LOG("Hooked aim: %s @ %p", *mn, m->methodPointer);
            break;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// No Grass: null the grass renderer's draw call
// ─────────────────────────────────────────────────────────────────────────────

using FnGrassDraw = void(*)(void*);
static FnGrassDraw g_origGrassDraw = nullptr;
static void hookGrassDraw(void *self) {
    if (!g_noGrass && g_origGrassDraw) g_origGrassDraw(self);
    // when g_noGrass=true: skip draw call entirely → grass invisible
}

static void hookNoGrass() {
    static const char *kGrass[] = {
        "GrassRenderer","GrassSystem","TerrainGrass","GrassBatch","GrassManager",nullptr
    };
    for (const char **cn = kGrass; *cn; cn++) {
        Il2CppClass *c = Il2Cpp::cls(*cn);
        if (!c) continue;
        static const char *kDraw[] = {"Render","Draw","DrawGrass","OnRender","DrawBatch",nullptr};
        for (const char **mn = kDraw; *mn; mn++) {
            MethodInfo *m = Il2Cpp::getMethod(c, *mn, -1);
            if (m && m->methodPointer) {
                void *orig = nullptr;
                DobbyHook(m->methodPointer, (void*)hookGrassDraw, &orig);
                g_origGrassDraw = (FnGrassDraw)orig;
                LOG("Hooked grass: %s::%s @ %p", *cn, *mn, m->methodPointer);
                return;
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Anti Damage: intercept TakeDamage and scale down incoming value
// ─────────────────────────────────────────────────────────────────────────────

using FnTakeDamage = void(*)(void*, float, void*);
static FnTakeDamage g_origTakeDamage = nullptr;
static void hookTakeDamage(void *self, float dmg, void *info) {
    float d = g_antiDamage
        ? dmg * g_damageMult.load(std::memory_order_relaxed)
        : dmg;
    if (g_origTakeDamage) g_origTakeDamage(self, d, info);
}

static void hookAntiDamage() {
    static const char *kCls[] = {
        "CSPlayerState","PlayerHealth","HealthSystem","PlayerHP","CharacterHealth",nullptr
    };
    for (const char **cn = kCls; *cn; cn++) {
        Il2CppClass *c = Il2Cpp::cls(*cn);
        if (!c) c = g_cls.playerState;
        if (!c) continue;
        static const char *kMeth[] = {
            "TakeDamage","OnTakeDamage","ReceiveDamage","ApplyDamage","HurtPlayer",nullptr
        };
        for (const char **mn = kMeth; *mn; mn++) {
            MethodInfo *m = Il2Cpp::getMethod(c, *mn, -1);
            if (m && m->methodPointer) {
                void *orig = nullptr;
                DobbyHook(m->methodPointer, (void*)hookTakeDamage, &orig);
                g_origTakeDamage = (FnTakeDamage)orig;
                LOG("Hooked damage: %s::%s @ %p", *cn, *mn, m->methodPointer);
                return;
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HEAD bone fix: override the hit-bone ID at damage-processing level.
//
// Writing boneIndex to AimController only moves the magnetism target visually.
// The game's hit registration picks the bone from the PhysicsRaycastHit normal
// (which body part the bullet actually grazed). To guarantee the damage engine
// records a headshot we must intercept the hit-processing call and clamp the
// bone argument to HEAD (Unity HumanBodyBones.Head = 5) whenever HEAD mode is on.
// ─────────────────────────────────────────────────────────────────────────────

// Signature covers the most common patterns seen in FF IL2CPP builds:
//   OnBulletHit(self, hitContext, boneId, damage, extra?)
// We intercept all overloads via separate typed wrappers so we match any arity.

static constexpr int kHumanBoneHead = 5; // Unity HumanBodyBones.Head

// 5-arg variant: (self, ctx, bone, dmg, extra)
using FnHit5 = void(*)(void*, void*, int, float, void*);
static FnHit5 g_origHit5 = nullptr;
static void hookHit5(void *self, void *ctx, int bone, float dmg, void *extra) {
    if (g_aimEnabled && g_aimBone.load(std::memory_order_relaxed) == 2)
        bone = kHumanBoneHead;
    if (g_origHit5) g_origHit5(self, ctx, bone, dmg, extra);
}

// 4-arg variant: (self, ctx, bone, dmg)
using FnHit4 = void(*)(void*, void*, int, float);
static FnHit4 g_origHit4 = nullptr;
static void hookHit4(void *self, void *ctx, int bone, float dmg) {
    if (g_aimEnabled && g_aimBone.load(std::memory_order_relaxed) == 2)
        bone = kHumanBoneHead;
    if (g_origHit4) g_origHit4(self, ctx, bone, dmg);
}

// 3-arg variant: (self, bone, dmg)
using FnHit3 = void(*)(void*, int, float);
static FnHit3 g_origHit3 = nullptr;
static void hookHit3(void *self, int bone, float dmg) {
    if (g_aimEnabled && g_aimBone.load(std::memory_order_relaxed) == 2)
        bone = kHumanBoneHead;
    if (g_origHit3) g_origHit3(self, bone, dmg);
}

static bool g_headBoneHooked = false;

static void hookHeadBoneFix() {
    // Candidate (class, method) pairs — searched in order, first match wins.
    // Free Fire builds are partially obfuscated but these class/method names
    // have stayed stable across multiple patches.
    static const struct { const char *cls; const char *meth; } kTargets[] = {
        {"CSPlayerState",    "OnBulletHit"},
        {"CSPlayerState",    "ProcessHit"},
        {"CSPlayerState",    "TakeHit"},
        {"CSPlayerState",    "OnBulletHitBody"},
        {"BulletHitHandler", "Process"},
        {"BulletHitHandler", "OnHit"},
        {"HitProcessor",     "OnHit"},
        {"HitProcessor",     "Process"},
        {"DamageReceiver",   "OnHit"},
        {"DamageReceiver",   "ProcessHit"},
        {"PlayerDamage",     "OnReceiveDamage"},
        {"PlayerDamage",     "ApplyDamage"},
        {"BodyPartDamage",   "OnHit"},
        {nullptr, nullptr}
    };

    for (int i = 0; kTargets[i].cls; i++) {
        Il2CppClass *c = Il2Cpp::cls(kTargets[i].cls);
        if (!c) continue;

        // Try to find the method; -1 for parameter count = match any arity
        MethodInfo *m = Il2Cpp::getMethod(c, kTargets[i].meth, -1);
        if (!m || !m->methodPointer) continue;

        // parameters_count does NOT include implicit `this`. Pick closest wrapper.
        uint32_t pcount = m->parameters_count;
        bool ok = false;
        void *orig = nullptr;

        if (pcount >= 4) {       // self + ctx + bone + dmg + [extra]
            ok = DobbyHook(m->methodPointer, (void*)hookHit5, &orig) == 0;
            g_origHit5 = (FnHit5)orig;
        } else if (pcount == 3) { // self + ctx + bone + dmg
            ok = DobbyHook(m->methodPointer, (void*)hookHit4, &orig) == 0;
            g_origHit4 = (FnHit4)orig;
        } else {                  // self + bone + dmg
            ok = DobbyHook(m->methodPointer, (void*)hookHit3, &orig) == 0;
            g_origHit3 = (FnHit3)orig;
        }

        if (ok) {
            g_headBoneHooked = true;
            LOG("HEAD bone fix hooked: %s::%s arity=%u @ %p",
                kTargets[i].cls, kTargets[i].meth, pcount, m->methodPointer);
            return;
        }
    }
    LOG("HEAD bone fix: no suitable hit method found — fallback: bone-index write only");
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
    hookAimSystem();
    hookHeadBoneFix();
    hookNoGrass();
    hookAntiDamage();
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
        case CMD_NO_GRASS:
            g_noGrass = enable;
            LOG("NoGrass %s", enable ? "ON" : "OFF");
            break;
        case CMD_ANTI_DAMAGE:
            g_antiDamage = enable;
            if (!enable) g_damageMult.store(0.5f, std::memory_order_relaxed);
            LOG("AntiDamage %s", enable ? "ON" : "OFF");
            break;
        case CMD_AIM_ENABLE:
            g_aimEnabled = enable;
            LOG("AimSystem %s", enable ? "ON" : "OFF");
            break;
        case CMD_AIM_BONE:
        case CMD_AIM_FOV:
        case CMD_AIM_SMOOTH:
            break; // these are intensity-only, handled by applyIntensity
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
            // 0% = stock interval (0.02), 100% = near-instant (0.001)
            g_rapidIntensity.store(0.02f - t * 0.019f, std::memory_order_relaxed);
            break;
        case CMD_ANTI_DAMAGE:
            // 0% = normal (1.0x), 100% = immune (0.0x)
            g_damageMult.store(1.f - t, std::memory_order_relaxed);
            break;
        case CMD_AIM_BONE:
            // intensity encodes discrete bone: 0=AI, 1=NECK, 2=HEAD
            g_aimBone.store(intensity, std::memory_order_relaxed);
            break;
        case CMD_AIM_FOV:
            // intensity = FOV degrees (5-90)
            g_aimFov.store((float)intensity, std::memory_order_relaxed);
            break;
        case CMD_AIM_SMOOTH:
            // intensity 0-100 → smooth factor 0.0-1.0
            g_aimSmooth.store(t, std::memory_order_relaxed);
            break;
        default: break;
    }
}
