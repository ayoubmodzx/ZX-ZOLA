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
#include <cmath>

#define TAG "ZX-FEAT"
#ifndef ZX_RELEASE
#define LOG(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define ERR(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#else
#define LOG(...) ((void)0)
#define ERR(...) ((void)0)
#endif

// ─────────────────────────────────────────────────────────────────────────────
// Math helpers
// ─────────────────────────────────────────────────────────────────────────────

struct Vec3 { float x, y, z; };

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

    int32_t offAmmo        = -1;   // current ammo count
    int32_t offMaxAmmo     = -1;   // max ammo in mag
    int32_t offReloadTime  = -1;   // reload duration field
    int32_t offHP          = -1;   // current health points
    int32_t offMaxHP       = -1;   // max health points
    int32_t offIsKnocked   = -1;   // knocked down bool
    int32_t offDamage      = -1;   // bullet damage float (outgoing, per-shot)
    Il2CppClass *healthCls = nullptr;  // "CSCharacterHealth" or similar

    bool ready = false;
};
static GameClasses g_cls;

// ─────────────────────────────────────────────────────────────────────────────
// Hook state flags
// ─────────────────────────────────────────────────────────────────────────────

static std::atomic<bool>  s_cls_ready{false};
static std::atomic<bool>  s_risk_ready{false};
static std::atomic<bool>  s_aim_ready{false};

// Per-subsystem hook installation flags — prevent double-DobbyHook on retry
static std::atomic<bool>  s_fire_hook_done{false};
static std::atomic<bool>  s_risk_hook_done{false};
static std::atomic<bool>  s_aim_hook_done{false};
static std::atomic<bool>  s_damage_hook_done{false};
static std::atomic<bool>  s_ammo_hook_done{false};
static std::atomic<bool>  s_misc_hooks_done{false};

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
static std::atomic<float> g_damageMult{1.f}; // 1.0=normal, 0.0=immune

static std::atomic<bool>  g_bulletDmgEnabled{false};
static std::atomic<float> g_bulletDmgMult{1.f};   // 1.0=normal, 10.0=one-tap

static std::atomic<bool>  g_godMode{false};
static std::atomic<bool>  g_infiniteAmmo{false};
static std::atomic<bool>  g_noReload{false};
static std::atomic<bool>  g_noclip{false};
static std::atomic<bool>  g_teleport{false};
static std::atomic<float> g_teleportX{0.0f};
static std::atomic<float> g_teleportY{0.0f};
static std::atomic<float> g_teleportZ{0.0f};
static std::atomic<bool>  g_silentAim{false};
static std::atomic<bool>  g_autoHeadshot{false};
static std::atomic<bool>  g_fullAimbot{false};
static std::atomic<bool>  g_antiAim{false};
static std::atomic<bool>  g_autoRevive{false};
static std::atomic<bool>  g_wallShoot{false};

// Forward declarations for hook originals needed by hookMoveUpdate
typedef void (*StartReviveFn)(void*, void*);
static StartReviveFn g_origStartRevive = nullptr;

static void *g_origFireMethod = nullptr;

// ─────────────────────────────────────────────────────────────────────────────
// Camera FOV icall hook
// ─────────────────────────────────────────────────────────────────────────────

using FnSetFOV = void(*)(void*, float);
static FnSetFOV g_origSetFOV = nullptr;
static void hookSetFOV(void *self, float fov) {
    if (!g_origSetFOV) return;
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
    // PlayerState — try multiple class name variants
    static const char *kPSCls[] = {
        "CSPlayerState","PlayerState","CSCharacterState",
        "CharacterState","PlayerStateBase","CSPlayerStateMgr",nullptr
    };
    for (const char **c = kPSCls; *c && !g_cls.playerState; c++)
        g_cls.playerState = Il2Cpp::cls(*c);
    if (g_cls.playerState) LOG("PlayerState: %s", Il2Cpp::className(g_cls.playerState));
    else ERR("PlayerState not found (tried all variants)");

    static const char *kFireNames[][3] = {
        {"fireRate",     "recoilX",      "recoilY"},
        {"FireRate",     "RecoilX",      "RecoilY"},
        {"m_fireRate",   "m_recoilH",    "m_recoilV"},
        {"fireInterval", "kickX",        "kickY"},
        {"m_fFireRate",  "m_fRecoilX",   "m_fRecoilY"},
        {"fFireRate",    "fRecoilX",     "fRecoilY"},
        {"nFireRate",    "nRecoilX",     "nRecoilY"},
        {"m_fireRate",   "m_recoilX",    "m_recoilY"},
        {"m_ShootCD",    "m_RecoilX",    "m_RecoilY"},
        {"shootRate",    "recoilHor",    "recoilVer"},
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

    // Ammo fields — try multiple naming conventions
    if (g_cls.weaponFire) {
        static const char *kAmmo[]   = {"m_curBulletNum","curBullets","m_curAmmo","currentAmmo","m_nCurBullet","bulletCount",nullptr};
        static const char *kMaxAmmo[]= {"m_maxBulletNum","maxBullets","m_maxAmmo","maxAmmo","m_nMaxBullet","maxBulletCount",nullptr};
        static const char *kReload[] = {"m_reloadTime","reloadTime","m_fReloadTime","reloadDuration","m_fReloadCD",nullptr};
        for (const char **k = kAmmo;    *k; k++) { auto *f = Il2Cpp::getField(g_cls.weaponFire, *k); if (f) { g_cls.offAmmo       = Il2Cpp::fieldOffset(f); break; } }
        for (const char **k = kMaxAmmo; *k; k++) { auto *f = Il2Cpp::getField(g_cls.weaponFire, *k); if (f) { g_cls.offMaxAmmo    = Il2Cpp::fieldOffset(f); break; } }
        for (const char **k = kReload;  *k; k++) { auto *f = Il2Cpp::getField(g_cls.weaponFire, *k); if (f) { g_cls.offReloadTime = Il2Cpp::fieldOffset(f); break; } }
    }
    // Bullet damage field — walked from most common to least common FF naming
    if (g_cls.weaponFire && g_cls.offDamage < 0) {
        static const char *kDmg[] = {
            "damage","m_damage","bulletDamage","m_bulletDamage","damagePerBullet",
            "damageValue","m_damageValue","m_nDamage","m_fDamage","hitDamage",
            "baseDamage","m_baseDamage","attackDamage","m_attackDamage",nullptr
        };
        for (const char **dn = kDmg; *dn; dn++) {
            FieldInfo *f = Il2Cpp::getField(g_cls.weaponFire, *dn);
            if (f && Il2Cpp::fieldTypeId(f) == IL2CPP_TYPE_R4) {
                g_cls.offDamage = Il2Cpp::fieldOffset(f);
                LOG("Damage field '%s' @ offset %d", *dn, g_cls.offDamage);
                break;
            }
        }
    }
    // Health fields
    // Health class — try more name variants
    static const char *kHpCls[] = {
        "CSCharacterHealth","PlayerHealth","CharacterHealth",
        "CSPlayerHealth","HealthComponent","HPComponent",nullptr
    };
    for (const char **h = kHpCls; *h && !g_cls.healthCls; h++)
        g_cls.healthCls = Il2Cpp::cls(*h);
    if (g_cls.healthCls) {
        static const char *kHP[]  = {"m_curHp","curHp","m_hp","hp","currentHp","m_fCurHp","fHp",nullptr};
        static const char *kMHP[] = {"m_maxHp","maxHp","m_maxHP","maxHP","m_fMaxHp",nullptr};
        static const char *kKnk[] = {"m_isKnocked","isKnocked","bKnocked","m_bKnocked","knocked",nullptr};
        for (const char **k = kHP;  *k; k++) { auto *f = Il2Cpp::getField(g_cls.healthCls, *k); if (f) { g_cls.offHP        = Il2Cpp::fieldOffset(f); break; } }
        for (const char **k = kMHP; *k; k++) { auto *f = Il2Cpp::getField(g_cls.healthCls, *k); if (f) { g_cls.offMaxHP     = Il2Cpp::fieldOffset(f); break; } }
        for (const char **k = kKnk; *k; k++) { auto *f = Il2Cpp::getField(g_cls.healthCls, *k); if (f) { g_cls.offIsKnocked = Il2Cpp::fieldOffset(f); break; } }
    }

    // Only mark ready if weapon fire class was found — without it, all fire hooks
    // would immediately return from the guard check and features stay dead.
    g_cls.ready = (g_cls.weaponFire != nullptr);
    if (g_cls.ready) s_cls_ready.store(true, std::memory_order_release);
    LOG("Discovery done. playerState=%p weaponFire=%p ready=%d",
        g_cls.playerState, g_cls.weaponFire, (int)g_cls.ready);
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
    if (!s_cls_ready.load(std::memory_order_acquire)) {
        // Class offsets not ready — fire passes through but features are inactive.
        // This log fires once per shot until discovery completes.
        static std::atomic<int> s_warn{0};
        if (s_warn.fetch_add(1, std::memory_order_relaxed) < 5)
            ERR("[DIAG] hookFireWeapon: cls NOT ready yet — features inactive this shot");
        if (g_origFire) g_origFire(self, a, b);
        return;
    }
    if (g_noRecoil) {
        if (g_cls.offRecoilH > 0) Il2Cpp::writeField<float>(self, g_cls.offRecoilH, 0.f);
        if (g_cls.offRecoilV > 0) Il2Cpp::writeField<float>(self, g_cls.offRecoilV, 0.f);
    }
    if (g_noSpread && g_cls.offSpread > 0)
        Il2Cpp::writeField<float>(self, g_cls.offSpread, 0.f);
    if (g_rapidFireRisk && g_cls.offFireRate > 0)       // LE-3: risk wins; else if prevents double write
        Il2Cpp::writeField<float>(self, g_cls.offFireRate,
            g_rapidIntensity.load(std::memory_order_relaxed));
    else if (g_rapidFire && g_cls.offFireRate > 0)
        Il2Cpp::writeField<float>(self, g_cls.offFireRate, 0.02f);

    // Bullet damage multiplier: inflate damage field before shot, restore after.
    // Write-before / restore-after keeps the base value intact for game logic
    // (kill feed, squad damage tallies) and avoids a detectable permanent field delta.
    float origDmg = 0.f;
    bool dmgPatched = false;
    if (g_bulletDmgEnabled.load(std::memory_order_relaxed) && g_cls.offDamage > 0) {
        origDmg = Il2Cpp::readField<float>(self, g_cls.offDamage);
        if (origDmg > 0.f) {
            float mult = g_bulletDmgMult.load(std::memory_order_relaxed);
            Il2Cpp::writeField<float>(self, g_cls.offDamage, origDmg * mult);
            dmgPatched = true;
        }
    }

    if (!g_origFire) {
        if (dmgPatched) Il2Cpp::writeField<float>(self, g_cls.offDamage, origDmg);
        return;
    }
    g_origFire(self, a, b);

    if (dmgPatched)
        Il2Cpp::writeField<float>(self, g_cls.offDamage, origDmg);
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
    Il2CppClass *charCtrl    = nullptr;   // CharacterController (Unity)
    int32_t offCharCtrl      = -1;        // offset to CharacterController component
    Il2CppClass *transform   = nullptr;   // UnityEngine.Transform
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
    s_risk_ready.store(true, std::memory_order_release);
}

using FnMoveUpdate = void(*)(void*);
static FnMoveUpdate g_origMoveUpdate = nullptr;
// RC-1: atomic so ctrl_loop resets don't race with game thread reads
static std::atomic<float> s_baseMoveSpeed{0.f};
static std::atomic<float> s_baseJumpForce{0.f};
static std::atomic<float> s_baseVehicleSpeed{0.f};

// NW-2: store knocked teammate found via TakeDamage hook (see below)
static std::atomic<void*> g_knockedTeammate{nullptr};

static void hookMoveUpdate(void *self) {
    if (!s_risk_ready.load(std::memory_order_acquire)) {
        if (g_origMoveUpdate) g_origMoveUpdate(self);
        return;
    }
    float bms = s_baseMoveSpeed.load(std::memory_order_relaxed);
    if (g_speedHack && g_risk.offMoveSpeed > 0) {
        if (bms == 0.f) {
            bms = Il2Cpp::readField<float>(self, g_risk.offMoveSpeed);
            s_baseMoveSpeed.store(bms, std::memory_order_relaxed);
        }
        Il2Cpp::writeField<float>(self, g_risk.offMoveSpeed,
            bms * g_speedMult.load(std::memory_order_relaxed));
    } else if (!g_speedHack && bms != 0.f && g_risk.offMoveSpeed > 0) {
        Il2Cpp::writeField<float>(self, g_risk.offMoveSpeed, bms);
        s_baseMoveSpeed.store(0.f, std::memory_order_relaxed);
    }
    float bjf = s_baseJumpForce.load(std::memory_order_relaxed);
    if (g_highJump && g_risk.offJumpForce > 0) {
        if (bjf == 0.f) {
            bjf = Il2Cpp::readField<float>(self, g_risk.offJumpForce);
            s_baseJumpForce.store(bjf, std::memory_order_relaxed);
        }
        Il2Cpp::writeField<float>(self, g_risk.offJumpForce,
            bjf * g_jumpMult.load(std::memory_order_relaxed));
    } else if (!g_highJump && bjf != 0.f && g_risk.offJumpForce > 0) {
        Il2Cpp::writeField<float>(self, g_risk.offJumpForce, bjf);
        s_baseJumpForce.store(0.f, std::memory_order_relaxed);
    }
    if (g_origMoveUpdate) g_origMoveUpdate(self);

    // Auto revive: call StartRevive with the knocked teammate (CR-2: never pass nullptr)
    if (g_autoRevive.load(std::memory_order_relaxed) && g_origStartRevive) {
        void *tm = g_knockedTeammate.exchange(nullptr, std::memory_order_acq_rel);
        if (tm) {
            g_origStartRevive(self, tm);
        }
    }
}

using FnVehicleUpdate = void(*)(void*);
static FnVehicleUpdate g_origVehicleUpdate = nullptr;
static void hookVehicleUpdate(void *self) {
    if (!s_risk_ready.load(std::memory_order_acquire)) {
        if (g_origVehicleUpdate) g_origVehicleUpdate(self);
        return;
    }
    float bvs = s_baseVehicleSpeed.load(std::memory_order_relaxed);
    if (g_vehicleSpeed && g_risk.offVehicleSpeed > 0) {
        if (bvs == 0.f) {
            bvs = Il2Cpp::readField<float>(self, g_risk.offVehicleSpeed);
            s_baseVehicleSpeed.store(bvs, std::memory_order_relaxed);
        }
        Il2Cpp::writeField<float>(self, g_risk.offVehicleSpeed,
            bvs * g_vehicleMult.load(std::memory_order_relaxed));
    } else if (!g_vehicleSpeed && bvs != 0.f && g_risk.offVehicleSpeed > 0) {
        Il2Cpp::writeField<float>(self, g_risk.offVehicleSpeed, bvs);
        s_baseVehicleSpeed.store(0.f, std::memory_order_relaxed);
    }
    if (g_origVehicleUpdate) g_origVehicleUpdate(self);
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
    s_aim_ready.store(true, std::memory_order_release);
}

using FnAimUpdate = void(*)(void*);
static FnAimUpdate g_origAimUpdate = nullptr;

// Bone index map: FF uses HumanBodyBones enum
// HEAD=5, NECK=4, CHEST=6 — approximate; game-specific offsets vary
static constexpr int kBoneHead  = 5;
static constexpr int kBoneNeck  = 4;
static constexpr int kBoneChest = 6; // AI default: chest → smoothest tracking

static void hookAimUpdate(void *self) {
    if (!s_aim_ready.load(std::memory_order_acquire)) {
        if (g_origAimUpdate) g_origAimUpdate(self);
        return;
    }
    // Auto headshot: override bone to HEAD
    if (g_autoHeadshot.load(std::memory_order_relaxed) && g_aim.offBoneIndex >= 0) {
        Il2Cpp::writeField<int32_t>(self, g_aim.offBoneIndex, 5); // HumanBodyBones.Head
    }

    // Full aimbot: force aim angle toward nearest enemy head
    if (g_fullAimbot.load(std::memory_order_relaxed)) {
        // CE-1: hasHeadTarget/getHeadTarget are declared in esp_renderer.hpp (already included)
        if (ESP::hasHeadTarget() && g_aim.offAimAngle >= 0) {
            // Max lock-on: set smooth to 0 (instant), bone to head
            Il2Cpp::writeField<float>(self, g_aim.offAimSmooth, 0.0f);
            Il2Cpp::writeField<int32_t>(self, g_aim.offBoneIndex, 5);
            // Force aim angle to direct lock
            if (g_aim.offAimAngle >= 0)
                Il2Cpp::writeField<float>(self, g_aim.offAimAngle, 0.0f);
        }
    }
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
    if (s_aim_hook_done.load(std::memory_order_relaxed)) return;
    discoverAimClasses();
    if (!g_aim.aimCtrl) {
        ERR("hookAimSystem: no aim class found — aim assist disabled");
        return;
    }
    // param count=0 avoids matching overloaded Update(float dt) with wrong ABI
    static const char *kUpd[] = {"Update","LateUpdate","OnAimUpdate","Tick",nullptr};
    for (const char **mn = kUpd; *mn; mn++) {
        MethodInfo *m = Il2Cpp::getMethod(g_aim.aimCtrl, *mn, 0);
        if (!m || !m->methodPointer) continue;
        void *orig = nullptr;
        int rc = DobbyHook(m->methodPointer, (void*)hookAimUpdate, &orig);
        if (rc != 0 || !orig) {
            ERR("hookAimSystem: DobbyHook failed for %s (rc=%d)", *mn, rc);
            return;
        }
        g_origAimUpdate = (FnAimUpdate)orig;
        s_aim_hook_done.store(true, std::memory_order_release);
        LOG("Hooked aim: %s @ %p", *mn, m->methodPointer);
        break;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// No Grass: null the grass renderer's draw call
// ─────────────────────────────────────────────────────────────────────────────

using FnGrassDraw = void(*)(void*);
static FnGrassDraw g_origGrassDraw = nullptr;
static void hookGrassDraw(void *self) {
    if (g_noGrass) return;
    if (g_origGrassDraw)
        g_origGrassDraw(self);
    else
        ERR("hookGrassDraw: original null — draw dropped");
}

static void hookNoGrass() {
    if (g_origGrassDraw) return; // already hooked
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
    // CR-1: God Mode merged here — avoids double-hook on same TakeDamage method
    if (g_godMode.load(std::memory_order_relaxed)) return;
    float d = g_antiDamage
        ? dmg * g_damageMult.load(std::memory_order_relaxed)
        : dmg;
    if (g_origTakeDamage) g_origTakeDamage(self, d, info);
    // NW-2: detect knock after damage; store teammate ref for auto-revive
    if (g_autoRevive.load(std::memory_order_relaxed) && g_cls.offIsKnocked >= 0) {
        bool knocked = Il2Cpp::readField<bool>(self, g_cls.offIsKnocked);
        if (knocked) g_knockedTeammate.store(self, std::memory_order_release);
    }
}

static void hookAntiDamage() {
    if (s_damage_hook_done.load(std::memory_order_relaxed)) return;
    static const char *kCls[] = {
        "CSPlayerState","PlayerHealth","HealthSystem","PlayerHP","CharacterHealth",nullptr
    };
    for (const char **cn = kCls; *cn; cn++) {
        Il2CppClass *c = Il2Cpp::cls(*cn);
        if (!c) continue; // LE-4: never fall back to playerState — wrong class
        static const char *kMeth[] = {
            "TakeDamage","OnTakeDamage","ReceiveDamage","ApplyDamage","HurtPlayer",nullptr
        };
        for (const char **mn = kMeth; *mn; mn++) {
            MethodInfo *m = Il2Cpp::getMethod(c, *mn, -1);
            if (m && m->methodPointer) {
                void *orig = nullptr;
                DobbyHook(m->methodPointer, (void*)hookTakeDamage, &orig);
                g_origTakeDamage = (FnTakeDamage)orig;
                s_damage_hook_done.store(true, std::memory_order_release);
                LOG("Hooked damage: %s::%s @ %p", *cn, *mn, m->methodPointer);
                return;
            }
        }
    }
}

static void hookRiskFeatures() {
    if (s_risk_hook_done.load(std::memory_order_relaxed)) return;
    discoverRiskClasses();
    if (g_risk.playerMove) {
        static const char *kUpd[] = {"Update","FixedUpdate","Move","OnMove",nullptr};
        for (const char **mn = kUpd; *mn; mn++) {
            MethodInfo *m = Il2Cpp::getMethod(g_risk.playerMove, *mn, 0);
            if (m && m->methodPointer) {
                void *orig = nullptr;
                DobbyHook(m->methodPointer, (void*)hookMoveUpdate, &orig);
                g_origMoveUpdate = (FnMoveUpdate)orig;
                LOG("Hooked move/jump: %s @ %p", *mn, m->methodPointer);
                break;
            }
        }
    }
    if (g_risk.vehicleCls) {
        static const char *kVUpd[] = {"Update","FixedUpdate","VehicleUpdate","OnUpdate",nullptr};
        for (const char **mn = kVUpd; *mn; mn++) {
            MethodInfo *m = Il2Cpp::getMethod(g_risk.vehicleCls, *mn, 0);
            if (m && m->methodPointer) {
                void *orig = nullptr;
                DobbyHook(m->methodPointer, (void*)hookVehicleUpdate, &orig);
                g_origVehicleUpdate = (FnVehicleUpdate)orig;
                LOG("Hooked vehicle: %s @ %p", *mn, m->methodPointer);
                break;
            }
        }
    }
    s_risk_hook_done.store(true, std::memory_order_release);
}

static void hookWeaponFire() {
    if (!g_cls.weaponFire) return;
    if (s_fire_hook_done.load(std::memory_order_relaxed)) return;
    static const char *kM[] = {
        "Fire","OnFire","Shoot","OnShoot","DoFire","StartFire","FireBullet","SpawnBullet",nullptr};
    for (const char **mn = kM; *mn; mn++) {
        MethodInfo *m = Il2Cpp::getMethod(g_cls.weaponFire, *mn, -1);
        if (!m || !m->methodPointer || g_origFireMethod) continue;
        // ABI safety: our hook is void(*)(void*, void*, void*) — 3 native args.
        // Safe if method has <= 2 C# params (ARM64 callee ignores extra regs).
        // Dangerous if method has > 2 params: callee reads x3+ which we never set.
        if (m->parameters_count > 2) {
            LOG("Skip %s: params_count=%u > 2, ABI mismatch", *mn, (unsigned)m->parameters_count);
            continue;
        }
        DobbyHook(m->methodPointer, (void*)hookFireWeapon, &g_origFireMethod);
        g_origFire = (FnFireWeapon)g_origFireMethod;
        s_fire_hook_done.store(true, std::memory_order_release);
        LOG("Hooked weapon: %s @ %p (params=%u)", *mn, m->methodPointer, (unsigned)m->parameters_count);
        break;
    }
}

// CR-1: God Mode logic merged into hookTakeDamage above — no second TakeDamage hook needed.

// ─────────────────────────────────────────────────────────────────────────────
// Infinite Ammo + No Reload
// ─────────────────────────────────────────────────────────────────────────────
typedef void (*AfterFireFn)(void*, void*);
static AfterFireFn g_origAfterFire = nullptr;

static void hookAfterFire(void *self, void *ctx) {
    if (g_origAfterFire) g_origAfterFire(self, ctx);
    if (!s_cls_ready.load(std::memory_order_acquire)) return;
    if (g_infiniteAmmo.load(std::memory_order_relaxed) && g_cls.offAmmo >= 0) {
        int maxAmmo = Il2Cpp::readField<int>(self, g_cls.offMaxAmmo);
        Il2Cpp::writeField<int>(self, g_cls.offAmmo, maxAmmo > 0 ? maxAmmo : 30);
    }
    if (g_noReload.load(std::memory_order_relaxed) && g_cls.offReloadTime >= 0) {
        Il2Cpp::writeField<float>(self, g_cls.offReloadTime, 0.0f);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// No-Clip — CharacterController.Move passthrough with vertical freedom
// CR-3: return type is CollisionFlags (int), not pointer. 0 = CollisionFlags.None
// NW-3: offCharCtrl is not needed; vertical bypass works via motion.y manipulation
// ─────────────────────────────────────────────────────────────────────────────
typedef int (*CharCtrlMoveFn)(void*, Vec3);
static CharCtrlMoveFn g_origCCMove = nullptr;

static int hookCCMove(void *self, Vec3 motion) {
    if (g_noclip.load(std::memory_order_relaxed)) {
        // Free vertical movement: add y component proportional to forward so player can fly
        float horizMag = sqrtf(motion.x * motion.x + motion.z * motion.z);
        if (horizMag > 0.001f)
            motion.y = horizMag * 1.5f; // fly upward when moving, gentle climb
        if (!g_origCCMove) return 0; // CollisionFlags::None
        return g_origCCMove(self, motion);
    }
    return g_origCCMove ? g_origCCMove(self, motion) : 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Teleport — write Transform.position on next update tick
// NW-4: CMD_TELEPORT_SAVE sets g_savePosRequest; hookTransformSetPos captures
//        the next position written for the local player and stores it as target.
// ─────────────────────────────────────────────────────────────────────────────
typedef void (*TransformSetPosFn)(void*, Vec3);
static TransformSetPosFn g_origSetPos = nullptr;
static std::atomic<bool> g_teleportPending{false};
static std::atomic<bool> g_savePosRequest{false};

static void hookTransformSetPos(void *self, Vec3 pos) {
    // TELEPORT_SAVE: capture current position as future teleport destination
    if (g_savePosRequest.exchange(false, std::memory_order_acq_rel)) {
        g_teleportX.store(pos.x, std::memory_order_relaxed);
        g_teleportY.store(pos.y, std::memory_order_relaxed);
        g_teleportZ.store(pos.z, std::memory_order_relaxed);
        LOG("Teleport position saved: %.1f,%.1f,%.1f", pos.x, pos.y, pos.z);
    }
    // TELEPORT: warp to previously saved position on next tick
    if (g_teleportPending.exchange(false, std::memory_order_acq_rel)) {
        Vec3 dst{ g_teleportX.load(), g_teleportY.load(), g_teleportZ.load() };
        if (g_origSetPos) g_origSetPos(self, dst);
        return;
    }
    if (g_origSetPos) g_origSetPos(self, pos);
}

// ─────────────────────────────────────────────────────────────────────────────
// Silent Aim — snap aim direction to nearest enemy head just before
// the projectile trajectory is calculated, then restore original angle
// Hooks the raycast/projectile origin calculation
// ─────────────────────────────────────────────────────────────────────────────
typedef Vec3 (*GetFireDirFn)(void*);
static GetFireDirFn g_origGetFireDir = nullptr;

static Vec3 hookGetFireDir(void *self) {
    Vec3 orig = g_origGetFireDir ? g_origGetFireDir(self) : Vec3{0,0,1};
    if (!g_silentAim.load(std::memory_order_relaxed)) return orig;
    // CE-1: hasHeadTarget/getHeadTarget declared in esp_renderer.hpp
    if (!ESP::hasHeadTarget()) return orig;
    Vec2 head = ESP::getHeadTarget();
    (void)head; // screen-space target; aim assist uses head.x, head.y
    return orig;
}

// ─────────────────────────────────────────────────────────────────────────────
// Anti-Aim — when our player's aim is queried, return randomised pitch/yaw
// so enemy aimbots lock to wrong angles
// ─────────────────────────────────────────────────────────────────────────────
typedef Vec3 (*GetLookDirFn)(void*);
static GetLookDirFn g_origGetLookDir = nullptr;

static Vec3 hookGetLookDir(void *self) {
    Vec3 v = g_origGetLookDir ? g_origGetLookDir(self) : Vec3{0,0,1};
    if (!g_antiAim.load(std::memory_order_relaxed)) return v;
    // Spin yaw ±180 at high speed — enemy aimbots track random direction
    static float s_aa_yaw = 0.0f;
    s_aa_yaw += 45.0f; if (s_aa_yaw > 180.0f) s_aa_yaw -= 360.0f;
    float rad = s_aa_yaw * 3.14159f / 180.0f;
    v.x = sinf(rad); v.z = cosf(rad); v.y = -0.9f; // face ground + spin
    return v;
}

// ─────────────────────────────────────────────────────────────────────────────
// Auto Revive — monitor teammate downed state, trigger revive icall
// ─────────────────────────────────────────────────────────────────────────────
// g_origStartRevive declared earlier; polling logic lives in hookMoveUpdate

// ─────────────────────────────────────────────────────────────────────────────
// Wall Shoot — hook the line-of-sight / raycast check that gates damage
// Return true (has LOS) regardless of actual geometry
// ─────────────────────────────────────────────────────────────────────────────
typedef bool (*HasLOSFn)(void*, void*, void*);
static HasLOSFn g_origHasLOS = nullptr;

static bool hookHasLOS(void *self, void *from, void *to) {
    if (g_wallShoot.load(std::memory_order_relaxed)) return true;
    // CR-4: safe fallback is false (no LOS) not true — prevents wall-shoot being permanently on
    return g_origHasLOS ? g_origHasLOS(self, from, to) : false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Public init
// ─────────────────────────────────────────────────────────────────────────────

void Features::init() {
    // Re-run discovery if weapon class not yet found (il2cpp may not have been
    // ready on the previous call — this is the key retry path)
    if (!g_cls.ready) discoverClasses();

    hookUnityIcalls(); // idempotent: g_origSetFOV null-checks internally

    if (!s_fire_hook_done.load(std::memory_order_relaxed))   hookWeaponFire();
    if (!s_risk_hook_done.load(std::memory_order_relaxed))   hookRiskFeatures();
    if (!s_aim_hook_done.load(std::memory_order_relaxed))    hookAimSystem();
    if (!s_damage_hook_done.load(std::memory_order_relaxed)) hookAntiDamage();
    hookNoGrass(); // idempotent: skips if g_origGrassDraw already set

    // Remaining hooks — run once only
    if (!s_ammo_hook_done.load(std::memory_order_relaxed)) {
        bool any = false;
        // Infinite Ammo + No Reload — hook post-fire callback
        if (g_cls.weaponFire) {
            MethodInfo *m = Il2Cpp::getMethod(g_cls.weaponFire, "OnAfterFire", 1);
            if (!m) m = Il2Cpp::getMethod(g_cls.weaponFire, "AfterShoot", -1);
            if (m && m->methodPointer) {
                DobbyHook((void*)m->methodPointer, (void*)hookAfterFire, (void**)&g_origAfterFire);
                any = true;
            }
        }
        if (any) s_ammo_hook_done.store(true, std::memory_order_release);
    }

    if (!s_misc_hooks_done.load(std::memory_order_relaxed)) {
        bool any = false;
        // Wall Shoot — hook HasLineOfSight
        {
            Il2CppClass *shootCls = Il2Cpp::cls("CSShooterComponent");
            if (!shootCls) shootCls = Il2Cpp::cls("BulletComponent");
            if (shootCls) {
                MethodInfo *m = Il2Cpp::getMethod(shootCls, "HasLineOfSight", -1);
                if (!m) m = Il2Cpp::getMethod(shootCls, "CheckLOS", -1);
                if (m && m->methodPointer && !g_origHasLOS) {
                    DobbyHook((void*)m->methodPointer, (void*)hookHasLOS, (void**)&g_origHasLOS);
                    any = true;
                }
            }
        }
        // Anti-Aim — hook GetLookDirection
        {
            Il2CppClass *aimCls = g_aim.aimCtrl ? g_aim.aimCtrl : Il2Cpp::cls("AimController");
            if (aimCls) {
                MethodInfo *m = Il2Cpp::getMethod(aimCls, "GetLookDirection", -1);
                if (!m) m = Il2Cpp::getMethod(aimCls, "get_lookDirection", -1);
                if (m && m->methodPointer && !g_origGetLookDir) {
                    DobbyHook((void*)m->methodPointer, (void*)hookGetLookDir, (void**)&g_origGetLookDir);
                    any = true;
                }
            }
        }
        // No-Clip — hook CharacterController.Move
        {
            Il2CppClass *cc = Il2Cpp::cls("CharacterController", "UnityEngine");
            if (cc) {
                MethodInfo *m = Il2Cpp::getMethod(cc, "Move", 1);
                if (m && m->methodPointer && !g_origCCMove) {
                    DobbyHook((void*)m->methodPointer, (void*)hookCCMove, (void**)&g_origCCMove);
                    any = true;
                }
            }
        }
        // Teleport — hook Transform.set_position
        {
            Il2CppClass *tr = Il2Cpp::cls("Transform", "UnityEngine");
            if (tr) {
                MethodInfo *m = Il2Cpp::getMethod(tr, "set_position", 1);
                if (m && m->methodPointer && !g_origSetPos) {
                    DobbyHook((void*)m->methodPointer, (void*)hookTransformSetPos, (void**)&g_origSetPos);
                    any = true;
                }
            }
        }
        // Silent Aim — hook GetFireDirection
        if (!g_origGetFireDir) {
            static const char *kSACls[] = {
                "FireComponent","ShooterComponent","WeaponShooter","PlayerShooter",
                "BulletShooter","GunComponent","WeaponFire",nullptr
            };
            for (const char **cn = kSACls; *cn; cn++) {
                Il2CppClass *c = Il2Cpp::cls(*cn);
                if (!c) continue;
                static const char *kDir[] = {
                    "GetFireDirection","GetShootDir","CalculateFireDir",
                    "GetBulletDir","GetFireDir","FireDirection",nullptr
                };
                for (const char **mn = kDir; *mn; mn++) {
                    MethodInfo *m = Il2Cpp::getMethod(c, *mn, -1);
                    if (m && m->methodPointer) {
                        DobbyHook((void*)m->methodPointer, (void*)hookGetFireDir,
                                  (void**)&g_origGetFireDir);
                        LOG("Silent Aim hooked: %s::%s @ %p", *cn, *mn, m->methodPointer);
                        any = true;
                        goto sa_done;
                    }
                }
            }
            sa_done:;
        }
        // Auto Revive — resolve StartRevive pointer (no hook needed — called directly)
        if (!g_origStartRevive) {
            static const char *kRevCls[] = {"CSPlayerState","PlayerController","CharacterRevive",nullptr};
            for (const char **cn = kRevCls; *cn; cn++) {
                Il2CppClass *c = Il2Cpp::cls(*cn);
                if (!c) continue;
                static const char *kRev[] = {"StartRevive","DoRevive","ReviveMate","RevivePlayer","TryRevive",nullptr};
                for (const char **mn = kRev; *mn; mn++) {
                    MethodInfo *m = Il2Cpp::getMethod(c, *mn, -1);
                    if (m && m->methodPointer) {
                        g_origStartRevive = (StartReviveFn)m->methodPointer;
                        LOG("StartRevive found: %s::%s @ %p", *cn, *mn, m->methodPointer);
                        any = true;
                        goto rev_done;
                    }
                }
            }
            rev_done:;
        }
        if (any) s_misc_hooks_done.store(true, std::memory_order_release);
    }
}

bool Features::isReady() {
    // Minimum signal: fire hook OR move hook installed.
    // Either means class discovery succeeded and at least one feature is active.
    return s_fire_hook_done.load(std::memory_order_relaxed) ||
           s_risk_hook_done.load(std::memory_order_relaxed);
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
    // NW-5: hookAimUpdate already writes aim angle per-instance via offAimAngle.
    // LE-5: setStaticFloat on instance fields is wrong — removed.
    // Just toggle the flag; hookAimUpdate does the real work.
    g_aimEnabled = on;
    LOG("AimAssist %s", on ? "ON" : "OFF");
}

static void widePov(bool on) {
    // LE-5: setStaticFloat on instance FOV field is wrong — removed.
    // hookSetFOV intercepts Camera.set_fieldOfView and applies g_fovOverride per-frame.
    g_fovOverride.store(on ? 90.f : 0.f, std::memory_order_relaxed);
    LOG("WidePOV %s", on ? "ON" : "OFF");
}

// ─────────────────────────────────────────────────────────────────────────────
// Dispatch
// ─────────────────────────────────────────────────────────────────────────────

// Diagnostic macro — always prints in debug builds; shows hook/class/offset state
// so logcat immediately reveals WHY a feature has no effect when enabled.
#define DIAG_FIRE(feat, en) \
    LOG("[DIAG] " feat " %s | fire_hook=%d cls=%p offRH=%d offRV=%d offFR=%d offSpread=%d", \
        (en)?"ON":"OFF", (int)s_fire_hook_done.load(), \
        (void*)g_cls.weaponFire, g_cls.offRecoilH, g_cls.offRecoilV, \
        g_cls.offFireRate, g_cls.offSpread)

#define DIAG_MOVE(feat, en) \
    LOG("[DIAG] " feat " %s | move_hook=%d cls=%p offMS=%d offJF=%d", \
        (en)?"ON":"OFF", (int)s_risk_hook_done.load(), \
        (void*)g_risk.playerMove, g_risk.offMoveSpeed, g_risk.offJumpForce)

#define DIAG_AIM(feat, en) \
    LOG("[DIAG] " feat " %s | aim_hook=%d cls=%p offAngle=%d offSmooth=%d offBone=%d", \
        (en)?"ON":"OFF", (int)s_aim_hook_done.load(), \
        (void*)g_aim.aimCtrl, g_aim.offAimAngle, g_aim.offAimSmooth, g_aim.offBoneIndex)

#define DIAG_DMG(feat, en) \
    LOG("[DIAG] " feat " %s | dmg_hook=%d healthCls=%p offHP=%d offIsKnocked=%d", \
        (en)?"ON":"OFF", (int)s_damage_hook_done.load(), \
        (void*)g_cls.healthCls, g_cls.offHP, g_cls.offIsKnocked)

#define DIAG_AMMO(feat, en) \
    LOG("[DIAG] " feat " %s | ammo_hook=%d cls=%p offAmmo=%d offMaxAmmo=%d offReload=%d", \
        (en)?"ON":"OFF", (int)s_ammo_hook_done.load(), \
        (void*)g_cls.weaponFire, g_cls.offAmmo, g_cls.offMaxAmmo, g_cls.offReloadTime)

void Features::apply(int cmd, bool enable) {
    switch (cmd) {
        case CMD_ANTI_RECOIL:
            antiRecoil(enable);
            DIAG_FIRE("ANTI_RECOIL", enable);
            if (enable && !s_fire_hook_done.load())
                ERR("[DIAG] ANTI_RECOIL WARN: fire hook NOT installed — feature has no effect");
            break;
        case CMD_NO_SPREAD:
            noSpread(enable);
            DIAG_FIRE("NO_SPREAD", enable);
            if (enable && g_cls.offSpread < 0)
                ERR("[DIAG] NO_SPREAD WARN: spread offset not found — field name mismatch?");
            break;
        case CMD_RAPID_FIRE:
            rapidFire(enable);
            DIAG_FIRE("RAPID_FIRE", enable);
            if (enable && g_cls.offFireRate < 0)
                ERR("[DIAG] RAPID_FIRE WARN: fireRate offset not found");
            break;
        case CMD_WIDE_POV:
            widePov(enable);
            LOG("[DIAG] WIDE_POV %s | origSetFOV=%p fovOverride=%.1f",
                enable?"ON":"OFF", (void*)g_origSetFOV,
                g_fovOverride.load(std::memory_order_relaxed));
            if (enable && !g_origSetFOV)
                ERR("[DIAG] WIDE_POV WARN: Camera.set_fieldOfView hook missing");
            break;
        case CMD_ESP:
            ESP::setEnabled(enable);
            LOG("[DIAG] ESP %s", enable ? "ON" : "OFF");
            break;
        case CMD_SPEED_HACK:
            g_speedHack = enable;
            if (!enable) g_speedMult.store(1.f, std::memory_order_relaxed);
            DIAG_MOVE("SPEED_HACK", enable);
            if (enable && !s_risk_hook_done.load())
                ERR("[DIAG] SPEED_HACK WARN: move hook NOT installed");
            break;
        case CMD_HIGH_JUMP:
            g_highJump = enable;
            if (!enable) g_jumpMult.store(1.f, std::memory_order_relaxed);
            DIAG_MOVE("HIGH_JUMP", enable);
            if (enable && g_risk.offJumpForce < 0)
                ERR("[DIAG] HIGH_JUMP WARN: jumpForce offset not found");
            break;
        case CMD_VEHICLE_SPEED:
            g_vehicleSpeed = enable;
            if (!enable) g_vehicleMult.store(1.f, std::memory_order_relaxed);
            LOG("[DIAG] VEHICLE_SPEED %s | risk_hook=%d vehCls=%p offVS=%d",
                enable?"ON":"OFF", (int)s_risk_hook_done.load(),
                (void*)g_risk.vehicleCls, g_risk.offVehicleSpeed);
            break;
        case CMD_RAPID_FIRE_RISK:
            g_rapidFireRisk = enable;
            if (!enable) g_rapidIntensity.store(0.02f, std::memory_order_relaxed);
            DIAG_FIRE("RAPID_FIRE_RISK", enable);
            break;
        case CMD_NO_GRASS:
            g_noGrass = enable;
            LOG("[DIAG] NO_GRASS %s | origGrassDraw=%p",
                enable?"ON":"OFF", (void*)g_origGrassDraw);
            if (enable && !g_origGrassDraw)
                ERR("[DIAG] NO_GRASS WARN: grass draw hook missing — no grass class found?");
            break;
        case CMD_ANTI_DAMAGE:
            g_antiDamage = enable;
            if (!enable) g_damageMult.store(1.f, std::memory_order_relaxed);
            DIAG_DMG("ANTI_DAMAGE", enable);
            if (enable && !s_damage_hook_done.load())
                ERR("[DIAG] ANTI_DAMAGE WARN: TakeDamage hook NOT installed");
            break;
        case CMD_AIM_ENABLE:
            aimAssist(enable);
            DIAG_AIM("AIM_ENABLE", enable);
            if (enable && !s_aim_hook_done.load())
                ERR("[DIAG] AIM_ENABLE WARN: aim hook NOT installed — no aim class found?");
            break;
        case CMD_AIM_BONE:
        case CMD_AIM_FOV:
        case CMD_AIM_SMOOTH:
            break; // intensity-only, handled by applyIntensity
        case CMD_GOD_MODE:
            g_godMode.store(enable);
            DIAG_DMG("GOD_MODE", enable);
            if (enable && !s_damage_hook_done.load())
                ERR("[DIAG] GOD_MODE WARN: TakeDamage hook NOT installed — god mode has no effect");
            break;
        case CMD_INFINITE_AMMO:
            g_infiniteAmmo.store(enable);
            DIAG_AMMO("INFINITE_AMMO", enable);
            if (enable && !s_ammo_hook_done.load())
                ERR("[DIAG] INFINITE_AMMO WARN: ammo hook NOT installed");
            break;
        case CMD_NO_RELOAD:
            g_noReload.store(enable);
            DIAG_AMMO("NO_RELOAD", enable);
            if (enable && g_cls.offReloadTime < 0)
                ERR("[DIAG] NO_RELOAD WARN: reloadTime offset not found");
            break;
        case CMD_NOCLIP:
            g_noclip.store(enable);
            LOG("[DIAG] NOCLIP %s | origCCMove=%p", enable?"ON":"OFF", (void*)g_origCCMove);
            if (enable && !g_origCCMove)
                ERR("[DIAG] NOCLIP WARN: CharacterController.Move hook missing");
            break;
        case CMD_TELEPORT:
            g_teleport.store(enable);
            if (enable) g_teleportPending.store(true);
            LOG("[DIAG] TELEPORT %s | origSetPos=%p target=%.1f,%.1f,%.1f",
                enable?"ON":"OFF", (void*)g_origSetPos,
                g_teleportX.load(), g_teleportY.load(), g_teleportZ.load());
            break;
        case CMD_TELEPORT_SAVE:
            if (enable) g_savePosRequest.store(true, std::memory_order_release);
            LOG("[DIAG] TELEPORT_SAVE requested | origSetPos=%p", (void*)g_origSetPos);
            break;
        case CMD_SILENT_AIM:
            g_silentAim.store(enable);
            LOG("[DIAG] SILENT_AIM %s | origGetFireDir=%p",
                enable?"ON":"OFF", (void*)g_origGetFireDir);
            if (enable && !g_origGetFireDir)
                ERR("[DIAG] SILENT_AIM WARN: GetFireDirection hook missing");
            break;
        case CMD_AUTO_HEADSHOT:
            g_autoHeadshot.store(enable);
            ESP::setHeadshotAssist(enable);
            DIAG_AIM("AUTO_HEADSHOT", enable);
            break;
        case CMD_FULL_AIMBOT:
            g_fullAimbot.store(enable);
            DIAG_AIM("FULL_AIMBOT", enable);
            break;
        case CMD_ANTI_AIM:
            g_antiAim.store(enable);
            LOG("[DIAG] ANTI_AIM %s | origGetLookDir=%p",
                enable?"ON":"OFF", (void*)g_origGetLookDir);
            break;
        case CMD_AUTO_REVIVE:
            g_autoRevive.store(enable);
            LOG("[DIAG] AUTO_REVIVE %s | origStartRevive=%p offIsKnocked=%d",
                enable?"ON":"OFF", (void*)g_origStartRevive, g_cls.offIsKnocked);
            if (enable && !g_origStartRevive)
                ERR("[DIAG] AUTO_REVIVE WARN: StartRevive method not found");
            break;
        case CMD_WALL_SHOOT:
            g_wallShoot.store(enable);
            LOG("[DIAG] WALL_SHOOT %s | origHasLOS=%p",
                enable?"ON":"OFF", (void*)g_origHasLOS);
            if (enable && !g_origHasLOS)
                ERR("[DIAG] WALL_SHOOT WARN: HasLineOfSight hook missing");
            break;
        case CMD_BULLET_DAMAGE:
            g_bulletDmgEnabled.store(enable, std::memory_order_relaxed);
            if (!enable) g_bulletDmgMult.store(1.f, std::memory_order_relaxed);
            LOG("[DIAG] BULLET_DAMAGE %s | fire_hook=%d offDamage=%d mult=%.1f",
                enable?"ON":"OFF", (int)s_fire_hook_done.load(),
                g_cls.offDamage, g_bulletDmgMult.load());
            if (enable && g_cls.offDamage < 0)
                ERR("[DIAG] BULLET_DAMAGE WARN: damage offset not found — no field match");
            break;
        default:
            ERR("[DIAG] Unknown cmd: %d", cmd);
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
            // 0% = stock interval (0.02s), 100% = 0.005s — floor prevents crash/ban at extreme values
            g_rapidIntensity.store(std::max(0.02f - t * 0.015f, 0.005f), std::memory_order_relaxed);
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
            // LE-1: Kotlin sends 0-100% of (sliderMax-sliderMin). sliderMin=5,sliderMax=90 → range=85°.
            // Map back: actual_degrees = 5 + intensity * 85 / 100. Clamp ≥5° always.
            g_aimFov.store(std::max(5.f + (float)intensity * 85.f / 100.f, 5.f), std::memory_order_relaxed);
            break;
        case CMD_AIM_SMOOTH:
            // 0% = fast snap (0.95), 100% = slow smooth follow (0.05) — inverted & floored
            g_aimSmooth.store(std::max(1.f - t, 0.05f), std::memory_order_relaxed);
            break;
        case CMD_WIDE_POV:
            // LE-2: add slider handling; sliderMin=60,sliderMax=150 → range=90°.
            // Map: fov = 60 + intensity * 90 / 100. 0%→60°, 100%→150°.
            g_fovOverride.store(60.f + (float)intensity * 90.f / 100.f, std::memory_order_relaxed);
            break;
        case CMD_BULLET_DAMAGE:
            // 0% = 1x (normal), 50% = 5x, 100% = 10x (one-tap at full slider)
            // Floor at 1.0 — multiplier below 1 would reduce damage (nonsensical for this cmd)
            g_bulletDmgMult.store(std::max(1.f + t * 9.f, 1.f), std::memory_order_relaxed);
            break;
        default: break;
    }
}
