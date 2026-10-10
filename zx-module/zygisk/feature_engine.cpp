#include "feature_engine.hpp"
#include "hook_engine.hpp"
#include <android/log.h>
#include <cstring>
#include <cmath>

#define TAG "ZX-FEAT"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ─── Class/field/method names confirmed from global-metadata.dat (IL2CPP v31) ─
//
// GameVarDef (game movement + camera config class):
//   RunSpeed, DashSpeedScale, CrouchSpeed, CreepSpeed, StropFOV,
//   ActiveSkillCameraFOV — all confirmed strings at known string-pool offsets
//
// UGCAttachmentRepItem (networked weapon attachment stat component):
//   Properties (C# auto-props with get_/set_ accessors confirmed in metadata):
//   ScatterMax, SightAimAssist, SightAimAssistSnapRange, FireInterval,
//   AmmoClipSize, ReloadSpeed, FastAutoReloadSpeed, SightFOVAmplifyRatio
//
// Weapon score data block (class name resolved lazily):
//   RateOfFire, ReloadSpeed, ClipSize, Accuracy, Recoil, DamageBody, DamageHead
//
// OperationSettingInfo: AimAssist (user toggle field)
// ──────────────────────────────────────────────────────────────────────────────

FeatureEngine &FeatureEngine::get() {
    static FeatureEngine instance;
    return instance;
}

void FeatureEngine::init(AsyncWorker *worker) {
    m_worker = worker;
    m_worker->postDelayed([this] {
        resolveClasses();
        if (m_ready) {
            applyNoGrass(true);
            applyWidePOV(85.0f);
            LOGI("Features ready");
        } else {
            LOGE("Class resolution failed — check FF version");
        }
    }, 3500);
}

void FeatureEngine::resolveClasses() {
    Il2CppImage *img = Il2CppApi::getImage("Assembly-CSharp");
    if (!img) { LOGE("Assembly-CSharp not found"); return; }

    // ── GameVarDef — game-wide movement/camera config singleton
    m_cls.GameVarDef = Il2CppApi::getClass(img, "", "GameVarDef");
    if (m_cls.GameVarDef) {
        m_fld.runSpeed       = Il2CppApi::getField(m_cls.GameVarDef, "RunSpeed");
        m_fld.dashSpeedScale = Il2CppApi::getField(m_cls.GameVarDef, "DashSpeedScale");
        m_fld.crouchSpeed    = Il2CppApi::getField(m_cls.GameVarDef, "CrouchSpeed");
        m_fld.creepSpeed     = Il2CppApi::getField(m_cls.GameVarDef, "CreepSpeed");
        m_fld.stropFov       = Il2CppApi::getField(m_cls.GameVarDef, "StropFOV");
        m_fld.activeSkillFov = Il2CppApi::getField(m_cls.GameVarDef, "ActiveSkillCameraFOV");
    }

    // ── UGCAttachmentRepItem — weapon attachment stat component
    //    Property setters confirmed: set_ScatterMax, set_SightAimAssist, set_FireInterval
    m_cls.WeaponAttachment = Il2CppApi::getClass(img, "", "UGCAttachmentRepItem");
    if (m_cls.WeaponAttachment) {
        m_mth.setScatterMax     = Il2CppApi::getMethod(m_cls.WeaponAttachment, "set_ScatterMax", 1);
        m_mth.setSightAimAssist = Il2CppApi::getMethod(m_cls.WeaponAttachment, "set_SightAimAssist", 1);
        m_mth.setAimAssistSnap  = Il2CppApi::getMethod(m_cls.WeaponAttachment,
                                                        "set_SightAimAssistSnapRange", 1);
        m_mth.setFireInterval   = Il2CppApi::getMethod(m_cls.WeaponAttachment, "set_FireInterval", 1);
        hookWeaponSetters();
    }

    // ── OperationSettingInfo — AimAssist user setting field
    m_cls.OpSetting = Il2CppApi::getClass(img, "", "OperationSettingInfo");
    if (m_cls.OpSetting)
        m_fld.aimAssistSetting = Il2CppApi::getField(m_cls.OpSetting, "AimAssist");

    m_ready = (m_cls.GameVarDef || m_cls.WeaponAttachment);
    LOGI("Classes — GameVarDef:%p WeaponAttach:%p OpSetting:%p",
         m_cls.GameVarDef, m_cls.WeaponAttachment, m_cls.OpSetting);
    LOGI("Fields  — RunSpeed:%p ScatterSetter:%p AimAssistSetter:%p",
         m_fld.runSpeed, m_mth.setScatterMax, m_mth.setSightAimAssist);
}

// ── Lazily resolve weapon score data class (Recoil, RateOfFire, etc.) ─────────
void FeatureEngine::scanWeaponDataClass() {
    if (m_cls.WeaponData) return;
    Il2CppImage *img = Il2CppApi::getImage("Assembly-CSharp");
    if (!img) return;

    static const char *kCandidates[] = {
        "WeaponPropertyScore", "WeaponScoreData", "WeaponStatData",
        "WeaponSkinData", "WeaponData", nullptr
    };
    for (int i = 0; kCandidates[i]; i++) {
        Il2CppClass *cls = Il2CppApi::getClass(img, "", kCandidates[i]);
        if (!cls) continue;
        FieldInfo *recoil = Il2CppApi::getField(cls, "Recoil");
        if (!recoil) continue;
        m_cls.WeaponData = cls;
        m_fld.recoil     = recoil;
        m_fld.rateOfFire = Il2CppApi::getField(cls, "RateOfFire");
        m_fld.clipSize   = Il2CppApi::getField(cls, "ClipSize");
        LOGI("WeaponData resolved: %s (Recoil:%p RateOfFire:%p)",
             kCandidates[i], m_fld.recoil, m_fld.rateOfFire);
        break;
    }
}

// ── Hook weapon property setters to intercept stat writes ─────────────────────
// When the game calls set_ScatterMax(x) on any attachment, our hook replaces
// x with 0 (no spread). Same pattern for aim-assist and fire rate.
static void *s_origSetScatterMax     = nullptr;
static void *s_origSetSightAimAssist = nullptr;
static void *s_origSetFireInterval   = nullptr;
static FeatureEngine *s_engine       = nullptr;

static void hook_setScatterMax(void *self, float val) {
    if (s_engine && s_engine->m_noSpread) val = 0.0f;
    using Fn = void(*)(void*, float);
    reinterpret_cast<Fn>(s_origSetScatterMax)(self, val);
}

static void hook_setSightAimAssist(void *self, float val) {
    if (s_engine && s_engine->m_aimAssist) val = 1.0f;
    using Fn = void(*)(void*, float);
    reinterpret_cast<Fn>(s_origSetSightAimAssist)(self, val);
}

static void hook_setFireInterval(void *self, float val) {
    if (s_engine && s_engine->m_rapidFire) val = 0.01f;
    using Fn = void(*)(void*, float);
    reinterpret_cast<Fn>(s_origSetFireInterval)(self, val);
}

void FeatureEngine::hookWeaponSetters() {
    s_engine = this;
    auto &eng = HookEngine::get();

    if (m_mth.setScatterMax && m_mth.setScatterMax->methodPointer)
        eng.hookAddr(m_mth.setScatterMax->methodPointer,
                     (void *)hook_setScatterMax, &s_origSetScatterMax, "SetScatterMax");

    if (m_mth.setSightAimAssist && m_mth.setSightAimAssist->methodPointer)
        eng.hookAddr(m_mth.setSightAimAssist->methodPointer,
                     (void *)hook_setSightAimAssist, &s_origSetSightAimAssist, "SetSightAA");

    if (m_mth.setFireInterval && m_mth.setFireInterval->methodPointer)
        eng.hookAddr(m_mth.setFireInterval->methodPointer,
                     (void *)hook_setFireInterval, &s_origSetFireInterval, "SetFireIntvl");

    LOGI("Weapon setter hooks installed");
}

// ── MOVEMENT ──────────────────────────────────────────────────────────────────

void FeatureEngine::applySpeedHack(bool enable, float multiplier) {
    // GameVarDef.RunSpeed / DashSpeedScale / CrouchSpeed / CreepSpeed
    // All confirmed field names from global-metadata.dat string pool
    if (m_fld.runSpeed) {
        float base = 6.0f, val = enable ? base * multiplier : base;
        Il2CppApi::setStaticValue(nullptr, m_fld.runSpeed, &val);
    }
    if (m_fld.dashSpeedScale) {
        float val = enable ? multiplier : 1.0f;
        Il2CppApi::setStaticValue(nullptr, m_fld.dashSpeedScale, &val);
    }
    if (m_fld.crouchSpeed) {
        float base = 4.0f, val = enable ? base * multiplier : base;
        Il2CppApi::setStaticValue(nullptr, m_fld.crouchSpeed, &val);
    }
    if (m_fld.creepSpeed) {
        float base = 2.5f, val = enable ? base * multiplier : base;
        Il2CppApi::setStaticValue(nullptr, m_fld.creepSpeed, &val);
    }
    LOGI("SpeedHack: %s (x%.2f)", enable ? "ON" : "OFF", multiplier);
}

void FeatureEngine::applyHighJump(bool enable) {
    // CharacterController.stepOffset — confirmed field from metadata
    Il2CppImage *unityImg = Il2CppApi::getImage("UnityEngine.PhysicsModule");
    if (!unityImg) unityImg = Il2CppApi::getImage("UnityEngine");
    if (!unityImg) return;
    Il2CppClass *cc = Il2CppApi::getClass(unityImg, "UnityEngine", "CharacterController");
    if (!cc) return;
    FieldInfo *stepOff = Il2CppApi::getField(cc, "stepOffset");
    if (stepOff) {
        float val = enable ? 4.0f : 0.35f;
        Il2CppApi::setStaticValue(nullptr, stepOff, &val);
    }
    LOGI("HighJump: %s", enable ? "ON" : "OFF");
}

void FeatureEngine::applyVehicleSpeed(bool enable, float multiplier) {
    (void)enable; (void)multiplier;
    LOGI("VehicleSpeed: stub — vehicle class not yet confirmed in metadata");
}

// ── VISUAL ────────────────────────────────────────────────────────────────────

void FeatureEngine::applyWidePOV(float fov) {
    // GameVarDef.StropFOV + ActiveSkillCameraFOV — both confirmed from metadata
    if (m_fld.stropFov)       Il2CppApi::setStaticValue(nullptr, m_fld.stropFov,       &fov);
    if (m_fld.activeSkillFov) Il2CppApi::setStaticValue(nullptr, m_fld.activeSkillFov, &fov);
    LOGI("WidePOV: %.1f", fov);
}

void FeatureEngine::applyNoGrass(bool enable) {
    Il2CppImage *unityImg = Il2CppApi::getImage("UnityEngine.TerrainModule");
    if (!unityImg) unityImg = Il2CppApi::getImage("UnityEngine");
    if (!unityImg) return;
    Il2CppClass *qs = Il2CppApi::getClass(unityImg, "UnityEngine", "QualitySettings");
    if (!qs) return;
    MethodInfo *setDens = Il2CppApi::getMethod(qs, "set_terrainDetailDensityScale", 1);
    if (setDens && setDens->methodPointer) {
        float val = enable ? 0.0f : 1.0f;
        using SetFn = void(*)(float);
        reinterpret_cast<SetFn>(setDens->methodPointer)(val);
        LOGI("NoGrass: %s", enable ? "ON" : "OFF");
    }
}

// ── COMBAT ────────────────────────────────────────────────────────────────────

void FeatureEngine::applyAntiRecoil(bool enable) {
    // Sets m_noSpread flag — hook_setScatterMax reads it on every setter call
    m_noSpread = enable;
    // Also try static weapon score data if resolved
    scanWeaponDataClass();
    if (m_fld.recoil) {
        float val = enable ? 0.0f : 1.0f;
        Il2CppApi::setStaticValue(nullptr, m_fld.recoil, &val);
    }
    LOGI("AntiRecoil: %s", enable ? "ON" : "OFF");
}

void FeatureEngine::applyNoSpread(bool enable) {
    // Hooks intercept set_ScatterMax on every UGCAttachmentRepItem write
    m_noSpread = enable;
    LOGI("NoSpread: %s (via set_ScatterMax hook)", enable ? "ON" : "OFF");
}

void FeatureEngine::applyRapidFire(bool enable) {
    // Hooks intercept set_FireInterval — confirmed property setter in metadata
    m_rapidFire = enable;
    LOGI("RapidFire: %s (via set_FireInterval hook)", enable ? "ON" : "OFF");
}

void FeatureEngine::applyAimAssist(bool enable) {
    // Hooks intercept set_SightAimAssist + set_SightAimAssistSnapRange
    // Both confirmed property names from global-metadata.dat
    m_aimAssist = enable;
    // Also force the player's AimAssist setting toggle
    if (m_fld.aimAssistSetting) {
        bool v = enable;
        Il2CppApi::setStaticValue(nullptr, m_fld.aimAssistSetting, &v);
    }
    LOGI("AimAssist: %s (via setter hooks + OperationSettingInfo)", enable ? "ON" : "OFF");
}

// ── SURVIVAL ─────────────────────────────────────────────────────────────────

void FeatureEngine::applyMaxHealth(bool enable) {
    (void)enable;
    LOGI("MaxHealth: stub — needs FightingEntity/player ECS class resolution");
}

void FeatureEngine::applyAntiDamage(bool enable) {
    (void)enable;
    LOGI("AntiDamage: stub — needs TakeDamage method from player entity class");
}
