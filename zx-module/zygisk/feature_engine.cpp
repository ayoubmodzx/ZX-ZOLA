#include "feature_engine.hpp"
#include "hook_engine.hpp"
#include <android/log.h>
#include <cstring>
#include <cmath>

#define TAG "ZX-FEAT"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ─── All names confirmed from global-metadata.dat (IL2CPP v31) ───────────────
//
// GameVarDef: RunSpeed, DashSpeedScale, CrouchSpeed, CreepSpeed,
//             StropFOV, ActiveSkillCameraFOV
//
// UGCAttachmentRepItem (networked weapon stat component) — hooked setters:
//   set_ScatterMax, set_ScatterSpeed, set_ScatterSpeedCrouchCreep,
//   set_SightAimAssist, set_SightAimAssistSnapRange, set_FireInterval,
//   set_AmmoClipSize, set_FullDamageDistance
//
// EWeaponScoreID (enum, NOT float fields): RateOfFire, ClipSize, Recoil, ...
//
// OperationSettingInfo: AimAssist
// ─────────────────────────────────────────────────────────────────────────────

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

    // ── UGCAttachmentRepItem — all setters confirmed from global-metadata.dat
    m_cls.WeaponAttachment = Il2CppApi::getClass(img, "", "UGCAttachmentRepItem");
    if (m_cls.WeaponAttachment) {
        m_mth.setScatterMax     = Il2CppApi::getMethod(m_cls.WeaponAttachment, "set_ScatterMax",              1);
        m_mth.setScatterSpeed   = Il2CppApi::getMethod(m_cls.WeaponAttachment, "set_ScatterSpeed",            1);
        m_mth.setScatterSpeedCC = Il2CppApi::getMethod(m_cls.WeaponAttachment, "set_ScatterSpeedCrouchCreep", 1);
        m_mth.setSightAimAssist = Il2CppApi::getMethod(m_cls.WeaponAttachment, "set_SightAimAssist",          1);
        m_mth.setAimAssistSnap  = Il2CppApi::getMethod(m_cls.WeaponAttachment, "set_SightAimAssistSnapRange", 1);
        m_mth.setFireInterval   = Il2CppApi::getMethod(m_cls.WeaponAttachment, "set_FireInterval",            1);
        m_mth.setAmmoClipSize   = Il2CppApi::getMethod(m_cls.WeaponAttachment, "set_AmmoClipSize",            1);
        m_mth.setFullDamageDist = Il2CppApi::getMethod(m_cls.WeaponAttachment, "set_FullDamageDistance",      1);
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


// ── Hook weapon property setters to intercept stat writes ─────────────────────
static void *s_origSetScatterMax     = nullptr;
static void *s_origSetScatterSpeed   = nullptr;
static void *s_origSetScatterSpeedCC = nullptr;
static void *s_origSetSightAimAssist = nullptr;
static void *s_origSetAimAssistSnap  = nullptr;
static void *s_origSetFireInterval   = nullptr;
static void *s_origSetAmmoClipSize   = nullptr;
static void *s_origSetFullDamageDist = nullptr;
static FeatureEngine *s_engine       = nullptr;

// ScatterMax=0 kills bullet spread; ScatterSpeed=0 stops spread accumulating during fire
static void hook_setScatterMax(void *self, float val) {
    if (s_engine && s_engine->m_noSpread) val = 0.0f;
    reinterpret_cast<void(*)(void*, float)>(s_origSetScatterMax)(self, val);
}
static void hook_setScatterSpeed(void *self, float val) {
    if (s_engine && s_engine->m_noSpread) val = 0.0f;
    reinterpret_cast<void(*)(void*, float)>(s_origSetScatterSpeed)(self, val);
}
static void hook_setScatterSpeedCC(void *self, float val) {
    if (s_engine && s_engine->m_noSpread) val = 0.0f;
    reinterpret_cast<void(*)(void*, float)>(s_origSetScatterSpeedCC)(self, val);
}
static void hook_setSightAimAssist(void *self, float val) {
    if (s_engine && s_engine->m_aimAssist) val = 1.0f;
    reinterpret_cast<void(*)(void*, float)>(s_origSetSightAimAssist)(self, val);
}
static void hook_setAimAssistSnap(void *self, float val) {
    if (s_engine && s_engine->m_aimAssist) val = 999.0f;
    reinterpret_cast<void(*)(void*, float)>(s_origSetAimAssistSnap)(self, val);
}
static void hook_setFireInterval(void *self, float val) {
    if (s_engine && s_engine->m_rapidFire) val = 0.01f;
    reinterpret_cast<void(*)(void*, float)>(s_origSetFireInterval)(self, val);
}
static void hook_setAmmoClipSize(void *self, int val) {
    if (s_engine && s_engine->m_rapidFire) val = 999;
    reinterpret_cast<void(*)(void*, int)>(s_origSetAmmoClipSize)(self, val);
}
static void hook_setFullDamageDist(void *self, float val) {
    if (s_engine && s_engine->m_extendRange) val = 200.0f;
    reinterpret_cast<void(*)(void*, float)>(s_origSetFullDamageDist)(self, val);
}

#define HOOK(mth, fn, orig, tag) \
    if (m_mth.mth && m_mth.mth->methodPointer) \
        eng.hookAddr(m_mth.mth->methodPointer, (void *)(fn), &(orig), (tag))

void FeatureEngine::hookWeaponSetters() {
    s_engine = this;
    auto &eng = HookEngine::get();
    HOOK(setScatterMax,     hook_setScatterMax,     s_origSetScatterMax,     "ScatterMax");
    HOOK(setScatterSpeed,   hook_setScatterSpeed,   s_origSetScatterSpeed,   "ScatterSpd");
    HOOK(setScatterSpeedCC, hook_setScatterSpeedCC, s_origSetScatterSpeedCC, "ScatterCC");
    HOOK(setSightAimAssist, hook_setSightAimAssist, s_origSetSightAimAssist, "SightAA");
    HOOK(setAimAssistSnap,  hook_setAimAssistSnap,  s_origSetAimAssistSnap,  "AASnap");
    HOOK(setFireInterval,   hook_setFireInterval,   s_origSetFireInterval,   "FireIntvl");
    HOOK(setAmmoClipSize,   hook_setAmmoClipSize,   s_origSetAmmoClipSize,   "ClipSize");
    HOOK(setFullDamageDist, hook_setFullDamageDist, s_origSetFullDamageDist, "FullDmgDst");
    LOGI("Weapon setter hooks installed (%zu methods)", sizeof(m_mth)/sizeof(void*));
}
#undef HOOK

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
    // Drives three hooks: ScatterMax, ScatterSpeed, ScatterSpeedCrouchCreep
    // All confirmed setters on UGCAttachmentRepItem from global-metadata.dat
    // "Recoil" in the metadata is an EWeaponScoreID enum value, not a float field
    m_noSpread = enable;
    LOGI("AntiRecoil: %s (via ScatterMax/ScatterSpeed hooks)", enable ? "ON" : "OFF");
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
