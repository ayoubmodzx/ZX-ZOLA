#pragma once
#include "il2cpp_api.hpp"
#include "async_worker.hpp"

class FeatureEngine {
public:
    static FeatureEngine &get();
    void init(AsyncWorker *worker);

    // ── COMBAT ────────────────────────────────────────────────────
    void applyAntiRecoil(bool enable = true);
    void applyNoSpread(bool enable = true);
    void applyRapidFire(bool enable = true);
    void applyAimAssist(bool enable = true);

    // ── MOVEMENT ──────────────────────────────────────────────────
    void applySpeedHack(bool enable = true, float multiplier = 1.5f);
    void applyHighJump(bool enable = true);
    void applyVehicleSpeed(bool enable = true, float multiplier = 2.0f);

    // ── VISUAL ────────────────────────────────────────────────────
    void applyWidePOV(float fov = 85.0f);
    void applyNoGrass(bool enable = true);

    // ── SURVIVAL ─────────────────────────────────────────────────
    void applyMaxHealth(bool enable = true);
    void applyAntiDamage(bool enable = true);

    bool isReady() const { return m_ready; }

private:
    FeatureEngine() = default;

    AsyncWorker *m_worker = nullptr;
    bool         m_ready  = false;

    // Class pointers — names confirmed from global-metadata.dat (IL2CPP v31)
    struct Classes {
        Il2CppClass *GameVarDef       = nullptr;  // game movement/camera config
        Il2CppClass *WeaponAttachment = nullptr;  // UGCAttachmentRepItem
        Il2CppClass *WeaponData       = nullptr;  // weapon score/stat class (lazy)
        Il2CppClass *CharCtrl         = nullptr;  // UnityEngine.CharacterController
        Il2CppClass *OpSetting        = nullptr;  // OperationSettingInfo
    } m_cls;

    // Fields from GameVarDef — static config, confirmed from global-metadata.dat
    struct Fields {
        FieldInfo *runSpeed        = nullptr;  // RunSpeed
        FieldInfo *dashSpeedScale  = nullptr;  // DashSpeedScale
        FieldInfo *crouchSpeed     = nullptr;  // CrouchSpeed
        FieldInfo *creepSpeed      = nullptr;  // CreepSpeed
        FieldInfo *stropFov        = nullptr;  // StropFOV
        FieldInfo *activeSkillFov  = nullptr;  // ActiveSkillCameraFOV
        // Weapon score data (lazy) — Recoil, RateOfFire, ClipSize, DamageBody, DamageHead
        FieldInfo *recoil          = nullptr;
        FieldInfo *rateOfFire      = nullptr;
        FieldInfo *clipSize        = nullptr;
        // OperationSettingInfo
        FieldInfo *aimAssistSetting = nullptr; // AimAssist
    } m_fld;

    // Methods from UGCAttachmentRepItem — property setters (confirmed in metadata)
    // These are hooked to intercept weapon stat writes
    struct Methods {
        MethodInfo *setScatterMax      = nullptr;  // set_ScatterMax
        MethodInfo *setSightAimAssist  = nullptr;  // set_SightAimAssist
        MethodInfo *setAimAssistSnap   = nullptr;  // set_SightAimAssistSnapRange
        MethodInfo *setFireInterval    = nullptr;  // set_FireInterval
    } m_mth;

    void resolveClasses();
    void scanWeaponDataClass();
    void hookWeaponSetters();

public:
    // State read by static hook trampolines — not part of the external API
    bool m_noSpread  = false;
    bool m_aimAssist = false;
    bool m_rapidFire = false;
};
