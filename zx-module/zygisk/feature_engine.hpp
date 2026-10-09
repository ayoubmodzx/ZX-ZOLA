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

    struct Classes {
        Il2CppClass *Player    = nullptr;
        Il2CppClass *Character = nullptr;
        Il2CppClass *Health    = nullptr;
        Il2CppClass *Weapon    = nullptr;
        Il2CppClass *Bullet    = nullptr;
        Il2CppClass *Recoil    = nullptr;
        Il2CppClass *Camera    = nullptr;
        Il2CppClass *Aim       = nullptr;
        Il2CppClass *Grass     = nullptr;
        Il2CppClass *Vehicle   = nullptr;
        Il2CppClass *Loot      = nullptr;
    } m_cls;

    struct Fields {
        FieldInfo *moveSpeed    = nullptr;
        FieldInfo *jumpForce    = nullptr;
        FieldInfo *recoilForce  = nullptr;
        FieldInfo *bulletSpread = nullptr;
        FieldInfo *fireRate     = nullptr;
        FieldInfo *fov          = nullptr;
        FieldInfo *grassEnable  = nullptr;
        FieldInfo *maxHealth    = nullptr;
        FieldInfo *vehicleSpeed = nullptr;
    } m_fld;

    struct Methods {
        MethodInfo *calcAimTarget = nullptr;
        MethodInfo *onFireWeapon  = nullptr;
        MethodInfo *takeDamage    = nullptr;
    } m_mth;

    void resolveClasses();
};
