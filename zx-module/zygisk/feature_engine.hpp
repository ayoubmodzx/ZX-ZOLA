#pragma once
#include "il2cpp_api.hpp"
#include "async_worker.hpp"

// All feature logic lives here — add your features as methods
class FeatureEngine {
public:
    static FeatureEngine &get();

    void init(AsyncWorker *worker);

    // ── Features ──────────────────────────────────────────────────
    void applyAimAssist();
    void applyAntiRecoil();
    void applySpeedHack(float multiplier);
    void applyNoGrass();
    void applyWidePOV(float fov);
    // Add more here without touching main.cpp

private:
    FeatureEngine() = default;

    AsyncWorker *m_worker = nullptr;

    // Cached class/method/field pointers — resolved once
    Il2CppClass  *m_PlayerClass     = nullptr;
    Il2CppClass  *m_WeaponClass     = nullptr;
    Il2CppClass  *m_CameraClass     = nullptr;
    MethodInfo   *m_UpdateMethod    = nullptr;
    FieldInfo    *m_RecoilField     = nullptr;
    FieldInfo    *m_SpeedField      = nullptr;
    FieldInfo    *m_FovField        = nullptr;

    void resolveClasses();
};
