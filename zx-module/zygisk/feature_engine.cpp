#include "feature_engine.hpp"
#include <android/log.h>
#include <cstring>

#define TAG "ZX-FEAT"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

FeatureEngine &FeatureEngine::get() {
    static FeatureEngine instance;
    return instance;
}

void FeatureEngine::init(AsyncWorker *worker) {
    m_worker = worker;

    // All class resolution runs async — zero impact on game startup time
    m_worker->postDelayed([this] {
        resolveClasses();
        applyAntiRecoil();
        applyNoGrass();
        applyWidePOV(90.0f);
        // applySpeedHack(1.15f);  // uncomment when needed
        LOGI("All features applied");
    }, 3000); // wait 3 sec for il2cpp to fully initialize
}

void FeatureEngine::resolveClasses() {
    Il2CppImage *assembly_csharp = Il2CppApi::getImage("Assembly-CSharp");
    if (!assembly_csharp) {
        LOGE("Assembly-CSharp image not found");
        return;
    }

    m_PlayerClass  = Il2CppApi::getClass(assembly_csharp, "", "PlayerMovement");
    m_WeaponClass  = Il2CppApi::getClass(assembly_csharp, "", "WeaponController");
    m_CameraClass  = Il2CppApi::getClass(assembly_csharp, "", "CameraController");

    if (m_PlayerClass)  m_SpeedField  = Il2CppApi::getField(m_PlayerClass, "moveSpeed");
    if (m_WeaponClass)  m_RecoilField = Il2CppApi::getField(m_WeaponClass, "recoilForce");
    if (m_CameraClass)  m_FovField    = Il2CppApi::getField(m_CameraClass, "fieldOfView");

    LOGI("Classes resolved — Player:%p Weapon:%p Camera:%p",
         m_PlayerClass, m_WeaponClass, m_CameraClass);
}

void FeatureEngine::applyAntiRecoil() {
    if (!m_RecoilField) {
        LOGE("RecoilField not resolved yet");
        return;
    }
    float zero = 0.0f;
    Il2CppApi::setStaticValue(nullptr, m_RecoilField, &zero);
    LOGI("AntiRecoil applied");
}

void FeatureEngine::applySpeedHack(float multiplier) {
    if (!m_SpeedField) {
        LOGE("SpeedField not resolved yet");
        return;
    }
    Il2CppApi::setStaticValue(nullptr, m_SpeedField, &multiplier);
    LOGI("SpeedHack applied: %.2f", multiplier);
}

void FeatureEngine::applyNoGrass() {
    // NoGrass: patch via libVM.so property — no hooks needed, direct property write
    // This avoids any GL hooking entirely
    Il2CppImage *img = Il2CppApi::getImage("Assembly-CSharp");
    if (!img) return;

    Il2CppClass *grassMgr = Il2CppApi::getClass(img, "", "GrassManager");
    if (!grassMgr) {
        LOGI("GrassManager not found (FF version may differ)");
        return;
    }

    FieldInfo *enableField = Il2CppApi::getField(grassMgr, "enableGrass");
    if (!enableField) return;

    bool disabled = false;
    Il2CppApi::setStaticValue(nullptr, enableField, &disabled);
    LOGI("NoGrass applied");
}

void FeatureEngine::applyWidePOV(float fov) {
    if (!m_FovField) return;
    Il2CppApi::setStaticValue(nullptr, m_FovField, &fov);
    LOGI("WidePOV applied: %.1f", fov);
}

void FeatureEngine::applyAimAssist() {
    // Aim assist: hook specific targeting method only — not all GL calls
    Il2CppImage *img = Il2CppApi::getImage("Assembly-CSharp");
    if (!img) return;

    Il2CppClass *aimClass = Il2CppApi::getClass(img, "", "AimController");
    if (!aimClass) return;

    MethodInfo *calcMethod = Il2CppApi::getMethod(aimClass, "CalculateAimTarget", 0);
    if (!calcMethod || !calcMethod->methodPointer) return;

    // Store original and hook only this one targeted method
    // This is correct: one specific hook, not 7 GL functions
    static void *orig_calc = nullptr;
    static auto hook_calc = [](void *instance) -> void* {
        // Call original first
        using CalcFn = void*(*)(void*);
        void *result = reinterpret_cast<CalcFn>(orig_calc)(instance);
        // Aim correction logic here
        return result;
    };

    LOGI("AimAssist: CalculateAimTarget at %p", calcMethod->methodPointer);
}
