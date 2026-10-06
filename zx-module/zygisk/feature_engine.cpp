#include "feature_engine.hpp"
#include "hook_engine.hpp"
#include <android/log.h>
#include <cstring>
#include <cmath>

#define TAG "ZX-FEAT"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

FeatureEngine &FeatureEngine::get() {
    static FeatureEngine instance;
    return instance;
}

void FeatureEngine::init(AsyncWorker *worker) {
    m_worker = worker;

    // Async — fires on background SCHED_IDLE thread after il2cpp stabilizes
    m_worker->postDelayed([this] {
        resolveClasses();

        if (m_ready) {
            // Apply defaults
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
    if (!img) {
        LOGE("Assembly-CSharp not found");
        return;
    }

    // ── Player ────────────────────────────────────────────────────────────────
    m_cls.Player    = Il2CppApi::getClass(img, "", "PlayerMovement");
    m_cls.Character = Il2CppApi::getClass(img, "", "CharacterController");
    m_cls.Health    = Il2CppApi::getClass(img, "", "HealthComponent");

    // ── Weapon ────────────────────────────────────────────────────────────────
    m_cls.Weapon    = Il2CppApi::getClass(img, "", "WeaponController");
    m_cls.Bullet    = Il2CppApi::getClass(img, "", "BulletManager");
    m_cls.Recoil    = Il2CppApi::getClass(img, "", "RecoilController");

    // ── Camera / Aim ─────────────────────────────────────────────────────────
    m_cls.Camera    = Il2CppApi::getClass(img, "", "CameraController");
    m_cls.Aim       = Il2CppApi::getClass(img, "", "AimController");

    // ── Environment ──────────────────────────────────────────────────────────
    m_cls.Grass     = Il2CppApi::getClass(img, "", "GrassManager");
    m_cls.Vehicle   = Il2CppApi::getClass(img, "", "VehicleController");
    m_cls.Loot      = Il2CppApi::getClass(img, "", "LootManager");

    // ── Fields ───────────────────────────────────────────────────────────────
    if (m_cls.Player)    m_fld.moveSpeed    = Il2CppApi::getField(m_cls.Player,    "moveSpeed");
    if (m_cls.Character) m_fld.jumpForce    = Il2CppApi::getField(m_cls.Character, "jumpForce");
    if (m_cls.Recoil)    m_fld.recoilForce  = Il2CppApi::getField(m_cls.Recoil,   "recoilForce");
    if (m_cls.Weapon)    m_fld.bulletSpread = Il2CppApi::getField(m_cls.Weapon,    "bulletSpread");
    if (m_cls.Weapon)    m_fld.fireRate     = Il2CppApi::getField(m_cls.Weapon,    "fireRate");
    if (m_cls.Camera)    m_fld.fov          = Il2CppApi::getField(m_cls.Camera,    "fieldOfView");
    if (m_cls.Grass)     m_fld.grassEnable  = Il2CppApi::getField(m_cls.Grass,    "enableGrass");
    if (m_cls.Health)    m_fld.maxHealth    = Il2CppApi::getField(m_cls.Health,    "maxHealth");
    if (m_cls.Vehicle)   m_fld.vehicleSpeed = Il2CppApi::getField(m_cls.Vehicle,  "maxSpeed");

    // Methods for hooks
    if (m_cls.Aim)    m_mth.calcAimTarget   = Il2CppApi::getMethod(m_cls.Aim,    "CalculateAimTarget", 0);
    if (m_cls.Weapon) m_mth.onFireWeapon    = Il2CppApi::getMethod(m_cls.Weapon, "OnFireWeapon",       1);
    if (m_cls.Health) m_mth.takeDamage      = Il2CppApi::getMethod(m_cls.Health, "TakeDamage",         2);

    m_ready = (m_cls.Player || m_cls.Weapon || m_cls.Camera);
    LOGI("Classes resolved — Player:%p Weapon:%p Camera:%p Grass:%p",
         m_cls.Player, m_cls.Weapon, m_cls.Camera, m_cls.Grass);
}

// ── COMBAT ────────────────────────────────────────────────────────────────────

void FeatureEngine::applyAntiRecoil(bool enable) {
    if (!m_fld.recoilForce) return;
    float val = enable ? 0.0f : 1.0f;
    Il2CppApi::setStaticValue(nullptr, m_fld.recoilForce, &val);
    LOGI("AntiRecoil: %s", enable ? "ON" : "OFF");
}

void FeatureEngine::applyNoSpread(bool enable) {
    if (!m_fld.bulletSpread) return;
    float val = enable ? 0.0f : 1.0f;
    Il2CppApi::setStaticValue(nullptr, m_fld.bulletSpread, &val);
    LOGI("NoSpread: %s", enable ? "ON" : "OFF");
}

void FeatureEngine::applyRapidFire(bool enable) {
    if (!m_fld.fireRate) return;
    float val = enable ? 0.05f : 0.3f;
    Il2CppApi::setStaticValue(nullptr, m_fld.fireRate, &val);
    LOGI("RapidFire: %s", enable ? "ON" : "OFF");
}

void FeatureEngine::applyAimAssist(bool enable) {
    // Only hooks ONE specific method — not all GL calls
    if (!m_mth.calcAimTarget || !m_mth.calcAimTarget->methodPointer) return;

    static void *orig_calc = nullptr;

    if (enable && !orig_calc) {
        // The actual aimbot correction hook
        static auto hook_fn = [](void *instance) -> void * {
            using Fn = void *(*)(void *);
            void *result = reinterpret_cast<Fn>(orig_calc)(instance);
            // Apply aim smoothing here — no GL touch
            return result;
        };

        HookEngine::get().hookAddr(
            m_mth.calcAimTarget->methodPointer,
            (void *)static_cast<void *(*)(void *)>(hook_fn),
            &orig_calc, "AimAssist");

    } else if (!enable && orig_calc) {
        HookEngine::get().unhook(m_mth.calcAimTarget->methodPointer);
        orig_calc = nullptr;
    }
    LOGI("AimAssist: %s", enable ? "ON" : "OFF");
}

// ── MOVEMENT ─────────────────────────────────────────────────────────────────

void FeatureEngine::applySpeedHack(bool enable, float multiplier) {
    if (!m_fld.moveSpeed) return;
    float base = 6.0f;
    float val  = enable ? base * multiplier : base;
    Il2CppApi::setStaticValue(nullptr, m_fld.moveSpeed, &val);
    LOGI("SpeedHack: %s (x%.2f)", enable ? "ON" : "OFF", multiplier);
}

void FeatureEngine::applyHighJump(bool enable) {
    if (!m_fld.jumpForce) return;
    float val = enable ? 18.0f : 8.0f;
    Il2CppApi::setStaticValue(nullptr, m_fld.jumpForce, &val);
    LOGI("HighJump: %s", enable ? "ON" : "OFF");
}

void FeatureEngine::applyVehicleSpeed(bool enable, float multiplier) {
    if (!m_fld.vehicleSpeed) return;
    float base = 100.0f;
    float val  = enable ? base * multiplier : base;
    Il2CppApi::setStaticValue(nullptr, m_fld.vehicleSpeed, &val);
    LOGI("VehicleSpeed: %s", enable ? "ON" : "OFF");
}

// ── VISUAL ────────────────────────────────────────────────────────────────────

void FeatureEngine::applyWidePOV(float fov) {
    if (!m_fld.fov) return;
    Il2CppApi::setStaticValue(nullptr, m_fld.fov, &fov);
    LOGI("WidePOV: %.1f", fov);
}

void FeatureEngine::applyNoGrass(bool enable) {
    if (!m_fld.grassEnable) return;
    bool val = !enable;  // grassEnable=false means no grass
    Il2CppApi::setStaticValue(nullptr, m_fld.grassEnable, &val);
    LOGI("NoGrass: %s", enable ? "ON" : "OFF");
}

// ── SURVIVAL ─────────────────────────────────────────────────────────────────

void FeatureEngine::applyMaxHealth(bool enable) {
    if (!m_fld.maxHealth) return;
    float val = enable ? 9999.0f : 200.0f;
    Il2CppApi::setStaticValue(nullptr, m_fld.maxHealth, &val);
    LOGI("MaxHealth: %s", enable ? "ON" : "OFF");
}

void FeatureEngine::applyAntiDamage(bool enable) {
    if (!m_mth.takeDamage || !m_mth.takeDamage->methodPointer) return;

    static void *orig_take_dmg = nullptr;

    if (enable && !orig_take_dmg) {
        static auto hook_dmg = [](void *self, float dmg, void *src) -> void {
            (void)dmg; (void)src;
            // Simply don't call original — damage ignored
        };
        HookEngine::get().hookAddr(
            m_mth.takeDamage->methodPointer,
            (void *)static_cast<void(*)(void*, float, void*)>(hook_dmg),
            &orig_take_dmg, "AntiDamage");
    } else if (!enable && orig_take_dmg) {
        HookEngine::get().unhook(m_mth.takeDamage->methodPointer);
        orig_take_dmg = nullptr;
    }
    LOGI("AntiDamage: %s", enable ? "ON" : "OFF");
}
