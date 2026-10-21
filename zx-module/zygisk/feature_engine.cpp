#include "feature_engine.hpp"
#include "hook_engine.hpp"
#include <android/log.h>
#include <cstring>
#include <cmath>
#include <cerrno>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define TAG "ZX-FEAT"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Abstract socket name (leading \0 = abstract, no filesystem entry)
static constexpr char kSockName[] = "zx_zola";

FeatureEngine &FeatureEngine::get() {
    static FeatureEngine instance;
    return instance;
}

void FeatureEngine::init(AsyncWorker *worker) {
    m_worker = worker;
    m_worker->postDelayed([this] {
        resolveClasses();
        if (m_ready) {
            LOGI("Features ready — socket server starting");
        } else {
            LOGE("Class resolution failed — check FF version");
        }
        startServer();
    }, 5000);
}

void FeatureEngine::resolveClasses() {
    Il2CppImage *img = Il2CppApi::getImage("Assembly-CSharp");
    if (!img) { LOGE("Assembly-CSharp not found"); return; }

    // Real names verified against IL2CPP v31 global-metadata.dat TypeDefinitions
    m_cls.Player    = Il2CppApi::getClass(img, "COW.GamePlay", "Player");
    m_cls.Character = Il2CppApi::getClass(img, "COW.GamePlay", "PlayerAttributes");
    m_cls.Health    = m_cls.Player;
    m_cls.Weapon    = Il2CppApi::getClass(img, "COW",          "WeaponPropertyUtil");
    m_cls.Recoil    = m_cls.Weapon;
    m_cls.Bullet    = Il2CppApi::getClass(img, "COW.GamePlay", "VerticleBulletController");
    m_cls.Camera    = Il2CppApi::getClass(img, "COW.GamePlay", "CameraPanZoom");
    m_cls.Aim       = Il2CppApi::getClass(img, "COW.GamePlay", "UGCAimAssistEntity");
    m_cls.Grass     = Il2CppApi::getClass(img, "COW.Graphics", "GrassSystem");
    m_cls.Vehicle   = Il2CppApi::getClass(img, "COW.GamePlay", "Vehicle");

    // All field names are obfuscated — resolve via readable method names only
    if (m_cls.Player)    m_mth.takeDamage    = Il2CppApi::getMethod(m_cls.Player,    "TakeDamage",               2);
    if (m_cls.Character) m_mth.setSpeedScale = Il2CppApi::getMethod(m_cls.Character, "SetSpecialRunSpeedScale",   1);
    if (m_cls.Weapon)    m_mth.recoilFormula = Il2CppApi::getMethod(m_cls.Weapon,    "RecoilFormula",            -1);
    if (m_cls.Weapon)    m_mth.rateOfFire    = Il2CppApi::getMethod(m_cls.Weapon,    "RateOfFireFormula",        -1);
    if (m_cls.Grass)     m_mth.getGrassInst  = Il2CppApi::getMethod(m_cls.Grass,     "get_GrassInstances",        0);
    if (m_cls.Grass)     m_mth.setGrassInst  = Il2CppApi::getMethod(m_cls.Grass,     "set_GrassInstances",        1);
    if (m_cls.Aim)       m_mth.calcAimTarget = Il2CppApi::getMethod(m_cls.Aim,       "CalculateAimPoint",        -1);

    // Resolve UnityEngine.Camera.set_fieldOfView for WidePOV
    // Also resolve Transform for Teleport
    Il2CppImage *unityImg = Il2CppApi::getImage("UnityEngine.CoreModule");
    if (!unityImg) unityImg = Il2CppApi::getImage("UnityEngine");
    if (unityImg) {
        m_cls.UnityCamera = Il2CppApi::getClass(unityImg, "UnityEngine", "Camera");
        if (m_cls.UnityCamera)
            m_mth.setCameraFov = Il2CppApi::getMethod(m_cls.UnityCamera, "set_fieldOfView", 1);

        m_cls.UnityTransform = Il2CppApi::getClass(unityImg, "UnityEngine", "Transform");
        if (m_cls.UnityTransform) {
            m_mth.setPosition = Il2CppApi::getMethod(m_cls.UnityTransform, "set_position", 1);
            m_mth.getPosition = Il2CppApi::getMethod(m_cls.UnityTransform, "get_position", 0);
        }
        // Component.get_transform (base of every MonoBehaviour)
        Il2CppClass *component = Il2CppApi::getClass(unityImg, "UnityEngine", "Component");
        if (component)
            m_mth.getTransform = Il2CppApi::getMethod(component, "get_transform", 0);
    }

    // ESP — visibility gate on Player class
    if (m_cls.Player) {
        static const char *kVisNames[] = {
            "GetIsVisible", "IsVisible", "get_IsVisible",
            "IsInView", "get_IsInView", "UpdateVisible", nullptr
        };
        for (int i = 0; kVisNames[i]; ++i) {
            MethodInfo *m = Il2CppApi::getMethod(m_cls.Player, kVisNames[i], -1);
            if (m && m->methodPointer) { m_mth.isVisible = m; break; }
        }
    }

    // InfiniteAmmo — current clip ammo getter
    if (m_cls.Weapon) {
        static const char *kAmmoNames[] = {
            "GetCurrentClipAmmo", "get_CurrentClipAmmo",
            "GetAmmoCount",       "get_AmmoCount",
            "get_Ammo",           "GetAmmo",
            "GetCurrentAmmo",     "get_CurrentAmmo", nullptr
        };
        for (int i = 0; kAmmoNames[i]; ++i) {
            MethodInfo *m = Il2CppApi::getMethod(m_cls.Weapon, kAmmoNames[i], -1);
            if (m && m->methodPointer) { m_mth.getCurrentAmmo = m; break; }
        }
    }

    // NoReload — reload check
    if (m_cls.Weapon) {
        static const char *kReloadNames[] = {
            "IsNeedReload", "NeedReload", "get_IsNeedReload",
            "CheckNeedReload", "ShouldReload", nullptr
        };
        for (int i = 0; kReloadNames[i]; ++i) {
            MethodInfo *m = Il2CppApi::getMethod(m_cls.Weapon, kReloadNames[i], -1);
            if (m && m->methodPointer) { m_mth.isNeedReload = m; break; }
        }
    }

    // WallShoot — bullet wall/obstacle hit check
    if (m_cls.Bullet) {
        static const char *kWallNames[] = {
            "CheckWall", "IsHitWall", "CheckObstacle",
            "IsBlockedByWall", "HitObstacle", "CheckHitWall",
            "IsHitStatic", nullptr
        };
        for (int i = 0; kWallNames[i]; ++i) {
            MethodInfo *m = Il2CppApi::getMethod(m_cls.Bullet, kWallNames[i], -1);
            if (m && m->methodPointer) { m_mth.checkWallHit = m; break; }
        }
    }

    // AutoRevive — knockdown state getter
    if (m_cls.Player) {
        static const char *kKDNames[] = {
            "get_IsKnockDown", "IsKnockDown", "GetIsKnockDown",
            "get_IsKnockedDown", "IsKnockedDown", nullptr
        };
        for (int i = 0; kKDNames[i]; ++i) {
            MethodInfo *m = Il2CppApi::getMethod(m_cls.Player, kKDNames[i], -1);
            if (m && m->methodPointer) { m_mth.isKnockDown = m; break; }
        }
    }

    // NoClip — CharacterController collision callback
    if (m_cls.Character) {
        m_mth.colliderHit = Il2CppApi::getMethod(m_cls.Character, "OnControllerColliderHit", 1);
        if (!m_mth.colliderHit && m_cls.Player)
            m_mth.colliderHit = Il2CppApi::getMethod(m_cls.Player, "OnControllerColliderHit", 1);
    }

    // Teleport — Player.Update for per-frame tick hook
    if (m_cls.Player) {
        static const char *kUpdateNames[] = {
            "Update", "LateUpdate", "OnUpdate", "Tick", nullptr
        };
        for (int i = 0; kUpdateNames[i]; ++i) {
            MethodInfo *m = Il2CppApi::getMethod(m_cls.Player, kUpdateNames[i], -1);
            if (m && m->methodPointer) { m_mth.playerUpdate = m; break; }
        }
    }

    m_ready = (m_cls.Player != nullptr || m_cls.Weapon != nullptr);
    LOGI("resolved Player:%p Weapon:%p Grass:%p Vehicle:%p | dmg:%p recoil:%p rof:%p speed:%p cam_fov:%p",
         m_cls.Player, m_cls.Weapon, m_cls.Grass, m_cls.Vehicle,
         m_mth.takeDamage, m_mth.recoilFormula, m_mth.rateOfFire, m_mth.setSpeedScale,
         m_mth.setCameraFov);
    LOGI("resolved esp:%p ammo:%p reload:%p wallhit:%p knockdown:%p collider:%p setpos:%p update:%p",
         m_mth.isVisible, m_mth.getCurrentAmmo, m_mth.isNeedReload,
         m_mth.checkWallHit, m_mth.isKnockDown, m_mth.colliderHit,
         m_mth.setPosition, m_mth.playerUpdate);
}

// ── Shared hook state (file-scope, hooks installed once, toggled via flags) ───

static bool  s_anti_recoil  = false;
static bool  s_no_spread    = false;
static bool  s_rapid_fire   = false;
static bool  s_anti_damage  = false;
static bool  s_no_grass     = false;
static bool  s_speed_on     = false;
static float s_speed_mul    = 1.5f;
static bool  s_wide_pov     = false;
static float s_target_fov   = 90.0f;
static bool  s_high_jump    = false;
static float s_jump_mul     = 2.5f;
static bool  s_vehicle_on   = false;
static float s_vehicle_mul  = 2.0f;
// ── New feature flags ─────────────────────────────────────────────────────────
static bool  s_esp           = false;
static bool  s_inf_ammo      = false;
static bool  s_no_reload     = false;
static bool  s_wall_shoot    = false;
static bool  s_auto_revive   = false;
static bool  s_noclip        = false;
// Teleport saved position (Vec3 stored as plain floats — no Unity dep)
struct Vec3 { float x, y, z; };
static Vec3  s_tp_saved      = {0, 0, 0};
static bool  s_tp_has_save   = false;
static bool  s_tp_pending    = false;  // set by applyTeleport, cleared by tick hook

static void *s_orig_recoil   = nullptr;
static void *s_orig_rof      = nullptr;
static void *s_orig_dmg      = nullptr;
static void *s_orig_grass    = nullptr;
static void *s_orig_speed    = nullptr;
static void *s_orig_aim      = nullptr;
static void *s_orig_fov      = nullptr;
static void *s_orig_jump     = nullptr;
static void *s_orig_vehicle  = nullptr;
// ── New orig pointers ─────────────────────────────────────────────────────────
static void *s_orig_visible   = nullptr;
static void *s_orig_ammo      = nullptr;
static void *s_orig_reload    = nullptr;
static void *s_orig_wallhit   = nullptr;
static void *s_orig_knockdown = nullptr;
static void *s_orig_collider  = nullptr;
static void *s_orig_setpos    = nullptr;  // Transform.set_position
static void *s_orig_getpos    = nullptr;  // Transform.get_position
static void *s_orig_gettrans  = nullptr;  // Component.get_transform
static void *s_orig_update    = nullptr;  // Player.Update (teleport tick)

// RecoilFormula — returns float; extra void* params absorb any signature variant
static float hook_recoil(void *self, void *a1, void *a2, void *a3, void *a4) {
    if (s_anti_recoil || s_no_spread) return 0.0f;
    using Fn = float (*)(void *, void *, void *, void *, void *);
    return reinterpret_cast<Fn>(s_orig_recoil)(self, a1, a2, a3, a4);
}

// RateOfFireFormula — returns float; low value = fast fire rate
static float hook_rof(void *self, void *a1, void *a2, void *a3, void *a4) {
    if (s_rapid_fire) return 0.01f;
    using Fn = float (*)(void *, void *, void *, void *, void *);
    return reinterpret_cast<Fn>(s_orig_rof)(self, a1, a2, a3, a4);
}

// TakeDamage — returns void; no-op when anti_damage active
static void hook_dmg(void *self, void *info, void *a2, void *a3, void *method) {
    if (s_anti_damage) return;
    using Fn = void (*)(void *, void *, void *, void *, void *);
    reinterpret_cast<Fn>(s_orig_dmg)(self, info, a2, a3, method);
}

// get_GrassInstances — returns collection ptr; nullptr = empty = no grass
static void *hook_grass(void *self, void *method) {
    if (s_no_grass) return nullptr;
    using Fn = void *(*)(void *, void *);
    return reinterpret_cast<Fn>(s_orig_grass)(self, method);
}

// SetSpecialRunSpeedScale — multiplies incoming scale when speed hack active
static void hook_speed(void *self, float scale, void *method) {
    float effective = s_speed_on ? scale * s_speed_mul : scale;
    using Fn = void (*)(void *, float, void *);
    reinterpret_cast<Fn>(s_orig_speed)(self, effective, method);
}

// Camera.set_fieldOfView — enforce target FOV when WidePOV active
// ARM64 IL2CPP instance setter: x0=this, s0=value (float), x1=MethodInfo*
static void hook_set_fov(void *cam, float fov, void *method) {
    using Fn = void (*)(void *, float, void *);
    reinterpret_cast<Fn>(s_orig_fov)(cam, s_wide_pov ? s_target_fov : fov, method);
}

// GiveDeltaSpeedScaleByKeyAndValue(int key, float value) — jump speed delta
// ARM64: x0=this, w1=key, s0=value, x2=MethodInfo*
static void hook_jump(void *self, int key, float value, void *method) {
    float effective = (s_high_jump && value > 0.f) ? value * s_jump_mul : value;
    using Fn = void (*)(void *, int, float, void *);
    reinterpret_cast<Fn>(s_orig_jump)(self, key, effective, method);
}

// Vehicle speed multiplier — hooks GetMaxSpeed() return value
// ARM64: x0=this, x1=MethodInfo* → returns float in s0
static float hook_vehicle(void *self, void *method) {
    using Fn = float (*)(void *, void *);
    float v = reinterpret_cast<Fn>(s_orig_vehicle)(self, method);
    return s_vehicle_on ? v * s_vehicle_mul : v;
}

// ── New hooks ────────────────────────────────────────────────────────────────

// ESP: IsVisible / GetIsVisible / get_IsVisible → always true when active
// IL2CPP bool = uint8_t (0/1), ARM64: x0=this, x1=MethodInfo* → w0
static uint8_t hook_is_visible(void *self, void *method) {
    if (s_esp) return 1;
    using Fn = uint8_t (*)(void *, void *);
    return reinterpret_cast<Fn>(s_orig_visible)(self, method);
}

// InfiniteAmmo: GetCurrentClipAmmo / get_Ammo → 999
static int hook_get_ammo(void *self, void *method) {
    if (s_inf_ammo) return 999;
    using Fn = int (*)(void *, void *);
    return reinterpret_cast<Fn>(s_orig_ammo)(self, method);
}

// NoReload: IsNeedReload / NeedReload → false
static uint8_t hook_is_reload(void *self, void *method) {
    if (s_no_reload) return 0;
    using Fn = uint8_t (*)(void *, void *);
    return reinterpret_cast<Fn>(s_orig_reload)(self, method);
}

// WallShoot: CheckHit / IsHitWall / CheckObstacle → 0 (no wall)
// Extra void* args absorb any signature variant safely in ARM64
static uint8_t hook_wall_hit(void *self, void *a1, void *a2, void *method) {
    if (s_wall_shoot) return 0;
    using Fn = uint8_t (*)(void *, void *, void *, void *);
    return reinterpret_cast<Fn>(s_orig_wallhit)(self, a1, a2, method);
}

// AutoRevive: get_IsKnockDown → always false (player never knocked)
static uint8_t hook_is_knockdown(void *self, void *method) {
    if (s_auto_revive) return 0;
    using Fn = uint8_t (*)(void *, void *);
    return reinterpret_cast<Fn>(s_orig_knockdown)(self, method);
}

// NoClip: OnControllerColliderHit → no-op so physics obstacles are ignored
static void hook_collider_hit(void *self, void *hit, void *method) {
    if (s_noclip) return;
    using Fn = void (*)(void *, void *, void *);
    reinterpret_cast<Fn>(s_orig_collider)(self, hit, method);
}

// Teleport tick: hooked onto Player.Update.
// ARM64 Vector3 HFA: set_position(Transform* x0, float s0,s1,s2, MethodInfo* x1)
//                    get_position returns floats in s0/s1/s2
static void hook_player_update(void *self, void *method) {
    if (s_orig_gettrans && s_orig_setpos && s_orig_getpos) {
        using GetTransFn = void *(*)(void *, void *);
        void *tr = reinterpret_cast<GetTransFn>(s_orig_gettrans)(self, nullptr);
        if (tr) {
            // Save current position when requested
            if (!s_tp_has_save) {
                using GetPosFn = Vec3 (*)(void *, void *);
                s_tp_saved   = reinterpret_cast<GetPosFn>(s_orig_getpos)(tr, nullptr);
                s_tp_has_save = true;
                LOGI("TeleportSave: pos=(%.2f,%.2f,%.2f)",
                     s_tp_saved.x, s_tp_saved.y, s_tp_saved.z);
            }
            // Teleport to saved position when requested
            if (s_tp_pending) {
                using SetPosFn = void (*)(void *, float, float, float, void *);
                reinterpret_cast<SetPosFn>(s_orig_setpos)(
                    tr, s_tp_saved.x, s_tp_saved.y, s_tp_saved.z, nullptr);
                s_tp_pending = false;
            }
        }
    }
    using Fn = void (*)(void *, void *);
    reinterpret_cast<Fn>(s_orig_update)(self, method);
}

// ── Feature implementations ───────────────────────────────────────────────────

void FeatureEngine::applyAntiRecoil(bool enable) {
    s_anti_recoil = enable;
    if (!m_mth.recoilFormula || !m_mth.recoilFormula->methodPointer) return;
    if (enable && !s_orig_recoil) {
        HookEngine::get().hookAddr(m_mth.recoilFormula->methodPointer,
            reinterpret_cast<void *>(hook_recoil), &s_orig_recoil, "AntiRecoil");
    } else if (!enable && !s_no_spread && s_orig_recoil) {
        HookEngine::get().unhook(m_mth.recoilFormula->methodPointer);
        s_orig_recoil = nullptr;
    }
    LOGI("AntiRecoil: %s", enable ? "ON" : "OFF");
}

void FeatureEngine::applyNoSpread(bool enable) {
    s_no_spread = enable;
    if (!m_mth.recoilFormula || !m_mth.recoilFormula->methodPointer) return;
    if (enable && !s_orig_recoil) {
        HookEngine::get().hookAddr(m_mth.recoilFormula->methodPointer,
            reinterpret_cast<void *>(hook_recoil), &s_orig_recoil, "NoSpread");
    } else if (!enable && !s_anti_recoil && s_orig_recoil) {
        HookEngine::get().unhook(m_mth.recoilFormula->methodPointer);
        s_orig_recoil = nullptr;
    }
    LOGI("NoSpread: %s", enable ? "ON" : "OFF");
}

void FeatureEngine::applyRapidFire(bool enable) {
    s_rapid_fire = enable;
    if (!m_mth.rateOfFire || !m_mth.rateOfFire->methodPointer) return;
    if (enable && !s_orig_rof) {
        HookEngine::get().hookAddr(m_mth.rateOfFire->methodPointer,
            reinterpret_cast<void *>(hook_rof), &s_orig_rof, "RapidFire");
    } else if (!enable && s_orig_rof) {
        HookEngine::get().unhook(m_mth.rateOfFire->methodPointer);
        s_orig_rof = nullptr;
    }
    LOGI("RapidFire: %s", enable ? "ON" : "OFF");
}

void FeatureEngine::applyAimAssist(bool enable) {
    if (!m_mth.calcAimTarget || !m_mth.calcAimTarget->methodPointer) return;
    if (enable && !s_orig_aim) {
        // Pass-through hook — future: bend aim vector toward nearest player
        HookEngine::get().hookAddr(m_mth.calcAimTarget->methodPointer,
            reinterpret_cast<void *>(+[](void *self, void *a1, void *a2, void *a3) -> void * {
                using Fn = void *(*)(void *, void *, void *, void *);
                return reinterpret_cast<Fn>(s_orig_aim)(self, a1, a2, a3);
            }), &s_orig_aim, "AimAssist");
    } else if (!enable && s_orig_aim) {
        HookEngine::get().unhook(m_mth.calcAimTarget->methodPointer);
        s_orig_aim = nullptr;
    }
    LOGI("AimAssist: %s", enable ? "ON" : "OFF");
}

void FeatureEngine::applySpeedHack(bool enable, float multiplier) {
    s_speed_on  = enable;
    s_speed_mul = multiplier;
    if (!m_mth.setSpeedScale || !m_mth.setSpeedScale->methodPointer) return;
    if (enable && !s_orig_speed) {
        HookEngine::get().hookAddr(m_mth.setSpeedScale->methodPointer,
            reinterpret_cast<void *>(hook_speed), &s_orig_speed, "SpeedHack");
    } else if (!enable && s_orig_speed) {
        HookEngine::get().unhook(m_mth.setSpeedScale->methodPointer);
        s_orig_speed = nullptr;
    }
    LOGI("SpeedHack: %s (x%.2f)", enable ? "ON" : "OFF", multiplier);
}

void FeatureEngine::applyHighJump(bool enable) {
    s_high_jump = enable;
    // Try to resolve jump method on first enable
    if (enable && !s_orig_jump && m_cls.Character) {
        // Common jump-related method names in COW.GamePlay.PlayerAttributes
        static const char *kJumpNames[] = {
            "GiveDeltaSpeedScaleByKeyAndValue",
            "SetJumpSpeedScale",
            "AddJumpForce",
            "DoJump",
            "Jump",
            nullptr
        };
        for (int i = 0; kJumpNames[i]; ++i) {
            MethodInfo *m = Il2CppApi::getMethod(m_cls.Character, kJumpNames[i], -1);
            if (m && m->methodPointer) {
                m_mth.jumpMethod = m;
                HookEngine::get().hookAddr(m->methodPointer,
                    reinterpret_cast<void *>(hook_jump), &s_orig_jump, "HighJump");
                LOGI("HighJump: hooked via %s", kJumpNames[i]);
                break;
            }
        }
        if (!s_orig_jump) {
            // Fallback: try on Player class
            if (m_cls.Player) {
                for (int i = 0; kJumpNames[i]; ++i) {
                    MethodInfo *m = Il2CppApi::getMethod(m_cls.Player, kJumpNames[i], -1);
                    if (m && m->methodPointer) {
                        m_mth.jumpMethod = m;
                        HookEngine::get().hookAddr(m->methodPointer,
                            reinterpret_cast<void *>(hook_jump), &s_orig_jump, "HighJump");
                        LOGI("HighJump: hooked via Player::%s", kJumpNames[i]);
                        break;
                    }
                }
            }
        }
        if (!s_orig_jump) LOGE("HighJump: no suitable method found in class tree");
    } else if (!enable && s_orig_jump && m_mth.jumpMethod) {
        HookEngine::get().unhook(m_mth.jumpMethod->methodPointer);
        s_orig_jump = nullptr;
    }
    LOGI("HighJump: %s (mul=%.2f)", enable ? "ON" : "OFF", s_jump_mul);
}

void FeatureEngine::applyVehicleSpeed(bool enable, float multiplier) {
    s_vehicle_on  = enable;
    s_vehicle_mul = multiplier;
    if (enable && !s_orig_vehicle && m_cls.Vehicle) {
        static const char *kVehicleNames[] = {
            "GetMaxSpeed",
            "get_MaxSpeed",
            "get_Speed",
            "GetSpeed",
            nullptr
        };
        for (int i = 0; kVehicleNames[i]; ++i) {
            MethodInfo *m = Il2CppApi::getMethod(m_cls.Vehicle, kVehicleNames[i], -1);
            if (m && m->methodPointer) {
                m_mth.vehicleAccel = m;
                HookEngine::get().hookAddr(m->methodPointer,
                    reinterpret_cast<void *>(hook_vehicle), &s_orig_vehicle, "VehicleSpeed");
                LOGI("VehicleSpeed: hooked via %s", kVehicleNames[i]);
                break;
            }
        }
        if (!s_orig_vehicle) LOGE("VehicleSpeed: no suitable method found in Vehicle class");
    } else if (!enable && s_orig_vehicle && m_mth.vehicleAccel) {
        HookEngine::get().unhook(m_mth.vehicleAccel->methodPointer);
        s_orig_vehicle = nullptr;
    }
    LOGI("VehicleSpeed: %s (x%.2f)", enable ? "ON" : "OFF", multiplier);
}

void FeatureEngine::applyWidePOV(float fov) {
    s_target_fov = fov;
    s_wide_pov   = (fov > 0.f);
    if (!m_mth.setCameraFov || !m_mth.setCameraFov->methodPointer) {
        LOGE("WidePOV: Camera.set_fieldOfView not resolved — UnityEngine image missing?");
        return;
    }
    if (s_wide_pov && !s_orig_fov) {
        HookEngine::get().hookAddr(m_mth.setCameraFov->methodPointer,
            reinterpret_cast<void *>(hook_set_fov), &s_orig_fov, "WidePOV");
    } else if (!s_wide_pov && s_orig_fov) {
        HookEngine::get().unhook(m_mth.setCameraFov->methodPointer);
        s_orig_fov = nullptr;
    }
    LOGI("WidePOV: %.1f", fov);
}

void FeatureEngine::applyNoGrass(bool enable) {
    s_no_grass = enable;
    if (!m_mth.getGrassInst || !m_mth.getGrassInst->methodPointer) return;
    if (enable && !s_orig_grass) {
        HookEngine::get().hookAddr(m_mth.getGrassInst->methodPointer,
            reinterpret_cast<void *>(hook_grass), &s_orig_grass, "NoGrass");
    } else if (!enable && s_orig_grass) {
        HookEngine::get().unhook(m_mth.getGrassInst->methodPointer);
        s_orig_grass = nullptr;
    }
    LOGI("NoGrass: %s", enable ? "ON" : "OFF");
}

void FeatureEngine::applyMaxHealth(bool enable) {
    // TakeDamage hook already caps damage to 0; MaxHealth kept as separate toggle
    // pending actual HP field offset from obfuscated PlayerAttributes fields
    LOGI("MaxHealth: %s (pending obfuscated field offset)", enable ? "ON" : "OFF");
}

void FeatureEngine::applyAntiDamage(bool enable) {
    s_anti_damage = enable;
    if (!m_mth.takeDamage || !m_mth.takeDamage->methodPointer) return;
    if (enable && !s_orig_dmg) {
        HookEngine::get().hookAddr(m_mth.takeDamage->methodPointer,
            reinterpret_cast<void *>(hook_dmg), &s_orig_dmg, "AntiDamage");
    } else if (!enable && s_orig_dmg) {
        HookEngine::get().unhook(m_mth.takeDamage->methodPointer);
        s_orig_dmg = nullptr;
    }
    LOGI("AntiDamage: %s", enable ? "ON" : "OFF");
}

// ─────────────────────────────────────────────────────────────────────────────
// ── New feature implementations ──────────────────────────────────────────────

void FeatureEngine::applyESP(bool enable) {
    s_esp = enable;
    if (!m_mth.isVisible || !m_mth.isVisible->methodPointer) {
        LOGE("ESP: visibility method not resolved — unable to hook");
        return;
    }
    if (enable && !s_orig_visible) {
        HookEngine::get().hookAddr(m_mth.isVisible->methodPointer,
            reinterpret_cast<void *>(hook_is_visible), &s_orig_visible, "ESP");
    } else if (!enable && s_orig_visible) {
        HookEngine::get().unhook(m_mth.isVisible->methodPointer);
        s_orig_visible = nullptr;
    }
    LOGI("ESP: %s", enable ? "ON" : "OFF");
}

void FeatureEngine::applyInfiniteAmmo(bool enable) {
    s_inf_ammo = enable;
    if (!m_mth.getCurrentAmmo || !m_mth.getCurrentAmmo->methodPointer) {
        LOGE("InfiniteAmmo: ammo getter not resolved");
        return;
    }
    if (enable && !s_orig_ammo) {
        HookEngine::get().hookAddr(m_mth.getCurrentAmmo->methodPointer,
            reinterpret_cast<void *>(hook_get_ammo), &s_orig_ammo, "InfAmmo");
    } else if (!enable && s_orig_ammo) {
        HookEngine::get().unhook(m_mth.getCurrentAmmo->methodPointer);
        s_orig_ammo = nullptr;
    }
    LOGI("InfiniteAmmo: %s", enable ? "ON" : "OFF");
}

void FeatureEngine::applyNoReload(bool enable) {
    s_no_reload = enable;
    if (!m_mth.isNeedReload || !m_mth.isNeedReload->methodPointer) {
        LOGE("NoReload: reload check not resolved");
        return;
    }
    if (enable && !s_orig_reload) {
        HookEngine::get().hookAddr(m_mth.isNeedReload->methodPointer,
            reinterpret_cast<void *>(hook_is_reload), &s_orig_reload, "NoReload");
    } else if (!enable && s_orig_reload) {
        HookEngine::get().unhook(m_mth.isNeedReload->methodPointer);
        s_orig_reload = nullptr;
    }
    LOGI("NoReload: %s", enable ? "ON" : "OFF");
}

void FeatureEngine::applyWallShoot(bool enable) {
    s_wall_shoot = enable;
    if (!m_mth.checkWallHit || !m_mth.checkWallHit->methodPointer) {
        LOGE("WallShoot: wall-hit check not resolved");
        return;
    }
    if (enable && !s_orig_wallhit) {
        HookEngine::get().hookAddr(m_mth.checkWallHit->methodPointer,
            reinterpret_cast<void *>(hook_wall_hit), &s_orig_wallhit, "WallShoot");
    } else if (!enable && s_orig_wallhit) {
        HookEngine::get().unhook(m_mth.checkWallHit->methodPointer);
        s_orig_wallhit = nullptr;
    }
    LOGI("WallShoot: %s", enable ? "ON" : "OFF");
}

void FeatureEngine::applyAutoRevive(bool enable) {
    s_auto_revive = enable;
    if (!m_mth.isKnockDown || !m_mth.isKnockDown->methodPointer) {
        LOGE("AutoRevive: knockdown getter not resolved");
        return;
    }
    if (enable && !s_orig_knockdown) {
        HookEngine::get().hookAddr(m_mth.isKnockDown->methodPointer,
            reinterpret_cast<void *>(hook_is_knockdown), &s_orig_knockdown, "AutoRevive");
    } else if (!enable && s_orig_knockdown) {
        HookEngine::get().unhook(m_mth.isKnockDown->methodPointer);
        s_orig_knockdown = nullptr;
    }
    LOGI("AutoRevive: %s", enable ? "ON" : "OFF");
}

void FeatureEngine::applyNoClip(bool enable) {
    s_noclip = enable;
    if (!m_mth.colliderHit || !m_mth.colliderHit->methodPointer) {
        LOGE("NoClip: OnControllerColliderHit not resolved");
        return;
    }
    if (enable && !s_orig_collider) {
        HookEngine::get().hookAddr(m_mth.colliderHit->methodPointer,
            reinterpret_cast<void *>(hook_collider_hit), &s_orig_collider, "NoClip");
    } else if (!enable && s_orig_collider) {
        HookEngine::get().unhook(m_mth.colliderHit->methodPointer);
        s_orig_collider = nullptr;
    }
    LOGI("NoClip: %s", enable ? "ON" : "OFF");
}

void FeatureEngine::applyTeleportSave() {
    if (!m_mth.playerUpdate || !m_mth.playerUpdate->methodPointer) {
        LOGE("TeleportSave: Player.Update not resolved");
        return;
    }
    // Cache orig pointers for the tick hook
    if (m_mth.setPosition) s_orig_setpos  = m_mth.setPosition->methodPointer;
    if (m_mth.getPosition) s_orig_getpos  = m_mth.getPosition->methodPointer;
    if (m_mth.getTransform) s_orig_gettrans = m_mth.getTransform->methodPointer;
    // Signal tick hook to capture position on next Player.Update call
    s_tp_has_save = false;
    // Install tick hook if not already there
    if (!s_orig_update) {
        HookEngine::get().hookAddr(m_mth.playerUpdate->methodPointer,
            reinterpret_cast<void *>(hook_player_update), &s_orig_update, "TpTick");
    }
    LOGI("TeleportSave: capturing position on next Update");
}

void FeatureEngine::applyTeleport() {
    if (!s_tp_has_save) {
        LOGE("Teleport: no saved position — call TeleportSave first");
        return;
    }
    if (!m_mth.playerUpdate || !m_mth.playerUpdate->methodPointer) {
        LOGE("Teleport: Player.Update not resolved");
        return;
    }
    // Cache orig pointers
    if (m_mth.setPosition)  s_orig_setpos   = m_mth.setPosition->methodPointer;
    if (m_mth.getPosition)  s_orig_getpos   = m_mth.getPosition->methodPointer;
    if (m_mth.getTransform) s_orig_gettrans = m_mth.getTransform->methodPointer;
    s_tp_pending = true;
    if (!s_orig_update) {
        HookEngine::get().hookAddr(m_mth.playerUpdate->methodPointer,
            reinterpret_cast<void *>(hook_player_update), &s_orig_update, "TpTick");
    }
    LOGI("Teleport: will move to (%.2f,%.2f,%.2f) on next Update",
         s_tp_saved.x, s_tp_saved.y, s_tp_saved.z);
}

// ── Command dispatch ──────────────────────────────────────────────────────────

void FeatureEngine::dispatch(uint8_t cmd, bool enable, float intensity) {
    switch (cmd) {
        // ── Weapon ──────────────────────────────────────────────────────────
        case ZX_ANTI_RECOIL:   applyAntiRecoil(enable); break;
        case ZX_NO_SPREAD:     applyNoSpread(enable); break;
        case ZX_RAPID_FIRE:
        case ZX_RAPID_RISK:    applyRapidFire(enable); break;

        // ── Aim ─────────────────────────────────────────────────────────────
        case ZX_AIM_ENABLE:
        case ZX_AIM_BONE:
        case ZX_AIM_FOV:
        case ZX_AIM_SMOOTH:
        case ZX_SILENT_AIM:
        case ZX_AUTO_HEADSHOT:
        case ZX_FULL_AIMBOT:
        case ZX_ANTI_AIM:      applyAimAssist(enable); break;

        // ── Movement ────────────────────────────────────────────────────────
        case ZX_SPEED_HACK:    applySpeedHack(enable, intensity > 0.f ? intensity / 100.f + 1.f : 1.5f); break;
        case ZX_HIGH_JUMP:     { s_jump_mul = intensity > 0.f ? intensity / 100.f + 1.f : 2.5f; applyHighJump(enable); } break;
        case ZX_VEHICLE_SPEED: applyVehicleSpeed(enable, intensity > 0.f ? intensity / 100.f + 1.f : 2.0f); break;

        // ── Visual ──────────────────────────────────────────────────────────
        case ZX_WIDE_POV:      applyWidePOV(enable ? (intensity > 0.f ? intensity : 85.0f) : 0.f); break;
        case ZX_NO_GRASS:      applyNoGrass(enable); break;

        // ── Survival ────────────────────────────────────────────────────────
        case ZX_ANTI_DAMAGE:   applyAntiDamage(enable); break;
        case ZX_GOD_MODE:      applyAntiDamage(enable); break; // god = block all damage

        // ── New features ─────────────────────────────────────────────────────
        case ZX_ESP:           applyESP(enable); break;
        case ZX_INFINITE_AMMO: applyInfiniteAmmo(enable); break;
        case ZX_NO_RELOAD:     applyNoReload(enable); break;
        case ZX_WALL_SHOOT:    applyWallShoot(enable); break;
        case ZX_AUTO_REVIVE:   applyAutoRevive(enable); break;
        case ZX_NOCLIP:        applyNoClip(enable); break;
        case ZX_TELEPORT_SAVE: applyTeleportSave(); break;
        case ZX_TELEPORT:      applyTeleport(); break;

        default:
            LOGE("dispatch: unknown cmd %d", (int)cmd);
    }
}

// ── Unix socket server ────────────────────────────────────────────────────────

void *FeatureEngine::serverThread(void *self) {
    static_cast<FeatureEngine *>(self)->runServer();
    return nullptr;
}

void FeatureEngine::startServer() {
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &attr, serverThread, this);
    pthread_attr_destroy(&attr);
    LOGI("Socket server thread started");
}

void FeatureEngine::runServer() {
    int srv = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (srv < 0) { LOGE("socket(): %s", strerror(errno)); return; }

    // Abstract socket — sun_path[0]='\0' + name, no filesystem entry needed
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    memset(addr.sun_path, 0, sizeof(addr.sun_path));
    size_t name_len = strlen(kSockName);
    memcpy(addr.sun_path + 1, kSockName, name_len);
    socklen_t addr_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + name_len);

    if (bind(srv, reinterpret_cast<struct sockaddr *>(&addr), addr_len) < 0) {
        LOGE("bind(\\0%s): %s", kSockName, strerror(errno));
        ::close(srv); return;
    }

    listen(srv, 8);
    LOGI("Socket server listening on \\0%s", kSockName);

    while (true) {
        int cli = accept(srv, nullptr, nullptr);
        if (cli < 0) {
            if (errno == EINTR) continue;
            LOGE("accept(): %s", strerror(errno));
            break;
        }

        ZxPacket pkt{};
        ssize_t n;
        while ((n = recv(cli, &pkt, sizeof(pkt), MSG_WAITALL)) == (ssize_t)sizeof(pkt)) {
            dispatch(pkt.cmd, pkt.enable != 0, pkt.intensity);
            // ACK: send back 1 byte so client knows it was processed
            uint8_t ack = 1;
            send(cli, &ack, 1, MSG_NOSIGNAL);
        }
        ::close(cli);
    }
    ::close(srv);
}
