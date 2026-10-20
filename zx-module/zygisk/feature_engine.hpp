#pragma once
#include "il2cpp_api.hpp"
#include "async_worker.hpp"

// Feature command IDs — shared with the Android app's socket client
enum ZxCmd : uint8_t {
    ZX_ANTI_RECOIL    = 1,  ZX_NO_SPREAD      = 2,
    ZX_RAPID_FIRE     = 3,  ZX_WIDE_POV       = 4,
    ZX_SPEED_HACK     = 6,  ZX_HIGH_JUMP      = 7,
    ZX_VEHICLE_SPEED  = 8,  ZX_RAPID_RISK     = 9,
    ZX_NO_GRASS       = 10, ZX_ANTI_DAMAGE    = 11,
    ZX_AIM_ENABLE     = 12, ZX_AIM_BONE       = 13,
    ZX_AIM_FOV        = 14, ZX_AIM_SMOOTH     = 15,
    ZX_MAX_HEALTH     = 16,
};

#pragma pack(push, 1)
struct ZxPacket {
    uint8_t cmd;
    uint8_t enable;   // 1=on, 0=off
    float   intensity; // optional multiplier / angle / percentage
};
#pragma pack(pop)

class FeatureEngine {
public:
    static FeatureEngine &get();

    void init(AsyncWorker *worker);

    // Start the Unix socket server (call from worker thread after init)
    void startServer();

    // Dispatch a command received via socket (or called directly)
    void dispatch(uint8_t cmd, bool enable, float intensity = 0.f);

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

    static void *serverThread(void *self);
    void runServer();
};
