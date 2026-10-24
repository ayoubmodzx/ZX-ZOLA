#pragma once
#include "il2cpp_api.hpp"
#include "async_worker.hpp"

// Feature command IDs — must match ZxEngine.Cmd in the Android app exactly
enum ZxCmd : uint8_t {
    ZX_ANTI_RECOIL    = 1,  ZX_NO_SPREAD      = 2,
    ZX_RAPID_FIRE     = 3,  ZX_WIDE_POV       = 4,
    ZX_ESP            = 5,
    ZX_SPEED_HACK     = 6,  ZX_HIGH_JUMP      = 7,
    ZX_VEHICLE_SPEED  = 8,  ZX_RAPID_RISK     = 9,
    ZX_NO_GRASS       = 10, ZX_ANTI_DAMAGE    = 11,
    ZX_AIM_ENABLE     = 12, ZX_AIM_BONE       = 13,
    ZX_AIM_FOV        = 14, ZX_AIM_SMOOTH     = 15,
    ZX_GOD_MODE       = 16,
    ZX_INFINITE_AMMO  = 17, ZX_NO_RELOAD      = 18,
    ZX_NOCLIP         = 19, ZX_TELEPORT       = 20,
    ZX_TELEPORT_SAVE  = 21, ZX_SILENT_AIM     = 22,
    ZX_AUTO_HEADSHOT  = 23, ZX_FULL_AIMBOT    = 24,
    ZX_ANTI_AIM       = 25, ZX_AUTO_REVIVE    = 26,
    ZX_WALL_SHOOT     = 27,
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

    // ── HEADSHOT / AIMBOT ─────────────────────────────────────────
    void applyAutoHeadshot(bool enable = true);
    void applySilentAim(bool enable = true);
    void applyFullAimbot(bool enable = true);
    void applyAntiAim(bool enable = true);

    // ── MOVEMENT ──────────────────────────────────────────────────
    void applySpeedHack(bool enable = true, float multiplier = 1.5f);
    void applyHighJump(bool enable = true);
    void applyVehicleSpeed(bool enable = true, float multiplier = 2.0f);

    // ── VISUAL ────────────────────────────────────────────────────
    void applyWidePOV(float fov = 85.0f);
    void applyNoGrass(bool enable = true);
    void applyESP(bool enable = true);

    // ── SURVIVAL ─────────────────────────────────────────────────
    void applyMaxHealth(bool enable = true);
    void applyAntiDamage(bool enable = true);
    void applyAutoRevive(bool enable = true);

    // ── WEAPON ────────────────────────────────────────────────────
    void applyInfiniteAmmo(bool enable = true);
    void applyNoReload(bool enable = true);
    void applyWallShoot(bool enable = true);

    // ── MOBILITY ──────────────────────────────────────────────────
    void applyNoClip(bool enable = true);
    void applyTeleportSave();
    void applyTeleport();

    bool isReady() const { return m_ready; }

private:
    FeatureEngine() = default;

    AsyncWorker *m_worker = nullptr;
    bool         m_ready  = false;

    struct Classes {
        Il2CppClass *Player       = nullptr;
        Il2CppClass *Character    = nullptr;
        Il2CppClass *Health       = nullptr;
        Il2CppClass *Weapon       = nullptr;
        Il2CppClass *Bullet       = nullptr;
        Il2CppClass *Recoil       = nullptr;
        Il2CppClass *Camera       = nullptr;
        Il2CppClass *Aim          = nullptr;
        Il2CppClass *Grass        = nullptr;
        Il2CppClass *Vehicle      = nullptr;
        Il2CppClass *Loot         = nullptr;
        Il2CppClass *UnityCamera  = nullptr;  // UnityEngine.Camera — for WidePOV
        Il2CppClass *UnityTransform = nullptr; // UnityEngine.Transform — for Teleport
        Il2CppClass *ResIdDef     = nullptr;  // COW::ResourceIDDef — singleton outline manager
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
        MethodInfo *calcAimTarget  = nullptr;
        MethodInfo *takeDamage     = nullptr;
        MethodInfo *recoilFormula  = nullptr;
        MethodInfo *rateOfFire     = nullptr;
        MethodInfo *setSpeedScale  = nullptr;
        MethodInfo *getGrassInst   = nullptr;
        MethodInfo *setGrassInst   = nullptr;
        MethodInfo *setCameraFov   = nullptr;  // UnityEngine.Camera.set_fieldOfView
        MethodInfo *jumpMethod     = nullptr;  // resolved at first HighJump enable
        MethodInfo *vehicleAccel   = nullptr;  // resolved at first VehicleSpeed enable
        // ESP
        MethodInfo *isVisible      = nullptr;  // Player visibility gate
        // InfiniteAmmo / NoReload
        MethodInfo *getCurrentAmmo = nullptr;  // WeaponPropertyUtil ammo getter
        MethodInfo *isNeedReload   = nullptr;  // WeaponPropertyUtil reload check
        // WallShoot
        MethodInfo *checkWallHit   = nullptr;  // VerticleBulletController wall detect
        // AutoRevive
        MethodInfo *isKnockDown    = nullptr;  // Player knockdown state getter
        // Teleport / NoClip — resolved lazily at first enable
        MethodInfo *setPosition    = nullptr;  // UnityEngine.Transform.set_position
        MethodInfo *getPosition    = nullptr;  // UnityEngine.Transform.get_position
        MethodInfo *getTransform   = nullptr;  // Component.get_transform
        MethodInfo *colliderHit       = nullptr;  // OnControllerColliderHit (NoClip)
        MethodInfo *playerUpdate      = nullptr;  // Player.Update (Teleport tick)
        MethodInfo *hudSetVisible     = nullptr;  // PlayerHUD.SetVisible (ESP visual)
        // Neon outline ESP — Player built-in outline system (IL2CPP v31 verified)
        MethodInfo *setOutlineVisible = nullptr;  // Player.SetOutlineVisible(bool)
        MethodInfo *initOutline       = nullptr;  // Player.InitOutline()
        MethodInfo *setRenderQ        = nullptr;  // Player.SetRenderQ(int) — through-wall rendering
        MethodInfo *revertRenderQ     = nullptr;  // Player.RevertToDefaultRenderQ()
        // COW::ResourceIDDef singleton — global outline enable
        MethodInfo *resIdGetInstance  = nullptr;  // ResourceIDDef.GetInstance() [static]
        MethodInfo *tryInitOutlineRes = nullptr;  // ResourceIDDef.TryInitPlayerOutlineRes()
        MethodInfo *showPlayerOutline = nullptr;  // ResourceIDDef.ShowPlayerOutline(bool)
        // COW::GameSettingData — server-side outline gate
        MethodInfo *enableOutlineMth  = nullptr;  // GameSettingData.EnableShowPlayerOutline(bool)
        // Headshot / Aimbot — Player class
        MethodInfo *getHeadBoneTransform = nullptr; // Player.get_HeadBoneTransform()
        MethodInfo *setAimRotation       = nullptr; // Player.SetAimRotation(Vector3)
        MethodInfo *updateAiming         = nullptr; // Player.UpdateAiming()  (per-frame)
        MethodInfo *hasHeuristicTarget   = nullptr; // Player.HasHeuristicTarget() → bool
        MethodInfo *getHeuristicTarget   = nullptr; // Player.GetHeuristicTarget() → Player*
        // ResourceIDDef — headshot-only mode gate
        MethodInfo *setOnlyHeadshot      = nullptr; // ResourceIDDef.set_OnlyHeadshot(bool)
        // Headshot damage gate — direct hooks (more reliable than set_OnlyHeadshot)
        MethodInfo *checkDamageHitHead   = nullptr; // Player.CheckDamageHitHead(DamageInfo) → bool
        MethodInfo *isInNoHeadShotState  = nullptr; // Player.IsInNoHeadShotState() → bool
        // Confirmed via global-metadata.dat strings analysis (binary verified)
        MethodInfo *getHeadCollider      = nullptr; // Player.get_HeadCollider() → Collider* (REAL hitbox)
        MethodInfo *getHeadTF            = nullptr; // Player.GetHeadTF() → Transform* (head transform)
        MethodInfo *colliderGetBounds    = nullptr; // UnityEngine.Collider.get_bounds() → Bounds struct
        MethodInfo *takeDamage4          = nullptr; // Player.TakeDamage(4 params) [210713] — client prediction
    } m_mth;

    void resolveClasses();

    static void *serverThread(void *self);
    void runServer();
};
