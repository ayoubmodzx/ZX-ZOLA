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

// Global outline enable — declared here so resolveClasses() can write them
static void     *s_match_show_outline_fn      = nullptr;  // MatchGame.ShowPlayerOutline
static void     *s_match_show_team_outline_fn = nullptr;  // MatchGame.ShowTeamOutline
static void     *s_match_try_init_fn          = nullptr;  // MatchGame.TryInitPlayerOutlineRes
static void     *s_match_get_inst_fn          = nullptr;  // MatchGame.GetMatch (static)
static void     *s_gs_enable_outline_fn       = nullptr;  // GameSettingData.EnableShowPlayerOutline
static FieldInfo *s_enable_outline_field = nullptr;
// Through-wall render queue trampolines (filled by applyESP hook setup)
static void *s_orig_set_render_q    = nullptr;
static void *s_orig_revert_render_q = nullptr;
// GameSettingData game-thread permission gate
static void  *s_gs_get_instance_fn  = nullptr;  // GameSettingData.get_Instance()
static void  *s_gs_enable_team_fn   = nullptr;  // GameSettingData.EnableShowTeamOutline()
// Local-player detection + enemy tracking for aimbot
static void  *s_is_local_player_fn  = nullptr;  // Player.IsLocalPlayer()

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
    m_cls.Aim       = m_cls.Player;   // GetAttackableCenterWS is on Player, not UGCAimAssistEntity
    m_cls.Grass     = Il2CppApi::getClass(img, "COW.Graphics", "GrassSystem");
    m_cls.Vehicle   = Il2CppApi::getClass(img, "COW.GamePlay", "Vehicle");

    // Method names verified against IL2CPP v31 global-metadata.dat (Free Fire OB47)
    if (m_cls.Player)    m_mth.takeDamage    = Il2CppApi::getMethod(m_cls.Player,    "TakeDamage",               -1);
    if (m_cls.Grass)     m_mth.getGrassInst  = Il2CppApi::getMethod(m_cls.Grass,     "get_GrassInstances",        0);
    if (m_cls.Grass)     m_mth.setGrassInst  = Il2CppApi::getMethod(m_cls.Grass,     "set_GrassInstances",        1);
    // GetAttackableCenterWS is on Player (M210036, p=62) — returns world-space aim center
    if (m_cls.Player)    m_mth.calcAimTarget = Il2CppApi::getMethod(m_cls.Player,    "GetAttackableCenterWS",     0);

    // Headshot / Aimbot methods — all on Player
    if (m_cls.Player) {
        m_mth.getHeadBoneTransform = Il2CppApi::getMethod(m_cls.Player, "get_HeadBoneTransform", 0);
        // Binary-verified: get_HeadCollider returns the PHYSICS Collider (= real server-side hitbox)
        // GetHeadTF returns a Transform at the head (may differ from bone crown)
        m_mth.getHeadCollider      = Il2CppApi::getMethod(m_cls.Player, "get_HeadCollider",      0);
        m_mth.getHeadTF            = Il2CppApi::getMethod(m_cls.Player, "GetHeadTF",             0);
        m_mth.setAimRotation       = Il2CppApi::getMethod(m_cls.Player, "SetAimRotation",        -1);
        m_mth.updateAiming         = Il2CppApi::getMethod(m_cls.Player, "UpdateAiming",          -1);
        m_mth.updateAimingADS      = Il2CppApi::getMethod(m_cls.Player, "ODKFDOFOHLN",            -1);
        m_mth.hasHeuristicTarget   = Il2CppApi::getMethod(m_cls.Player, "HasHeuristicTarget",     0);
        m_mth.getHeuristicTarget   = Il2CppApi::getMethod(m_cls.Player, "GetHeuristicTarget",     0);
        LOGI("[AIM] GetAttackableCenterWS=%p GetHeadBoneTransform=%p SetAimRotation=%p",
             m_mth.calcAimTarget        ? m_mth.calcAimTarget->methodPointer        : nullptr,
             m_mth.getHeadBoneTransform ? m_mth.getHeadBoneTransform->methodPointer : nullptr,
             m_mth.setAimRotation       ? m_mth.setAimRotation->methodPointer       : nullptr);
        LOGI("[AIM] UpdateAiming=%p HasHeuristic=%p GetHeuristic=%p",
             m_mth.updateAiming       ? m_mth.updateAiming->methodPointer       : nullptr,
             m_mth.hasHeuristicTarget ? m_mth.hasHeuristicTarget->methodPointer : nullptr,
             m_mth.getHeuristicTarget ? m_mth.getHeuristicTarget->methodPointer : nullptr);
        m_mth.isLocalPlayer = Il2CppApi::getMethod(m_cls.Player, "IsLocalPlayer", 0);
        LOGI("[AIM] IsLocalPlayer=%p",
             m_mth.isLocalPlayer ? m_mth.isLocalPlayer->methodPointer : nullptr);
        LOGI("[AIM] get_HeadCollider=%p GetHeadTF=%p",
             m_mth.getHeadCollider ? m_mth.getHeadCollider->methodPointer : nullptr,
             m_mth.getHeadTF       ? m_mth.getHeadTF->methodPointer       : nullptr);
        // Headshot gate hooks — override at the damage-hit-check level
        m_mth.checkDamageHitHead  = Il2CppApi::getMethod(m_cls.Player, "CheckDamageHitHead",  -1);
        m_mth.isInNoHeadShotState = Il2CppApi::getMethod(m_cls.Player, "IsInNoHeadShotState", -1);
        // TakeDamage(4) [210713] — fires on enemy instances during client-side prediction.
        // Binary-verified: unique 4-param overload separate from TakeDamage(9).
        m_mth.takeDamage4         = Il2CppApi::getMethod(m_cls.Player, "TakeDamage",          4);
        LOGI("[AIM] CheckDamageHitHead=%p IsInNoHeadShotState=%p TakeDamage4=%p",
             m_mth.checkDamageHitHead  ? m_mth.checkDamageHitHead->methodPointer  : nullptr,
             m_mth.isInNoHeadShotState ? m_mth.isInNoHeadShotState->methodPointer : nullptr,
             m_mth.takeDamage4         ? m_mth.takeDamage4->methodPointer         : nullptr);
    }

    // SpeedHack — search multiple names across PlayerAttributes then Player
    {
        static const char *kSpeedNames[] = {
            "SetSpecialRunSpeedScale", "SetRunSpeedScale", "SetMoveSpeedScale",
            "AddRunSpeed", "SetSpeed", "SetMoveSpeed", nullptr
        };
        Il2CppClass *tgts[] = { m_cls.Character, m_cls.Player, nullptr };
        for (int t = 0; !m_mth.setSpeedScale && tgts[t]; ++t)
            for (int i = 0; kSpeedNames[i]; ++i) {
                MethodInfo *m = Il2CppApi::getMethod(tgts[t], kSpeedNames[i], -1);
                if (m && m->methodPointer) { m_mth.setSpeedScale = m; break; }
            }
    }

    // Recoil / RoF — obfuscated; try common patterns across Weapon / Player / Character
    {
        static const char *kRecoilNames[] = {
            "RecoilFormula",
            "GetRecoilScale","CalcRecoil","GetRecoil","ComputeRecoil",
            "GetRecoilValue","OnRecoil","ApplyRecoil","CalcSpread",
            "GetVerticalRecoil","GetHorizontalRecoil", nullptr
        };
        static const char *kRofNames[] = {
            "RateOfFireFormula",
            "GetFireRate","CalcFireRate","GetRateOfFire","GetFireInterval",
            "ComputeFireRate","GetShootInterval","GetFireDelay", nullptr
        };
        Il2CppClass *tgts[] = { m_cls.Weapon, m_cls.Player, m_cls.Character, nullptr };
        for (int t = 0; tgts[t]; ++t) {
            if (!m_mth.recoilFormula)
                for (int i = 0; kRecoilNames[i]; ++i) {
                    MethodInfo *m = Il2CppApi::getMethod(tgts[t], kRecoilNames[i], -1);
                    if (m && m->methodPointer) { m_mth.recoilFormula = m; break; }
                }
            if (!m_mth.rateOfFire)
                for (int i = 0; kRofNames[i]; ++i) {
                    MethodInfo *m = Il2CppApi::getMethod(tgts[t], kRofNames[i], -1);
                    if (m && m->methodPointer) { m_mth.rateOfFire = m; break; }
                }
        }
        if (!m_mth.recoilFormula) LOGE("recoilFormula: all names exhausted — still obfuscated");
        if (!m_mth.rateOfFire)    LOGE("rateOfFire: all names exhausted — still obfuscated");
    }

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
        // Collider.get_bounds() — Unity 2019+: PhysicsModule, not CoreModule.
        // Try with and without .dll suffix since strstr lookup may miss if API strips it.
        {
            Il2CppImage *physImg = Il2CppApi::getImage("UnityEngine.PhysicsModule");
            if (!physImg) physImg = Il2CppApi::getImage("UnityEngine.PhysicsModule.dll");
            if (!physImg) physImg = Il2CppApi::getImage("UnityEngine.Physics");
            Il2CppImage *imgs[] = { physImg, unityImg, nullptr };
            for (int i = 0; !m_mth.colliderGetBounds && imgs[i]; ++i) {
                if (!imgs[i]) continue;
                Il2CppClass *colliderCls = Il2CppApi::getClass(imgs[i], "UnityEngine", "Collider");
                if (colliderCls)
                    m_mth.colliderGetBounds = Il2CppApi::getMethod(colliderCls, "get_bounds", 0);
            }
        }
        LOGI("[AIM] Collider.get_bounds=%p",
             m_mth.colliderGetBounds ? m_mth.colliderGetBounds->methodPointer : nullptr);
    }

    // ESP — hook the HUD/UI draw methods that render enemy indicators
    // IsVisible gate is also hooked for culling, but the real visual effect
    // requires forcing the enemy health bar / name plate to always render.
    if (m_cls.Player) {
        m_mth.isVisible = Il2CppApi::getMethod(m_cls.Player, "IsVisible", 0);

        // Scan ALL Player methods first — dumps exact names/params to logcat so we know
        // what the runtime actually exposes (SetOutlineVisible may be named differently or
        // on a subcomponent).
        LOGI("[ESP-DIAG] === Scanning Player methods for 'utline' ===");
        Il2CppApi::scanMethods(m_cls.Player, "utline");
        LOGI("[ESP-DIAG] === Scanning Player methods for 'Outline' ===");
        Il2CppApi::scanMethods(m_cls.Player, "Outline");
        LOGI("[ESP-DIAG] === Scanning Player methods for 'outline' ===");
        Il2CppApi::scanMethods(m_cls.Player, "outline");
        LOGI("[ESP-DIAG] === Scanning Player methods for 'Visible' ===");
        Il2CppApi::scanMethods(m_cls.Player, "Visible");
        LOGI("[ESP-DIAG] === Scanning Player methods for 'Color' ===");
        Il2CppApi::scanMethods(m_cls.Player, "Color");
        LOGI("[ESP-DIAG] === Scanning Player methods for 'Render' ===");
        Il2CppApi::scanMethods(m_cls.Player, "Render");

        // Try to resolve via iterator first; fall back to name lookup
        m_mth.setOutlineVisible = Il2CppApi::scanMethods(m_cls.Player, "SetOutlineVisible");
        if (!m_mth.setOutlineVisible || !m_mth.setOutlineVisible->methodPointer) {
            m_mth.setOutlineVisible = Il2CppApi::getMethod(m_cls.Player, "SetOutlineVisible", -1);
            if (!m_mth.setOutlineVisible || !m_mth.setOutlineVisible->methodPointer)
                m_mth.setOutlineVisible = Il2CppApi::getMethod(m_cls.Player, "SetOutlineVisible", 1);
        }
        m_mth.initOutline = Il2CppApi::scanMethods(m_cls.Player, "InitOutline");
        if (!m_mth.initOutline || !m_mth.initOutline->methodPointer) {
            m_mth.initOutline = Il2CppApi::getMethod(m_cls.Player, "InitOutline", -1);
            if (!m_mth.initOutline || !m_mth.initOutline->methodPointer)
                m_mth.initOutline = Il2CppApi::getMethod(m_cls.Player, "InitOutline", 0);
        }
    }
    LOGI("[ESP-DIAG] resolve: Player=%p isVisible=%p setOutlineVisible=%p initOutline=%p",
         (void*)m_cls.Player,
         m_mth.isVisible         ? m_mth.isVisible->methodPointer         : nullptr,
         m_mth.setOutlineVisible ? m_mth.setOutlineVisible->methodPointer : nullptr,
         m_mth.initOutline       ? m_mth.initOutline->methodPointer       : nullptr);
    if (!m_mth.setOutlineVisible || !m_mth.setOutlineVisible->methodPointer)
        LOGE("[ESP-DIAG] SetOutlineVisible NOT found even via iterator scan");
    if (!m_mth.initOutline || !m_mth.initOutline->methodPointer)
        LOGE("[ESP-DIAG] InitOutline NOT found even via iterator scan");

    // Search for the HUD class that renders enemy name/health plates
    static const char *kHudClasses[] = {
        "PlayerHUD", "EnemyHUD", "EnemyIndicator", "PlayerIndicator",
        "PlayerNamePlate", "HUDPlayerItem", "PlayerInfoHUD", nullptr
    };
    static const char *kHudNamespaces[] = {
        "COW.GamePlay", "COW.UI", "COW", "COW.HUD", nullptr
    };
    Il2CppClass *hudCls = nullptr;
    for (int ns = 0; !hudCls && kHudNamespaces[ns]; ++ns)
        for (int c = 0; kHudClasses[c]; ++c) {
            hudCls = Il2CppApi::getClass(img, kHudNamespaces[ns], kHudClasses[c]);
            if (hudCls) { LOGI("ESP HUD class: %s::%s", kHudNamespaces[ns], kHudClasses[c]); break; }
        }

    if (hudCls) {
        // Force enemy health bar / name plate to always be visible
        static const char *kShowNames[] = {
            "SetVisible","Show","OnShow","SetActive","SetEnemyVisible",
            "UpdateVisible","RefreshVisible","ForceShow","SetShowState", nullptr
        };
        for (int i = 0; kShowNames[i]; ++i) {
            MethodInfo *m = Il2CppApi::getMethod(hudCls, kShowNames[i], -1);
            if (m && m->methodPointer) {
                m_mth.hudSetVisible = m;
                LOGI("ESP HUD method: %s", kShowNames[i]);
                break;
            }
        }
    }
    if (!hudCls || !m_mth.hudSetVisible)
        LOGE("ESP: HUD class/method not found — IsVisible-only mode (no visible boxes)");

    // InfiniteAmmo — get_IsAmmoFree (bool) on PlayerAttributes (index 245979)
    // WeaponPropertyUtil has 0 exposed methods in this build; PlayerAttributes is the right target
    if (m_cls.Character)
        m_mth.getCurrentAmmo = Il2CppApi::getMethod(m_cls.Character, "get_IsAmmoFree", 0);

    // NoReload — IsReloading on Player (index 210813)
    if (m_cls.Player)
        m_mth.isNeedReload = Il2CppApi::getMethod(m_cls.Player, "IsReloading", 0);

    // WallShoot — search multiple names on VerticleBulletController
    if (m_cls.Bullet) {
        static const char *kFireNames[] = {
            "CanFire","CheckCanFire","IsCanFire","get_CanFire",
            "CanShoot","IsAllowedToFire","CheckWallPenetration", nullptr
        };
        for (int i = 0; kFireNames[i]; ++i) {
            MethodInfo *m = Il2CppApi::getMethod(m_cls.Bullet, kFireNames[i], -1);
            if (m && m->methodPointer) { m_mth.checkWallHit = m; break; }
        }
        if (!m_mth.checkWallHit) LOGE("WallShoot: no method found on VerticleBulletController");
    }

    // AutoRevive — get_IsPendingRevive on Player (index 210262); return 1 triggers revive logic
    if (m_cls.Player)
        m_mth.isKnockDown = Il2CppApi::getMethod(m_cls.Player, "get_IsPendingRevive", 0);

    // NoClip — interface-mangled name on Player (IL2CPP explicit interface implementation)
    if (m_cls.Player)
        m_mth.colliderHit = Il2CppApi::getMethod(m_cls.Player,
            "COW.GamePlay.IPhysicalCharacter.OnControllerColliderHit", 1);

    // Teleport tick — search multiple Update names on Player
    if (m_cls.Player) {
        static const char *kUpdateNames[] = {
            "OnUpdate","Update","Tick","OnTick","FixedUpdate","LateUpdate", nullptr
        };
        for (int i = 0; kUpdateNames[i]; ++i) {
            MethodInfo *m = Il2CppApi::getMethod(m_cls.Player, kUpdateNames[i], -1);
            if (m && m->methodPointer) { m_mth.playerUpdate = m; break; }
        }
        if (!m_mth.playerUpdate) LOGE("Teleport: no Update method found on Player");
    }

    // Player.SetRenderQ(int) — sets render queue to 5000+ so player renders above walls
    // Player.RevertToDefaultRenderQ() — restores normal render queue on ESP off
    if (m_cls.Player) {
        m_mth.setRenderQ    = Il2CppApi::getMethod(m_cls.Player, "SetRenderQ",              -1);
        m_mth.revertRenderQ = Il2CppApi::getMethod(m_cls.Player, "RevertToDefaultRenderQ",  0);
        LOGI("[ESP] SetRenderQ=%p RevertRenderQ=%p",
             m_mth.setRenderQ    ? m_mth.setRenderQ->methodPointer    : nullptr,
             m_mth.revertRenderQ ? m_mth.revertRenderQ->methodPointer : nullptr);
    }

    // COW::MatchGame — confirmed via global-metadata.dat strings analysis:
    //   TryInitPlayerOutlineRes and ShowPlayerOutline are on COW.MatchGame, NOT ResourceIDDef.
    //   MatchGame.GetMatch() is the static singleton accessor (COW-MatchGame-GetMatch0 in metadata).
    {
        Il2CppClass *matchGameCls = Il2CppApi::getClass(img, "COW", "MatchGame");
        m_cls.ResIdDef = matchGameCls;  // reuse slot — ResIdDef had no outline methods
        if (matchGameCls) {
            // GetMatch() is the static self-accessor — returns the live MatchGame singleton
            m_mth.resIdGetInstance  = Il2CppApi::getMethod(matchGameCls, "GetMatch",               -1);
            m_mth.tryInitOutlineRes = Il2CppApi::getMethod(matchGameCls, "TryInitPlayerOutlineRes", -1);
            m_mth.showPlayerOutline = Il2CppApi::getMethod(matchGameCls, "ShowPlayerOutline",       -1);
            LOGI("[ESP] MatchGame: GetMatch=%p TryInitOutlineRes=%p ShowPlayerOutline=%p",
                 m_mth.resIdGetInstance  ? m_mth.resIdGetInstance->methodPointer  : nullptr,
                 m_mth.tryInitOutlineRes ? m_mth.tryInitOutlineRes->methodPointer : nullptr,
                 m_mth.showPlayerOutline ? m_mth.showPlayerOutline->methodPointer : nullptr);
        } else LOGE("[ESP] MatchGame class not found — namespace may differ");

        // GameSettingData.EnableShowPlayerOutline(bool) — permission gate on COW.GameSettingData
        Il2CppClass *gsCls = Il2CppApi::getClass(img, "COW", "GameSettingData");
        if (gsCls)
            m_mth.enableOutlineMth = Il2CppApi::getMethod(gsCls, "EnableShowPlayerOutline", -1);
        LOGI("[ESP] GameSettingData.EnableShowPlayerOutline=%p",
             m_mth.enableOutlineMth ? m_mth.enableOutlineMth->methodPointer : nullptr);

        // Store all MatchGame outline functions — called from game-thread hooks
        if (m_mth.showPlayerOutline && m_mth.showPlayerOutline->methodPointer)
            s_match_show_outline_fn = m_mth.showPlayerOutline->methodPointer;
        if (m_mth.tryInitOutlineRes && m_mth.tryInitOutlineRes->methodPointer)
            s_match_try_init_fn = m_mth.tryInitOutlineRes->methodPointer;
        if (m_mth.resIdGetInstance && m_mth.resIdGetInstance->methodPointer)
            s_match_get_inst_fn = m_mth.resIdGetInstance->methodPointer;
        // ShowTeamOutline — also activate for full visibility
        MethodInfo *showTeamMth = Il2CppApi::getMethod(matchGameCls, "ShowTeamOutline", -1);
        if (showTeamMth && showTeamMth->methodPointer)
            s_match_show_team_outline_fn = showTeamMth->methodPointer;
        LOGI("[ESP] MatchGame fns: GetMatch=%p TryInit=%p ShowPlayer=%p ShowTeam=%p",
             s_match_get_inst_fn, s_match_try_init_fn,
             s_match_show_outline_fn, s_match_show_team_outline_fn);
    }

    // GameSettingData singleton gate — resolve get_Instance + EnableShow* + EnableTeam*
    {
        Il2CppClass *gsCls2 = Il2CppApi::getClass(img, "COW", "GameSettingData");
        if (gsCls2) {
            MethodInfo *enMth = Il2CppApi::getMethod(gsCls2, "EnableShowPlayerOutline", -1);
            if (enMth && enMth->methodPointer)
                s_gs_enable_outline_fn = enMth->methodPointer;
            m_mth.gsGetInstance    = Il2CppApi::getMethod(gsCls2, "get_Instance",            0);
            m_mth.gsEnablePlayerOL = enMth;
            m_mth.gsEnableTeamOL   = Il2CppApi::getMethod(gsCls2, "EnableShowTeamOutline",   1);
            if (m_mth.gsGetInstance && m_mth.gsGetInstance->methodPointer)
                s_gs_get_instance_fn = m_mth.gsGetInstance->methodPointer;
            if (m_mth.gsEnableTeamOL && m_mth.gsEnableTeamOL->methodPointer)
                s_gs_enable_team_fn = m_mth.gsEnableTeamOL->methodPointer;
            LOGI("[ESP] GSD: EnablePlayer=%p get_Instance=%p EnableTeam=%p",
                 s_gs_enable_outline_fn, s_gs_get_instance_fn, s_gs_enable_team_fn);
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

// Aimbot / headshot flags
static bool  s_auto_headshot = false;
static bool  s_silent_aim    = false;
static bool  s_full_aimbot   = false;
static bool  s_anti_aim      = false;

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
static void *s_orig_visible          = nullptr;
static void *s_orig_hud_show         = nullptr;
static bool  s_esp_hud               = false;
static void *s_orig_set_outline_vis  = nullptr;
static void *s_orig_init_outline     = nullptr;
static void *s_orig_ammo      = nullptr;
static void *s_orig_reload    = nullptr;
static void *s_orig_wallhit   = nullptr;
static void *s_orig_knockdown = nullptr;
static void *s_orig_collider  = nullptr;
static void *s_orig_setpos    = nullptr;  // Transform.set_position
static void *s_orig_getpos    = nullptr;  // Transform.get_position
static void *s_orig_gettrans  = nullptr;  // Component.get_transform
static void *s_orig_update    = nullptr;  // Player.Update (teleport tick)
// Headshot / aimbot orig pointers
static void *s_orig_attackable_ctr      = nullptr;  // Player.GetAttackableCenterWS
static void *s_orig_get_head_bone       = nullptr;  // Player.get_HeadBoneTransform
static void *s_orig_get_head_collider   = nullptr;  // Player.get_HeadCollider() — real physics hitbox
static void *s_orig_get_head_tf         = nullptr;  // Player.GetHeadTF() — alternative head transform
static void *s_orig_collider_get_bounds = nullptr;  // Collider.get_bounds() → Bounds{center,extents}
static void *s_orig_set_aim_rot         = nullptr;  // Player.SetAimRotation
static void *s_orig_update_aiming       = nullptr;  // Player.UpdateAiming
static void *s_orig_update_aiming_ads   = nullptr;  // Player.ODKFDOFOHLN (ADS/scope)
static void *s_orig_has_heuristic       = nullptr;  // Player.HasHeuristicTarget
static void *s_orig_get_heuristic       = nullptr;  // Player.GetHeuristicTarget
static void *s_orig_check_dmg_hithead   = nullptr;  // Player.CheckDamageHitHead
static void *s_orig_no_headshot_state   = nullptr;  // Player.IsInNoHeadShotState
static void *s_orig_take_damage_4       = nullptr;  // Player.TakeDamage(4) — enemy client-side prediction
// InitOutline hooked target address — calling this address goes through our hook
static void *s_initoutline_hooked_addr  = nullptr;
// ResourceIDDef — cached for in-game lazy init (singleton not available at lobby time)
static void        *s_res_id_get_inst      = nullptr;  // ResourceIDDef.GetInstance()
static void        *s_res_id_try_init      = nullptr;  // ResourceIDDef.TryInitPlayerOutlineRes()
static void        *s_res_id_show          = nullptr;  // ResourceIDDef.ShowPlayerOutline(bool)
static void        *s_res_id_only_headshot = nullptr;  // ResourceIDDef.set_OnlyHeadshot(bool)
static Il2CppClass *s_res_id_cls           = nullptr;  // ResourceIDDef class (for field scan)
static void        *s_res_id_inst          = nullptr;  // cached singleton instance (set after lazy-init)
// Flag: ShowPlayerOutline(true) was successfully called this match session.
// Reset on applyESP(false) so next enable tries again.
static bool         s_matchgame_outline_done = false;

// GameSettingData game-thread call state + enemy tracking
static bool   s_gs_outline_done     = false;
static void  *s_local_player        = nullptr;
static void  *s_enemy_list[32]      = {};
static int    s_enemy_count         = 0;

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

// ESP: IsVisible gate — always true (culling bypass)
static uint8_t hook_is_visible(void *self, void *method) {
    if (s_esp) return 1;
    using Fn = uint8_t (*)(void *, void *);
    return reinterpret_cast<Fn>(s_orig_visible)(self, method);
}

// ESP: HUD SetVisible(bool) — force true so enemy plates always render
// ARM64: x0=this, w1=visible(bool), x2=MethodInfo*
static void hook_hud_set_visible(void *self, uint8_t visible, void *method) {
    uint8_t forced = s_esp_hud ? 1 : visible;
    LOGI("[ESP-DIAG] HUD SetVisible: hud=%p orig=%d forced=%d", self, (int)visible, (int)forced);
    using Fn = void (*)(void *, uint8_t, void *);
    reinterpret_cast<Fn>(s_orig_hud_show)(self, forced, method);
}

// ESP: SetOutlineVisible — binary-verified: pc=2 (uint8 visible, int mode).
// game_val=16 is the native through-wall state (used for teammates). Force 16 on enemies too.
static void hook_set_outline_vis(void *self, uint8_t visible, int mode, void *method) {
    // 16 = through-wall outline (confirmed from logcat: game uses 16 for team outlines).
    // Force 16 when game tries to hide (0) or uses a weaker value (<16).
    uint8_t forced = (s_esp && visible < 16) ? 16 : visible;
    LOGI("[ESP-DBG] SetOutlineVisible: self=%p game_val=%d mode=%d forced=%d esp=%d", self, (int)visible, mode, (int)forced, (int)s_esp);
    using Fn = void (*)(void *, uint8_t, int, void *);
    reinterpret_cast<Fn>(s_orig_set_outline_vis)(self, forced, mode, method);
}

// ESP: InitOutline() — binary-verified: pc=1 (one explicit param before MethodInfo*).
// Inject SetOutlineVisible(self, 1, 0) right after each player's outline init.
static void hook_init_outline(void *self, void *param0, void *method) {
    LOGI("[ESP-DBG] InitOutline fired: self=%p param0=%p esp=%d outline_fn=%p", self, param0, (int)s_esp, s_orig_set_outline_vis);
    using Fn = void (*)(void *, void *, void *);
    reinterpret_cast<Fn>(s_orig_init_outline)(self, param0, method);
    LOGI("[ESP-DBG] InitOutline orig done — now calling SetOutlineVisible(16,0+1)");
    if (s_esp && s_orig_set_outline_vis) {
        using ShowFn = void (*)(void *, uint8_t, int, void *);
        reinterpret_cast<ShowFn>(s_orig_set_outline_vis)(self, 16, 0, nullptr);  // enemy mode
        reinterpret_cast<ShowFn>(s_orig_set_outline_vis)(self, 16, 1, nullptr);  // team mode
        LOGI("[ESP-DBG] SetOutlineVisible(16,0+1) injected for self=%p", self);
    } else {
        LOGI("[ESP-DBG] InitOutline: skipped inject (esp=%d fn=%p)", (int)s_esp, s_orig_set_outline_vis);
    }
}

// InfiniteAmmo: get_IsAmmoFree (bool) → 1 = ammo is free/unlimited
static uint8_t hook_get_ammo(void *self, void *method) {
    if (s_inf_ammo) return 1;
    using Fn = uint8_t (*)(void *, void *);
    return reinterpret_cast<Fn>(s_orig_ammo)(self, method);
}

// NoReload: IsNeedReload / NeedReload → false
static uint8_t hook_is_reload(void *self, void *method) {
    if (s_no_reload) return 0;
    using Fn = uint8_t (*)(void *, void *);
    return reinterpret_cast<Fn>(s_orig_reload)(self, method);
}

// WallShoot: CanFire → 1 (always allowed to fire, bypasses wall/obstacle check)
static uint8_t hook_wall_hit(void *self, void *method) {
    if (s_wall_shoot) return 1;
    using Fn = uint8_t (*)(void *, void *);
    return reinterpret_cast<Fn>(s_orig_wallhit)(self, method);
}

// AutoRevive: get_IsPendingRevive → always true so game triggers revive logic immediately
static uint8_t hook_is_knockdown(void *self, void *method) {
    if (s_auto_revive) return 1;
    using Fn = uint8_t (*)(void *, void *);
    return reinterpret_cast<Fn>(s_orig_knockdown)(self, method);
}

// NoClip: OnControllerColliderHit → no-op so physics obstacles are ignored
static void hook_collider_hit(void *self, void *hit, void *method) {
    if (s_noclip) return;
    using Fn = void (*)(void *, void *, void *);
    reinterpret_cast<Fn>(s_orig_collider)(self, hit, method);
}

// Global tick for ESP outline — increments once per ANY player Update call.
// All players share this counter on the Unity main thread so thread_local is wrong.
static uint32_t s_global_outline_tick = 0;

static void hook_player_update(void *self, void *method) {
    // ── ESP proactive outline ─────────────────────────────────────────────────
    // thread_local was wrong: all Unity Update() callbacks run on the same main
    // thread, so thread_local is SHARED across all players. With 4 players only
    // the one that hits tick=60 ever gets SetOutlineVisible — others are skipped.
    // Fix: global counter mod small number → fires for EVERY player frequently.
    // Pass nullptr for MethodInfo* — method here is Player.Update's MethodInfo,
    // which is wrong for SetOutlineVisible. nullptr is safe; game ignores it.
    if (s_esp) {
        ++s_global_outline_tick;
        uint32_t slot = ((uintptr_t)self >> 12) & 0x1F;
        if ((s_global_outline_tick % 30) == (slot % 30)) {
            // value=16 is the through-wall outline state (confirmed from game's own team calls)
            if (s_orig_set_outline_vis) {
                using ShowFn = void (*)(void *, uint8_t, int, void *);
                reinterpret_cast<ShowFn>(s_orig_set_outline_vis)(self, 16, 0, nullptr);  // enemy
                reinterpret_cast<ShowFn>(s_orig_set_outline_vis)(self, 16, 1, nullptr);  // team
            }
            // SetRenderQ(5000) renders enemy above walls (Overlay queue)
            if (s_orig_set_render_q) {
                using SetRQFn = void (*)(void *, int, void *);
                reinterpret_cast<SetRQFn>(s_orig_set_render_q)(self, 5000, nullptr);
            }
            static uint32_t s_sov_fire_cnt = 0;
            if ((++s_sov_fire_cnt) <= 10)
                LOGI("[ESP-DBG] proactive SOV(16,0+1)+RQ(5000) fire#%u self=%p slot=%u tick=%u",
                    s_sov_fire_cnt, self, slot, s_global_outline_tick);
        }
    }
    // ── Player classification + GameSettingData permission gate ──────────────
    if (s_is_local_player_fn) {
        using IsLocalFn = uint8_t (*)(void *, void *);
        uint8_t isLocal = reinterpret_cast<IsLocalFn>(s_is_local_player_fn)(self, nullptr);
        if (isLocal) {
            s_local_player = self;
            // Call GameSettingData.EnableShowPlayerOutline/Team once per session from game thread
            if (s_esp && !s_gs_outline_done && s_gs_get_instance_fn && s_gs_enable_outline_fn) {
                using GetInstFn = void *(*)(void *);
                void *gsd = reinterpret_cast<GetInstFn>(s_gs_get_instance_fn)(nullptr);
                if (gsd) {
                    using EnableFn = void (*)(void *, uint8_t, void *);
                    reinterpret_cast<EnableFn>(s_gs_enable_outline_fn)(gsd, 1, nullptr);
                    if (s_gs_enable_team_fn)
                        reinterpret_cast<EnableFn>(s_gs_enable_team_fn)(gsd, 1, nullptr);
                    s_gs_outline_done = true;
                    LOGI("[ESP] GSD.EnableShowPlayerOutline(true) called gsd=%p", gsd);
                }
            }
        } else {
            // Track enemy instances for aimbot targeting
            bool found = false;
            for (int i = 0; i < s_enemy_count; ++i)
                if (s_enemy_list[i] == self) { found = true; break; }
            if (!found && s_enemy_count < 32)
                s_enemy_list[s_enemy_count++] = self;
        }
    }
    // ── Teleport tick ────────────────────────────────────────────────────────
    if (s_orig_gettrans && s_orig_setpos && s_orig_getpos) {
        using GetTransFn = void *(*)(void *, void *);
        void *tr = reinterpret_cast<GetTransFn>(s_orig_gettrans)(self, nullptr);
        if (tr) {
            if (!s_tp_has_save) {
                using GetPosFn = Vec3 (*)(void *, void *);
                s_tp_saved   = reinterpret_cast<GetPosFn>(s_orig_getpos)(tr, nullptr);
                s_tp_has_save = true;
                LOGI("TeleportSave: pos=(%.2f,%.2f,%.2f)",
                     s_tp_saved.x, s_tp_saved.y, s_tp_saved.z);
            }
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

// ── Headshot / Aimbot hooks ────────────────────────────────────────────────────

// CheckDamageHitHead — client-side gate that decides if a hit registers as headshot.
// Force-return true when any headshot feature is active so every bullet counts.
// Signature: bool CheckDamageHitHead(DamageInfo* info) — we pass through `info` unchanged.
static uint8_t hook_check_dmg_hithead(void *self, void *info, void *method) {
    LOGI("[HS-CRASH] hook_check_dmg_hithead ENTERED: self=%p info=%p method=%p hs=%d sa=%d fa=%d",
         self, info, method, (int)s_auto_headshot, (int)s_silent_aim, (int)s_full_aimbot);
    if (s_auto_headshot || s_silent_aim || s_full_aimbot) {
        return 1;
    }
    LOGI("[HS-CRASH] CheckDamageHitHead: calling original trampoline=%p", s_orig_check_dmg_hithead);
    using Fn = uint8_t (*)(void *, void *, void *);
    uint8_t r = reinterpret_cast<Fn>(s_orig_check_dmg_hithead)(self, info, method);
    LOGI("[HS-CRASH] CheckDamageHitHead: orig returned %d", (int)r);
    return r;
}

// IsInNoHeadShotState — returns true when player is in a state where headshots are blocked
// (e.g. special armor, skill effects). Force-return false so the block is bypassed.
static uint8_t hook_no_headshot_state(void *self, void *method) {
    if (s_auto_headshot || s_silent_aim || s_full_aimbot) {
        LOGI("[HS-DBG] IsInNoHeadShotState: self=%p FORCED=0 (bypassed)", self);
        return 0;
    }
    using Fn = uint8_t (*)(void *, void *);
    return reinterpret_cast<Fn>(s_orig_no_headshot_state)(self, method);
}

// GetAttackableCenterWS — redirect aim center to head bone when auto-hs / silent-aim / aimbot on
// Returns Vec3 by value (ARM64 HFA convention: s0/s1/s2)
static Vec3 hook_get_attackable_center(void *self, void *method) {
    // Lazy-init MatchGame singleton for ESP outline.
    // MatchGame.GetMatch() is the static accessor (confirmed via global-metadata.dat).
    // Fires when enemy is visible to aim system — guaranteed in-match with enemies nearby.
    // MatchGame lazy-init intentionally removed from hook context (crash in IL2CPP hook thread).
    // MatchGame.ShowPlayerOutline is called once in applyESP() from safe main-thread context.

    // ESP: set enemy render queue to Transparent layer (renders above walls).
    // Per-enemy InitOutline + SetOutlineVisible(1) is injected every ~90 calls via the
    // hooked InitOutline address — this goes through hook_init_outline which runs
    // original + SetOutlineVisible(1), covering enemies present before ESP was toggled.
    // ESP: set render queue above Overlay (5000) so enemy renders through walls.
    // Only SetRenderQ here — InitOutline fires naturally from game; MatchGame calls
    // were crashing because both called with nullptr MethodInfo* on first enemy tick.
    if (s_esp && s_orig_set_render_q) {
        static uint32_t s_rq_cnt = 0;
        bool rq_log = ((++s_rq_cnt) % 120) == 1;
        if (rq_log) LOGI("[ESP-DBG] SetRenderQ(5000) call#%u self=%p fn=%p", s_rq_cnt, self, s_orig_set_render_q);
        using SetRQFn = void (*)(void *, int, void *);
        reinterpret_cast<SetRQFn>(s_orig_set_render_q)(self, 5000, nullptr);
        if (rq_log) LOGI("[ESP-DBG] SetRenderQ returned OK call#%u", s_rq_cnt);
    }
    if (s_auto_headshot || s_silent_aim || s_full_aimbot) {
        static uint32_t s_aim_cnt = 0;
        ++s_aim_cnt;
        // Log every call for first 20, then every 60 — catches crashes on first execution
        bool do_log = (s_aim_cnt <= 20) || ((s_aim_cnt % 60) == 1);

        if (do_log) LOGI("[HS-CRASH] aim#%u ENTER self=%p headtf_fn=%p bone_fn=%p getpos_fn=%p",
            s_aim_cnt, self, s_orig_get_head_tf, s_orig_get_head_bone, s_orig_getpos);

        // Priority 1 (Collider.get_bounds) REMOVED — Collider.bounds queries PhysX
        // which is NOT thread-safe from a hook thread → guaranteed crash.
        // Priority 2: GetHeadTF (alternate head transform)
        if (s_orig_get_head_tf && s_orig_getpos) {
            if (do_log) LOGI("[HS-CRASH] aim#%u calling GetHeadTF fn=%p self=%p", s_aim_cnt, s_orig_get_head_tf, self);
            using GetTFFn = void *(*)(void *, void *);
            void *headTF = reinterpret_cast<GetTFFn>(s_orig_get_head_tf)(self, nullptr);
            if (do_log) LOGI("[HS-CRASH] aim#%u GetHeadTF returned tf=%p", s_aim_cnt, headTF);
            if (headTF) {
                if (do_log) LOGI("[HS-CRASH] aim#%u calling getpos on headTF fn=%p tf=%p", s_aim_cnt, s_orig_getpos, headTF);
                using GetPosFn = Vec3 (*)(void *, void *);
                Vec3 tp = reinterpret_cast<GetPosFn>(s_orig_getpos)(headTF, nullptr);
                if (do_log) LOGI("[HS-CRASH] aim#%u GetHeadTF.pos=(%.3f,%.3f,%.3f)", s_aim_cnt, tp.x, tp.y, tp.z);
                if (tp.x != 0.0f || tp.y != 0.0f || tp.z != 0.0f) {
                    return tp;  // GetHeadTF is already at head center — no offset needed
                }
            }
            if (do_log) LOGI("[HS-CRASH] aim#%u P2 GetHeadTF=null/zero — falling back", s_aim_cnt);
        } else {
            if (do_log) LOGI("[HS-CRASH] aim#%u P2 SKIP: tf_fn=%p getpos_fn=%p", s_aim_cnt, s_orig_get_head_tf, s_orig_getpos);
        }

        // Priority 3: head bone with -0.15m offset
        if (s_orig_get_head_bone && s_orig_getpos) {
            if (do_log) LOGI("[HS-CRASH] aim#%u calling get_HeadBoneTransform fn=%p self=%p", s_aim_cnt, s_orig_get_head_bone, self);
            using GetBoneFn = void *(*)(void *, void *);
            void *headT = reinterpret_cast<GetBoneFn>(s_orig_get_head_bone)(self, nullptr);
            if (do_log) LOGI("[HS-CRASH] aim#%u get_HeadBoneTransform returned bone=%p", s_aim_cnt, headT);
            if (headT) {
                if (do_log) LOGI("[HS-CRASH] aim#%u calling getpos on bone fn=%p bone=%p", s_aim_cnt, s_orig_getpos, headT);
                using GetPosFn = Vec3 (*)(void *, void *);
                Vec3 hp = reinterpret_cast<GetPosFn>(s_orig_getpos)(headT, nullptr);
                if (do_log) LOGI("[HS-CRASH] aim#%u bone.pos=(%.3f,%.3f,%.3f)", s_aim_cnt, hp.x, hp.y, hp.z);
                if (hp.x != 0.0f || hp.y != 0.0f || hp.z != 0.0f) {
                    return hp;  // head bone position, no offset
                }
            }
        } else {
            if (do_log) LOGI("[HS-CRASH] aim#%u P3 SKIP: bone_fn=%p getpos_fn=%p", s_aim_cnt, s_orig_get_head_bone, s_orig_getpos);
        }

        // Priority LAST: all specialized head methods failed/null — shift original center up ~0.55m
        // This works unconditionally since s_orig_attackable_ctr trampoline is always valid when we get here.
        {
            using Fn = Vec3 (*)(void *, void *);
            Vec3 orig = reinterpret_cast<Fn>(s_orig_attackable_ctr)(self, method);
            orig.y += 0.55f;
            if (do_log) LOGI("[HS-CRASH] aim#%u YSHIFT fallback orig+0.55=(%.3f,%.3f,%.3f)", s_aim_cnt, orig.x, orig.y, orig.z);
            return orig;
        }
    }
    using Fn = Vec3 (*)(void *, void *);
    return reinterpret_cast<Fn>(s_orig_attackable_ctr)(self, method);
}

// ── Aimbot core — shared by UpdateAiming and ODKFDOFOHLN (ADS) hooks ─────────
// Prefers GetHeadTF (stable transform, no animation jitter) over bone for fast-
// moving targets; falls back to bone if GetHeadTF returns null/zero.
static inline void run_aimbot_core(void *self) {
    if (!s_full_aimbot && !s_auto_headshot) return;
    // Require local player to be known; bail for any non-local instance
    if (!s_local_player || self != s_local_player) return;
    if (!s_orig_getpos || !s_orig_gettrans) return;

    using GetTransFn = void *(*)(void *, void *);
    void *myT = reinterpret_cast<GetTransFn>(s_orig_gettrans)(self, nullptr);
    if (!myT) return;
    using GetPosFn = Vec3 (*)(void *, void *);
    Vec3 myPos = reinterpret_cast<GetPosFn>(s_orig_getpos)(myT, nullptr);

    void *bestEnemy = nullptr;
    Vec3  bestHead  = {};
    float bestDist2 = 1e20f;

    // Step 1: HeuristicTarget (aim-assist active path)
    if (s_orig_has_heuristic && s_orig_get_heuristic) {
        using HasFn = uint8_t (*)(void *, void *);
        if (reinterpret_cast<HasFn>(s_orig_has_heuristic)(self, nullptr)) {
            using GetFn = void *(*)(void *, void *);
            void *he = reinterpret_cast<GetFn>(s_orig_get_heuristic)(self, nullptr);
            if (he) bestEnemy = he;
        }
    }

    // Step 2: enemy list scan — covers stationary enemies + fast movers
    // GetHeadTF is a stable non-animated transform (no jitter on fast movement);
    // bone is a fallback when GetHeadTF is unavailable or returns zero.
    if (!bestEnemy && (s_orig_get_head_tf || s_orig_get_head_bone)) {
        for (int i = 0; i < s_enemy_count; ++i) {
            void *ep = s_enemy_list[i];
            if (!ep || ep == self) continue;
            void *hT = nullptr;
            if (s_orig_get_head_tf) {
                using GetTFFn = void *(*)(void *, void *);
                hT = reinterpret_cast<GetTFFn>(s_orig_get_head_tf)(ep, nullptr);
            }
            if (!hT && s_orig_get_head_bone) {
                using GetBoneFn = void *(*)(void *, void *);
                hT = reinterpret_cast<GetBoneFn>(s_orig_get_head_bone)(ep, nullptr);
            }
            if (!hT) continue;
            Vec3 hPos = reinterpret_cast<GetPosFn>(s_orig_getpos)(hT, nullptr);
            if (hPos.x == 0.f && hPos.y == 0.f && hPos.z == 0.f) continue;
            float dx2 = hPos.x - myPos.x, dy2 = hPos.y - myPos.y, dz2 = hPos.z - myPos.z;
            float d2  = dx2*dx2 + dy2*dy2 + dz2*dz2;
            if (d2 < bestDist2) { bestDist2 = d2; bestEnemy = ep; bestHead = hPos; }
        }
    }
    if (!bestEnemy) return;

    // Resolve head position for HeuristicTarget path (prefer stable GetHeadTF)
    if (bestDist2 >= 1e20f) {
        void *hT = nullptr;
        if (s_orig_get_head_tf) {
            using GetTFFn = void *(*)(void *, void *);
            hT = reinterpret_cast<GetTFFn>(s_orig_get_head_tf)(bestEnemy, nullptr);
        }
        if (!hT && s_orig_get_head_bone) {
            using GetBoneFn = void *(*)(void *, void *);
            hT = reinterpret_cast<GetBoneFn>(s_orig_get_head_bone)(bestEnemy, nullptr);
        }
        if (!hT) return;
        bestHead = reinterpret_cast<GetPosFn>(s_orig_getpos)(hT, nullptr);
    }

    float dx    = bestHead.x - myPos.x;
    float dy    = bestHead.y - myPos.y;
    float dz    = bestHead.z - myPos.z;
    float horiz = sqrtf(dx*dx + dz*dz);
    // Free Fire uses -Z as player forward direction
    float yaw   =  atan2f(dx, -dz) * (180.0f / 3.14159265f);
    float pitch = -atan2f(dy, horiz) * (180.0f / 3.14159265f);

    if (!s_orig_set_aim_rot) return;
    Vec3 aimRot = {pitch, yaw, 0.0f};
    using SetAimFn = void (*)(void *, Vec3, void *);
    reinterpret_cast<SetAimFn>(s_orig_set_aim_rot)(self, aimRot, nullptr);
}

// UpdateAiming — per-frame full aimbot entry point (hip-fire / normal mode)
static void hook_update_aiming(void *self, void *method) {
    if (s_orig_update_aiming) {
        using Fn = void (*)(void *, void *);
        reinterpret_cast<Fn>(s_orig_update_aiming)(self, method);
    }
    run_aimbot_core(self);
}

// ODKFDOFOHLN — ADS/scope aim update entry point (fired when player is scoped)
static void hook_update_aiming_ads(void *self, void *method) {
    if (s_orig_update_aiming_ads) {
        using Fn = void (*)(void *, void *);
        reinterpret_cast<Fn>(s_orig_update_aiming_ads)(self, method);
    }
    run_aimbot_core(self);
}

// ── Shared helper: install / remove GetAttackableCenterWS hook ────────────────
static void installAimCenterHook(MethodInfo *mth) {
    if (!mth || !mth->methodPointer || s_orig_attackable_ctr) return;
    HookEngine::get().hookAddr(mth->methodPointer,
        reinterpret_cast<void *>(hook_get_attackable_center),
        &s_orig_attackable_ctr, "AimCenter");
    LOGI("[AIM] GetAttackableCenterWS hooked: trampoline=%p", s_orig_attackable_ctr);
}
static void removeAimCenterHook(MethodInfo *mth) {
    if (!mth || !mth->methodPointer || !s_orig_attackable_ctr) return;
    if (s_auto_headshot || s_silent_aim || s_full_aimbot || s_esp) return; // another feature still needs it
    HookEngine::get().unhook(mth->methodPointer);
    s_orig_attackable_ctr = nullptr;
    LOGI("[AIM] GetAttackableCenterWS unhooked");
}

void FeatureEngine::applyAimAssist(bool enable) {
    // Legacy pass-through — now replaced by applyAutoHeadshot / applySilentAim / applyFullAimbot.
    // Keep a minimal hook so ZX_AIM_ENABLE still does something: treat as full aimbot toggle.
    applyFullAimbot(enable);
}

void FeatureEngine::applyAutoHeadshot(bool enable) {
    s_auto_headshot = enable;

    // Store head-bone / collider / getpos / gettrans pointers on first enable
    if (enable) {
        if (!s_orig_get_head_bone && m_mth.getHeadBoneTransform)
            s_orig_get_head_bone = m_mth.getHeadBoneTransform->methodPointer;
        // Binary-verified: get_HeadCollider = real physics hitbox — use as primary aim point
        if (!s_orig_get_head_collider && m_mth.getHeadCollider)
            s_orig_get_head_collider = m_mth.getHeadCollider->methodPointer;
        if (!s_orig_get_head_tf && m_mth.getHeadTF)
            s_orig_get_head_tf = m_mth.getHeadTF->methodPointer;
        if (!s_orig_collider_get_bounds && m_mth.colliderGetBounds)
            s_orig_collider_get_bounds = m_mth.colliderGetBounds->methodPointer;
        if (!s_orig_getpos && m_mth.getPosition)
            s_orig_getpos = m_mth.getPosition->methodPointer;
        if (!s_orig_gettrans && m_mth.getTransform)
            s_orig_gettrans = m_mth.getTransform->methodPointer;
        // Cache set_OnlyHeadshot fn pointer for lazy-init path inside the hook
        if (!s_res_id_only_headshot && m_mth.setOnlyHeadshot)
            s_res_id_only_headshot = m_mth.setOnlyHeadshot->methodPointer;
        // Also populate class/getter for singleton resolution if not yet populated by ESP
        if (!s_res_id_cls)       s_res_id_cls       = m_cls.ResIdDef;
        if (!s_res_id_get_inst && m_mth.resIdGetInstance)
            s_res_id_get_inst = m_mth.resIdGetInstance->methodPointer;
        // SetAimRotation + IsLocalPlayer needed for run_aimbot_core (force-aim path)
        if (!s_orig_set_aim_rot && m_mth.setAimRotation)
            s_orig_set_aim_rot = m_mth.setAimRotation->methodPointer;
        if (!s_is_local_player_fn && m_mth.isLocalPlayer)
            s_is_local_player_fn = m_mth.isLocalPlayer->methodPointer;
    }

    // UpdateAiming hook — forces physical aim toward enemy head (hip-fire + ADS)
    // Without this, AutoHeadshot only redirects aim-assist and can't force aim on body shots.
    if (m_mth.updateAiming && m_mth.updateAiming->methodPointer) {
        if (enable && !s_orig_update_aiming) {
            HookEngine::get().hookAddr(m_mth.updateAiming->methodPointer,
                reinterpret_cast<void *>(hook_update_aiming), &s_orig_update_aiming, "AutoHSAim");
            LOGI("[AIM] AutoHeadshot UpdateAiming hooked: trampoline=%p", s_orig_update_aiming);
        } else if (!enable && !s_full_aimbot && s_orig_update_aiming) {
            HookEngine::get().unhook(m_mth.updateAiming->methodPointer);
            s_orig_update_aiming = nullptr;
        }
    }
    if (m_mth.updateAimingADS && m_mth.updateAimingADS->methodPointer) {
        if (enable && !s_orig_update_aiming_ads) {
            HookEngine::get().hookAddr(m_mth.updateAimingADS->methodPointer,
                reinterpret_cast<void *>(hook_update_aiming_ads), &s_orig_update_aiming_ads, "AutoHSADS");
            LOGI("[AIM] AutoHeadshot ODKFDOFOHLN hooked: trampoline=%p", s_orig_update_aiming_ads);
        } else if (!enable && !s_full_aimbot && s_orig_update_aiming_ads) {
            HookEngine::get().unhook(m_mth.updateAimingADS->methodPointer);
            s_orig_update_aiming_ads = nullptr;
        }
    }

    // Hook GetAttackableCenterWS → head position
    LOGI("[HS-CRASH] about to %s AimCenterHook calcAimTarget=%p ptr=%p",
        enable ? "install" : "remove",
        m_mth.calcAimTarget,
        m_mth.calcAimTarget ? m_mth.calcAimTarget->methodPointer : nullptr);
    if (enable) installAimCenterHook(m_mth.calcAimTarget);
    else        removeAimCenterHook(m_mth.calcAimTarget);
    LOGI("[HS-CRASH] AimCenterHook %s done trampoline=%p", enable ? "install" : "remove", s_orig_attackable_ctr);

    // If the singleton is already live (e.g. toggled mid-match), call immediately.
    // Otherwise hook_get_attackable_center will call it lazily on next enemy tick.
    if (m_mth.setOnlyHeadshot && m_mth.setOnlyHeadshot->methodPointer) {
        void *inst = s_res_id_inst;
        if (!inst && m_mth.resIdGetInstance && m_mth.resIdGetInstance->methodPointer) {
            using GetInstFn = void *(*)(void *);
            inst = reinterpret_cast<GetInstFn>(m_mth.resIdGetInstance->methodPointer)(nullptr);
        }
        if (inst) {
            using SetFn = void (*)(void *, uint8_t, void *);
            reinterpret_cast<SetFn>(m_mth.setOnlyHeadshot->methodPointer)(inst, enable ? 1 : 0, nullptr);
            LOGI("[AIM] set_OnlyHeadshot(%d) on ResIDDef inst=%p (immediate)", (int)enable, inst);
        } else {
            if (enable) LOGI("[AIM] set_OnlyHeadshot deferred — ResIDDef not yet live (lobby)");
            else        LOGI("[AIM] set_OnlyHeadshot(0) skipped — no inst (feature was never active in-match)");
        }
    }
    // CheckDamageHitHead / IsInNoHeadShotState — direct damage-gate hooks
    if (m_mth.checkDamageHitHead && m_mth.checkDamageHitHead->methodPointer) {
        if (enable && !s_orig_check_dmg_hithead) {
            LOGI("[HS-CRASH] BEFORE hookAddr CheckDamageHitHead ptr=%p hook_fn=%p",
                m_mth.checkDamageHitHead->methodPointer,
                reinterpret_cast<void *>(hook_check_dmg_hithead));
            HookEngine::get().hookAddr(m_mth.checkDamageHitHead->methodPointer,
                reinterpret_cast<void *>(hook_check_dmg_hithead), &s_orig_check_dmg_hithead, "CheckDamageHitHead");
            LOGI("[HS-CRASH] AFTER hookAddr CheckDamageHitHead trampoline=%p", s_orig_check_dmg_hithead);
        } else if (!enable && !s_silent_aim && !s_full_aimbot && s_orig_check_dmg_hithead) {
            HookEngine::get().unhook(m_mth.checkDamageHitHead->methodPointer);
            s_orig_check_dmg_hithead = nullptr;
        }
    } else { LOGE("[HS-CRASH] CheckDamageHitHead mth=%p ptr=%s — fallback to aim-center only",
        m_mth.checkDamageHitHead,
        m_mth.checkDamageHitHead ? "NULL_method_ptr" : "NULL_mth"); }

    LOGI("AutoHeadshot: %s  center_hook=%p bone=%p collider=%p headTF=%p hithead=%p",
         enable ? "ON" : "OFF", s_orig_attackable_ctr, s_orig_get_head_bone,
         s_orig_get_head_collider, s_orig_get_head_tf, s_orig_check_dmg_hithead);
}

void FeatureEngine::applySilentAim(bool enable) {
    s_silent_aim = enable;

    if (enable) {
        if (!s_orig_get_head_bone && m_mth.getHeadBoneTransform)
            s_orig_get_head_bone = m_mth.getHeadBoneTransform->methodPointer;
        if (!s_orig_get_head_collider && m_mth.getHeadCollider)
            s_orig_get_head_collider = m_mth.getHeadCollider->methodPointer;
        if (!s_orig_get_head_tf && m_mth.getHeadTF)
            s_orig_get_head_tf = m_mth.getHeadTF->methodPointer;
        if (!s_orig_collider_get_bounds && m_mth.colliderGetBounds)
            s_orig_collider_get_bounds = m_mth.colliderGetBounds->methodPointer;
        if (!s_orig_getpos && m_mth.getPosition)
            s_orig_getpos = m_mth.getPosition->methodPointer;
        if (!s_orig_gettrans && m_mth.getTransform)
            s_orig_gettrans = m_mth.getTransform->methodPointer;
        if (!s_res_id_only_headshot && m_mth.setOnlyHeadshot)
            s_res_id_only_headshot = m_mth.setOnlyHeadshot->methodPointer;
        if (!s_res_id_cls)      s_res_id_cls      = m_cls.ResIdDef;
        if (!s_res_id_get_inst && m_mth.resIdGetInstance)
            s_res_id_get_inst = m_mth.resIdGetInstance->methodPointer;
        // Share the damage-gate hooks with AutoHeadshot
        if (m_mth.checkDamageHitHead && m_mth.checkDamageHitHead->methodPointer
                && !s_orig_check_dmg_hithead) {
            LOGI("[HS-CRASH] BEFORE hookAddr CheckDamageHitHead (SilentAim) ptr=%p",
                m_mth.checkDamageHitHead->methodPointer);
            HookEngine::get().hookAddr(m_mth.checkDamageHitHead->methodPointer,
                reinterpret_cast<void *>(hook_check_dmg_hithead), &s_orig_check_dmg_hithead, "CheckDamageHitHead");
            LOGI("[HS-CRASH] AFTER hookAddr CheckDamageHitHead (SilentAim) trampoline=%p", s_orig_check_dmg_hithead);
        }
    } else {
        if (!s_auto_headshot && !s_full_aimbot) {
            if (s_orig_check_dmg_hithead && m_mth.checkDamageHitHead) {
                HookEngine::get().unhook(m_mth.checkDamageHitHead->methodPointer);
                s_orig_check_dmg_hithead = nullptr;
            }
        }
    }

    if (enable) installAimCenterHook(m_mth.calcAimTarget);
    else        removeAimCenterHook(m_mth.calcAimTarget);

    LOGI("SilentAim: %s  center_hook=%p hithead=%p", enable ? "ON" : "OFF", s_orig_attackable_ctr, s_orig_check_dmg_hithead);
}

void FeatureEngine::applyFullAimbot(bool enable) {
    s_full_aimbot = enable;

    if (enable) {
        if (!s_orig_get_head_bone && m_mth.getHeadBoneTransform)
            s_orig_get_head_bone = m_mth.getHeadBoneTransform->methodPointer;
        if (!s_orig_get_head_collider && m_mth.getHeadCollider)
            s_orig_get_head_collider = m_mth.getHeadCollider->methodPointer;
        if (!s_orig_get_head_tf && m_mth.getHeadTF)
            s_orig_get_head_tf = m_mth.getHeadTF->methodPointer;
        if (!s_orig_collider_get_bounds && m_mth.colliderGetBounds)
            s_orig_collider_get_bounds = m_mth.colliderGetBounds->methodPointer;
        if (!s_orig_getpos && m_mth.getPosition)
            s_orig_getpos = m_mth.getPosition->methodPointer;
        if (!s_orig_gettrans && m_mth.getTransform)
            s_orig_gettrans = m_mth.getTransform->methodPointer;
        if (!s_orig_set_aim_rot && m_mth.setAimRotation)
            s_orig_set_aim_rot = m_mth.setAimRotation->methodPointer;
        if (!s_orig_has_heuristic && m_mth.hasHeuristicTarget)
            s_orig_has_heuristic = m_mth.hasHeuristicTarget->methodPointer;
        if (!s_orig_get_heuristic && m_mth.getHeuristicTarget)
            s_orig_get_heuristic = m_mth.getHeuristicTarget->methodPointer;
        if (!s_res_id_only_headshot && m_mth.setOnlyHeadshot)
            s_res_id_only_headshot = m_mth.setOnlyHeadshot->methodPointer;
        if (!s_res_id_cls)      s_res_id_cls      = m_cls.ResIdDef;
        if (!s_res_id_get_inst && m_mth.resIdGetInstance)
            s_res_id_get_inst = m_mth.resIdGetInstance->methodPointer;
        if (!s_is_local_player_fn && m_mth.isLocalPlayer)
            s_is_local_player_fn = m_mth.isLocalPlayer->methodPointer;
    }

    if (enable) installAimCenterHook(m_mth.calcAimTarget);
    else        removeAimCenterHook(m_mth.calcAimTarget);

    // Hook UpdateAiming for per-frame aim snap (hip-fire / normal mode)
    if (m_mth.updateAiming && m_mth.updateAiming->methodPointer) {
        if (enable && !s_orig_update_aiming) {
            HookEngine::get().hookAddr(m_mth.updateAiming->methodPointer,
                reinterpret_cast<void *>(hook_update_aiming), &s_orig_update_aiming, "FullAimbot");
            LOGI("[AIM] UpdateAiming hooked: trampoline=%p", s_orig_update_aiming);
        } else if (!enable && s_orig_update_aiming) {
            HookEngine::get().unhook(m_mth.updateAiming->methodPointer);
            s_orig_update_aiming = nullptr;
            s_enemy_count = 0;
            s_local_player = nullptr;
            LOGI("[AIM] UpdateAiming unhooked, enemy list cleared");
        }
    } else {
        LOGE("[AIM] FullAimbot: UpdateAiming ptr null");
    }

    // ODKFDOFOHLN — ADS/scope aim update (same aimbot core, different entry point)
    if (m_mth.updateAimingADS && m_mth.updateAimingADS->methodPointer) {
        if (enable && !s_orig_update_aiming_ads) {
            HookEngine::get().hookAddr(m_mth.updateAimingADS->methodPointer,
                reinterpret_cast<void *>(hook_update_aiming_ads), &s_orig_update_aiming_ads, "AimbotADS");
            LOGI("[AIM] ODKFDOFOHLN hooked: trampoline=%p", s_orig_update_aiming_ads);
        } else if (!enable && s_orig_update_aiming_ads) {
            HookEngine::get().unhook(m_mth.updateAimingADS->methodPointer);
            s_orig_update_aiming_ads = nullptr;
        }
    } else {
        LOGI("[AIM] ODKFDOFOHLN not found — ADS tracking via UpdateAiming only");
    }

    // CheckDamageHitHead — ensures stationary enemy headshots register on full aimbot
    if (m_mth.checkDamageHitHead && m_mth.checkDamageHitHead->methodPointer) {
        if (enable && !s_orig_check_dmg_hithead) {
            HookEngine::get().hookAddr(m_mth.checkDamageHitHead->methodPointer,
                reinterpret_cast<void *>(hook_check_dmg_hithead), &s_orig_check_dmg_hithead, "CheckDamageHitHead");
            LOGI("[AIM] CheckDamageHitHead hooked (FullAimbot): trampoline=%p", s_orig_check_dmg_hithead);
        } else if (!enable && !s_auto_headshot && !s_silent_aim && s_orig_check_dmg_hithead) {
            HookEngine::get().unhook(m_mth.checkDamageHitHead->methodPointer);
            s_orig_check_dmg_hithead = nullptr;
        }
    }

    LOGI("FullAimbot: %s  update=%p ads=%p center=%p hithead=%p heuristic=%p/%p",
         enable ? "ON" : "OFF",
         s_orig_update_aiming, s_orig_update_aiming_ads, s_orig_attackable_ctr,
         s_orig_check_dmg_hithead, s_orig_has_heuristic, s_orig_get_heuristic);
}

void FeatureEngine::applyAntiAim(bool enable) {
    s_anti_aim = enable;
    // Anti-aim: jam enemy aim assist by making our attackable center return zero/far position.
    // The hook_get_attackable_center already handles this when anti_aim flag is set —
    // for our own player object we return a far-away position.
    // No separate hook needed; the existing center hook covers it.
    LOGI("AntiAim: %s", enable ? "ON" : "OFF");
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
            "GetCurrentMaxSpeed",
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
    s_esp     = enable;
    s_esp_hud = enable;

    // Cache ResourceIDDef pointers for lazy in-game init inside hook_get_attackable_center.
    // Singleton only exists inside a match, so we can't call it here at toggle time.
    if (enable) {
        s_res_id_get_inst = m_mth.resIdGetInstance  ? m_mth.resIdGetInstance->methodPointer  : nullptr;
        s_res_id_try_init = m_mth.tryInitOutlineRes ? m_mth.tryInitOutlineRes->methodPointer : nullptr;
        s_res_id_show     = m_mth.showPlayerOutline ? m_mth.showPlayerOutline->methodPointer : nullptr;
        s_res_id_cls      = m_cls.ResIdDef;
    } else {
        // Reset lazy-init state so next enable retries from scratch
        s_res_id_get_inst = nullptr;
        s_res_id_try_init = nullptr;
        s_res_id_show     = nullptr;
        s_res_id_cls      = nullptr;
        // Reset per-session statics in the hook so next enable restarts fresh
        // (done via the s_res_init_done static inside hook_get_attackable_center —
        //  can't reset a function-local static from here; it resets on next match entry
        //  naturally since the singleton pointer changes per session)
    }

    // Layer 1 (DISABLED): IsVisible() in Free Fire is a stealth-state getter, not a
    // renderer culling check. Forcing it true marks ALL players as cloaked/invisible,
    // which is the opposite of what we want — bodies disappear, only weapons remain.
    // Outline layers (3+4) render through walls via the game's depth-ignore outline
    // shader without touching this method.
    (void)s_orig_visible;

    // Layer 2: HUD SetVisible — forces enemy health bars / name plates to render
    if (m_mth.hudSetVisible && m_mth.hudSetVisible->methodPointer) {
        if (enable && !s_orig_hud_show)
            HookEngine::get().hookAddr(m_mth.hudSetVisible->methodPointer,
                reinterpret_cast<void *>(hook_hud_set_visible), &s_orig_hud_show, "ESP-hud");
        else if (!enable && s_orig_hud_show) {
            HookEngine::get().unhook(m_mth.hudSetVisible->methodPointer);
            s_orig_hud_show = nullptr;
        }
    } else {
        LOGE("ESP: HUD method not resolved — enemies visible in culling only, no boxes");
    }

    // Layer 3: SetOutlineVisible — Dobby hook (signature fixed: pc=2 → uint8_t visible, int mode).
    // Hooks every game call so visible=0 is forced to 1; trampoline fills s_orig_set_outline_vis.
    if (m_mth.setOutlineVisible && m_mth.setOutlineVisible->methodPointer) {
        if (enable && !s_orig_set_outline_vis) {
            HookEngine::get().hookAddr(m_mth.setOutlineVisible->methodPointer,
                reinterpret_cast<void *>(hook_set_outline_vis), &s_orig_set_outline_vis, "ESP-SetOutlineVis");
            LOGI("[ESP-DIAG] Layer3 SetOutlineVisible HOOKED trampoline=%p", s_orig_set_outline_vis);
        } else if (!enable && s_orig_set_outline_vis) {
            HookEngine::get().unhook(m_mth.setOutlineVisible->methodPointer);
            s_orig_set_outline_vis = nullptr;
            LOGI("[ESP-DIAG] Layer3 SetOutlineVisible unhooked");
        } else {
            LOGI("[ESP-DIAG] Layer3 ptr=%p (already in target state)", s_orig_set_outline_vis);
        }
    } else {
        LOGE("[ESP-DIAG] Layer3 SKIP — SetOutlineVisible ptr null");
    }

    // Layer 4: InitOutline — HOOK it so hook_init_outline auto-calls SetOutlineVisible(1) after.
    // We call InitOutline through its hooked address from hook_get_attackable_center (throttled),
    // which triggers: hook_init_outline → original InitOutline → SetOutlineVisible(self, 1).
    // s_orig_init_outline = trampoline to original (filled by Dobby).
    if (m_mth.initOutline && m_mth.initOutline->methodPointer) {
        if (enable && !s_orig_init_outline) {
            HookEngine::get().hookAddr(m_mth.initOutline->methodPointer,
                reinterpret_cast<void *>(hook_init_outline), &s_orig_init_outline, "ESP-InitOutline");
            s_initoutline_hooked_addr = m_mth.initOutline->methodPointer;
            LOGI("[ESP-DIAG] Layer4 InitOutline hooked, trampoline=%p hooked_addr=%p",
                 s_orig_init_outline, s_initoutline_hooked_addr);
        } else if (!enable && s_orig_init_outline) {
            HookEngine::get().unhook(m_mth.initOutline->methodPointer);
            s_orig_init_outline = nullptr;
            s_initoutline_hooked_addr = nullptr;
            LOGI("[ESP-DIAG] Layer4 InitOutline unhooked");
        }
    } else {
        LOGE("[ESP-DIAG] Layer4 SKIP — InitOutline ptr null");
    }

    // Layer 5: Player.Update hook for proactive per-frame outline + renderQ injection.
    // Activates when either SetOutlineVisible OR SetRenderQ is resolved — we need the
    // per-frame tick regardless of which outline path we end up using.
    bool hasOutlinePath = (m_mth.setOutlineVisible && m_mth.setOutlineVisible->methodPointer) ||
                          (m_mth.setRenderQ       && m_mth.setRenderQ->methodPointer);
    if (m_mth.playerUpdate && m_mth.playerUpdate->methodPointer && hasOutlinePath) {
        if (enable && !s_orig_update) {
            HookEngine::get().hookAddr(m_mth.playerUpdate->methodPointer,
                reinterpret_cast<void *>(hook_player_update), &s_orig_update, "ESP-UpdateTick");
            LOGI("[ESP-DIAG] Layer5 Player.Update hooked for proactive outline+renderQ");
        } else if (!enable && s_orig_update) {
            if (!s_tp_has_save && !s_tp_pending) {
                HookEngine::get().unhook(m_mth.playerUpdate->methodPointer);
                s_orig_update = nullptr;
                LOGI("[ESP-DIAG] Layer5 Player.Update unhooked");
            }
        }
    } else {
        LOGE("[ESP-DIAG] Layer5 SKIP — no outline path or playerUpdate ptr null");
    }

    // Layer 6: SetRenderQ — store method pointer for per-frame injection in hook_player_update.
    // SetRenderQ(5000) puts each player in Unity's Overlay render queue (renders above walls).
    // No Dobby hook needed — we call it directly inside the Player.Update hook.
    LOGI("[ESP-DIAG] Layer6 setup: setRenderQ=%p revertRenderQ=%p",
         m_mth.setRenderQ    ? m_mth.setRenderQ->methodPointer    : nullptr,
         m_mth.revertRenderQ ? m_mth.revertRenderQ->methodPointer : nullptr);
    if (m_mth.setRenderQ && m_mth.setRenderQ->methodPointer) {
        if (enable) {
            s_orig_set_render_q    = m_mth.setRenderQ->methodPointer;
            s_orig_revert_render_q = (m_mth.revertRenderQ && m_mth.revertRenderQ->methodPointer)
                                     ? m_mth.revertRenderQ->methodPointer : nullptr;
            LOGI("[ESP-DIAG] Layer6 SetRenderQ ptr=%p stored", s_orig_set_render_q);
        } else {
            s_orig_set_render_q    = nullptr;
            s_orig_revert_render_q = nullptr;
            LOGI("[ESP-DIAG] Layer6 SetRenderQ ptr cleared");
        }
    } else {
        LOGE("[ESP-DIAG] Layer6 SKIP — SetRenderQ ptr null");
    }

    // MatchGame.ShowPlayerOutline(true) is deferred to hook_get_attackable_center.
    // Reason: applyESP runs on the socket server thread (raw pthread, no IL2CPP managed context).
    // Calling managed IL2CPP singletons from that thread crashes. The aim hook runs on the
    // game's own update thread which has managed context — safe to call GetMatch() there.
    // Reset the once-flag so the next match session re-enables the outline.
    if (!enable) { s_matchgame_outline_done = false; s_gs_outline_done = false; }
    // Also cache GSD function pointers so hook_player_update can call them
    if (enable && !s_gs_get_instance_fn && m_mth.gsGetInstance)
        s_gs_get_instance_fn = m_mth.gsGetInstance->methodPointer;
    if (enable && !s_gs_enable_team_fn && m_mth.gsEnableTeamOL)
        s_gs_enable_team_fn = m_mth.gsEnableTeamOL->methodPointer;
    if (enable && !s_is_local_player_fn && m_mth.isLocalPlayer)
        s_is_local_player_fn = m_mth.isLocalPlayer->methodPointer;
    LOGI("[ESP-DIAG] MatchGame.ShowPlayerOutline deferred to game thread (flag reset=%d)", !enable);

    // Layer 7: GetAttackableCenterWS hook — fires on each enemy the aim system processes.
    // Guarantees SetRenderQ + SetOutlineVisible reach enemy instances even when
    // Player.Update only runs for the local player. Shared with headshot/aimbot hooks.
    if (m_mth.calcAimTarget) {
        if (enable) installAimCenterHook(m_mth.calcAimTarget);
        else        removeAimCenterHook(m_mth.calcAimTarget);
        LOGI("[ESP-DIAG] Layer7 aim-center hook: %s trampoline=%p",
             enable ? "ON" : "OFF", s_orig_attackable_ctr);
    } else {
        LOGE("[ESP-DIAG] Layer7 SKIP — calcAimTarget ptr null");
    }

    LOGI("[ESP-DIAG] applyESP done: enable=%d hud=%p outline=%p initoutline=%p update=%p renderQ=%p",
         (int)enable, s_orig_hud_show, s_orig_set_outline_vis, s_orig_init_outline,
         s_orig_update, s_orig_set_render_q);
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
        case ZX_AIM_ENABLE:    applyAimAssist(enable);    break;
        case ZX_AIM_BONE:      applyAimAssist(enable);    break;  // bone selector — todo
        case ZX_AIM_FOV:       applyAimAssist(enable);    break;  // FOV slider  — todo
        case ZX_AIM_SMOOTH:    applyAimAssist(enable);    break;  // smoothing   — todo
        case ZX_SILENT_AIM:    applySilentAim(enable);    break;
        case ZX_AUTO_HEADSHOT: applyAutoHeadshot(enable); break;
        case ZX_FULL_AIMBOT:   applyFullAimbot(enable);   break;
        case ZX_ANTI_AIM:      applyAntiAim(enable);      break;

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
