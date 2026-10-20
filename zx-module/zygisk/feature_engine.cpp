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
            applyNoGrass(true);
            applyWidePOV(85.0f);
            LOGI("Features ready — socket server starting");
        } else {
            LOGE("Class resolution failed — check FF version");
        }
        startServer();
    }, 3500);
}

void FeatureEngine::resolveClasses() {
    Il2CppImage *img = Il2CppApi::getImage("Assembly-CSharp");
    if (!img) { LOGE("Assembly-CSharp not found"); return; }

    m_cls.Player    = Il2CppApi::getClass(img, "", "PlayerMovement");
    m_cls.Character = Il2CppApi::getClass(img, "", "CharacterController");
    m_cls.Health    = Il2CppApi::getClass(img, "", "HealthComponent");
    m_cls.Weapon    = Il2CppApi::getClass(img, "", "WeaponController");
    m_cls.Bullet    = Il2CppApi::getClass(img, "", "BulletManager");
    m_cls.Recoil    = Il2CppApi::getClass(img, "", "RecoilController");
    m_cls.Camera    = Il2CppApi::getClass(img, "", "CameraController");
    m_cls.Aim       = Il2CppApi::getClass(img, "", "AimController");
    m_cls.Grass     = Il2CppApi::getClass(img, "", "GrassManager");
    m_cls.Vehicle   = Il2CppApi::getClass(img, "", "VehicleController");

    if (m_cls.Player)    m_fld.moveSpeed    = Il2CppApi::getField(m_cls.Player,    "moveSpeed");
    if (m_cls.Character) m_fld.jumpForce    = Il2CppApi::getField(m_cls.Character, "jumpForce");
    if (m_cls.Recoil)    m_fld.recoilForce  = Il2CppApi::getField(m_cls.Recoil,   "recoilForce");
    if (m_cls.Weapon)    m_fld.bulletSpread = Il2CppApi::getField(m_cls.Weapon,    "bulletSpread");
    if (m_cls.Weapon)    m_fld.fireRate     = Il2CppApi::getField(m_cls.Weapon,    "fireRate");
    if (m_cls.Camera)    m_fld.fov          = Il2CppApi::getField(m_cls.Camera,    "fieldOfView");
    if (m_cls.Grass)     m_fld.grassEnable  = Il2CppApi::getField(m_cls.Grass,    "enableGrass");
    if (m_cls.Health)    m_fld.maxHealth    = Il2CppApi::getField(m_cls.Health,    "maxHealth");
    if (m_cls.Vehicle)   m_fld.vehicleSpeed = Il2CppApi::getField(m_cls.Vehicle,  "maxSpeed");

    if (m_cls.Aim)    m_mth.calcAimTarget = Il2CppApi::getMethod(m_cls.Aim,    "CalculateAimTarget", 0);
    if (m_cls.Weapon) m_mth.onFireWeapon  = Il2CppApi::getMethod(m_cls.Weapon, "OnFireWeapon",       1);
    if (m_cls.Health) m_mth.takeDamage    = Il2CppApi::getMethod(m_cls.Health, "TakeDamage",         2);

    m_ready = (m_cls.Player || m_cls.Weapon || m_cls.Camera);
    LOGI("Classes resolved — Player:%p Weapon:%p Camera:%p Grass:%p",
         m_cls.Player, m_cls.Weapon, m_cls.Camera, m_cls.Grass);
}

// ── Feature implementations ───────────────────────────────────────────────────

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
    if (!m_mth.calcAimTarget || !m_mth.calcAimTarget->methodPointer) return;
    static void *orig_calc = nullptr;
    if (enable && !orig_calc) {
        static auto hook_fn = [](void *instance) -> void * {
            using Fn = void *(*)(void *);
            return reinterpret_cast<Fn>(orig_calc)(instance);
        };
        HookEngine::get().hookAddr(m_mth.calcAimTarget->methodPointer,
            (void *)static_cast<void *(*)(void *)>(hook_fn), &orig_calc, "AimAssist");
    } else if (!enable && orig_calc) {
        HookEngine::get().unhook(m_mth.calcAimTarget->methodPointer);
        orig_calc = nullptr;
    }
    LOGI("AimAssist: %s", enable ? "ON" : "OFF");
}

void FeatureEngine::applySpeedHack(bool enable, float multiplier) {
    if (!m_fld.moveSpeed) return;
    float val = enable ? 6.0f * multiplier : 6.0f;
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
    float val = enable ? 100.0f * multiplier : 100.0f;
    Il2CppApi::setStaticValue(nullptr, m_fld.vehicleSpeed, &val);
    LOGI("VehicleSpeed: %s", enable ? "ON" : "OFF");
}

void FeatureEngine::applyWidePOV(float fov) {
    if (!m_fld.fov) return;
    Il2CppApi::setStaticValue(nullptr, m_fld.fov, &fov);
    LOGI("WidePOV: %.1f", fov);
}

void FeatureEngine::applyNoGrass(bool enable) {
    if (!m_fld.grassEnable) return;
    bool val = !enable;
    Il2CppApi::setStaticValue(nullptr, m_fld.grassEnable, &val);
    LOGI("NoGrass: %s", enable ? "ON" : "OFF");
}

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
            (void)self; (void)dmg; (void)src;
        };
        HookEngine::get().hookAddr(m_mth.takeDamage->methodPointer,
            (void *)static_cast<void(*)(void*, float, void*)>(hook_dmg),
            &orig_take_dmg, "AntiDamage");
    } else if (!enable && orig_take_dmg) {
        HookEngine::get().unhook(m_mth.takeDamage->methodPointer);
        orig_take_dmg = nullptr;
    }
    LOGI("AntiDamage: %s", enable ? "ON" : "OFF");
}

// ── Command dispatch ──────────────────────────────────────────────────────────

void FeatureEngine::dispatch(uint8_t cmd, bool enable, float intensity) {
    switch (cmd) {
        case ZX_ANTI_RECOIL:   applyAntiRecoil(enable); break;
        case ZX_NO_SPREAD:     applyNoSpread(enable); break;
        case ZX_RAPID_FIRE:    applyRapidFire(enable); break;
        case ZX_AIM_ENABLE:    applyAimAssist(enable); break;
        case ZX_SPEED_HACK:    applySpeedHack(enable, intensity > 0.f ? intensity : 1.5f); break;
        case ZX_HIGH_JUMP:     applyHighJump(enable); break;
        case ZX_VEHICLE_SPEED: applyVehicleSpeed(enable, intensity > 0.f ? intensity : 2.0f); break;
        case ZX_WIDE_POV:      applyWidePOV(intensity > 0.f ? intensity : 85.0f); break;
        case ZX_NO_GRASS:      applyNoGrass(enable); break;
        case ZX_MAX_HEALTH:    applyMaxHealth(enable); break;
        case ZX_ANTI_DAMAGE:   applyAntiDamage(enable); break;
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
