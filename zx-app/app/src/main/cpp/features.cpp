#include "features.hpp"
#include "il2cpp_scanner.hpp"
#include "dobby_stub.hpp"
#include <android/log.h>
#include <cstring>

#define TAG "ZX-FEAT"
#define LOG(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

// ── Field write helpers ───────────────────────────────────────────────────────

static inline void writeFloat(Il2CppClass *klass, const char *field, float val) {
    auto *f = Il2Cpp::getField(klass, field);
    if (f) Il2Cpp::setStaticFloat(f, val);
}

static inline void writeBool(Il2CppClass *klass, const char *field, bool val) {
    auto *f = Il2Cpp::getField(klass, field);
    if (f) Il2Cpp::setStaticBool(f, val);
}

// ── Feature implementations ──────────────────────────────────────────────────

static void antiRecoil(bool on) {
    writeFloat(Il2Cpp::cls("RecoilController"), "recoilForce",   on ? 0.0f : 1.0f);
    writeFloat(Il2Cpp::cls("RecoilController"), "verticalRecoil", on ? 0.0f : 1.0f);
    LOG("AntiRecoil %s", on?"ON":"OFF");
}

static void noSpread(bool on) {
    writeFloat(Il2Cpp::cls("WeaponController"), "bulletSpread",   on ? 0.0f : 1.0f);
    writeFloat(Il2Cpp::cls("WeaponController"), "horizontalDrift", on ? 0.0f : 1.0f);
    LOG("NoSpread %s", on?"ON":"OFF");
}

static void rapidFire(bool on) {
    writeFloat(Il2Cpp::cls("WeaponController"), "fireRate",   on ? 0.01f : 0.3f);
    writeFloat(Il2Cpp::cls("WeaponController"), "fireDelay",  on ? 0.0f  : 0.1f);
    LOG("RapidFire %s", on?"ON":"OFF");
}

static void *orig_aim_calc = nullptr;
static void *hook_aim_calc(void *self) {
    // Call original, then snap to nearest enemy — stub for now
    using Fn = void *(*)(void *);
    return reinterpret_cast<Fn>(orig_aim_calc)(self);
}
static void aimAssist(bool on) {
    auto *m = Il2Cpp::getMethod(Il2Cpp::cls("AimController"), "CalculateAimTarget", 0);
    if (!m || !m->methodPointer) return;
    if (on && !orig_aim_calc)
        DobbyHook(m->methodPointer, (void*)hook_aim_calc, &orig_aim_calc);
    else if (!on && orig_aim_calc)
        DobbyDestroy(m->methodPointer);
    LOG("AimAssist %s", on?"ON":"OFF");
}

static void speedHack(bool on) {
    writeFloat(Il2Cpp::cls("PlayerMovement"), "moveSpeed",    on ? 9.5f  : 6.0f);
    writeFloat(Il2Cpp::cls("PlayerMovement"), "sprintSpeed",  on ? 13.0f : 9.0f);
    LOG("SpeedHack %s", on?"ON":"OFF");
}

static void highJump(bool on) {
    writeFloat(Il2Cpp::cls("CharacterController"), "jumpForce",    on ? 20.0f : 8.0f);
    writeFloat(Il2Cpp::cls("CharacterController"), "gravityScale", on ? 0.6f  : 1.0f);
    LOG("HighJump %s", on?"ON":"OFF");
}

static void vehicleSpeed(bool on) {
    writeFloat(Il2Cpp::cls("VehicleController"), "maxSpeed",        on ? 200.0f : 100.0f);
    writeFloat(Il2Cpp::cls("VehicleController"), "enginePower",     on ? 2.0f   : 1.0f);
    LOG("VehicleSpeed %s", on?"ON":"OFF");
}

static void widePov(bool on) {
    Il2Cpp::setStaticFloat(
        Il2Cpp::getField(Il2Cpp::cls("CameraController"), "fieldOfView"),
        on ? 90.0f : 60.0f);
    LOG("WidePOV %s", on?"ON":"OFF");
}

static void noGrass(bool on) {
    writeBool(Il2Cpp::cls("GrassManager"), "enableGrass", !on);
    LOG("NoGrass %s", on?"ON":"OFF");
}

static void maxHealth(bool on) {
    writeFloat(Il2Cpp::cls("HealthComponent"), "maxHealth",     on ? 9999.0f : 200.0f);
    writeFloat(Il2Cpp::cls("HealthComponent"), "currentHealth", on ? 9999.0f : 200.0f);
    LOG("MaxHealth %s", on?"ON":"OFF");
}

static void *orig_take_dmg = nullptr;
static void  hook_take_dmg(void *self, float dmg, void *src) {
    // Block all incoming damage
    (void)self; (void)dmg; (void)src;
}
static void antiDamage(bool on) {
    auto *m = Il2Cpp::getMethod(Il2Cpp::cls("HealthComponent"), "TakeDamage", 2);
    if (!m || !m->methodPointer) return;
    if (on && !orig_take_dmg)
        DobbyHook(m->methodPointer, (void*)hook_take_dmg, &orig_take_dmg);
    else if (!on && orig_take_dmg)
        DobbyDestroy(m->methodPointer);
    LOG("AntiDamage %s", on?"ON":"OFF");
}

// ── Dispatch ─────────────────────────────────────────────────────────────────

void Features::apply(int cmd, bool enable) {
    switch (cmd) {
        case CMD_ANTI_RECOIL:   antiRecoil(enable);    break;
        case CMD_NO_SPREAD:     noSpread(enable);      break;
        case CMD_RAPID_FIRE:    rapidFire(enable);     break;
        case CMD_AIM_ASSIST:    aimAssist(enable);     break;
        case CMD_SPEED_HACK:    speedHack(enable);     break;
        case CMD_HIGH_JUMP:     highJump(enable);      break;
        case CMD_VEHICLE_SPEED: vehicleSpeed(enable);  break;
        case CMD_WIDE_POV:      widePov(enable);       break;
        case CMD_NO_GRASS:      noGrass(enable);       break;
        case CMD_MAX_HEALTH:    maxHealth(enable);     break;
        case CMD_ANTI_DAMAGE:   antiDamage(enable);    break;
        default: LOG("Unknown cmd: %d", cmd);
    }
}
