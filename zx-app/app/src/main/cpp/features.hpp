#pragma once

enum FeatureCmd {
    CMD_ANTI_RECOIL      = 1, CMD_NO_SPREAD        = 2,
    CMD_RAPID_FIRE       = 3, CMD_WIDE_POV          = 4,
    CMD_ESP              = 5, CMD_SPEED_HACK        = 6,
    CMD_HIGH_JUMP        = 7, CMD_VEHICLE_SPEED     = 8,
    CMD_RAPID_FIRE_RISK  = 9, CMD_NO_GRASS          = 10,
    CMD_ANTI_DAMAGE      = 11,
    CMD_AIM_ENABLE       = 12, // master aim hook toggle
    CMD_AIM_BONE         = 13, // intensity: 0=AI(smooth), 1=NECK, 2=HEAD
    CMD_AIM_FOV          = 14, // intensity: 5-90 degrees magnetism radius
    CMD_AIM_SMOOTH       = 15, // intensity: 0-100 tracking smoothness
    CMD_GOD_MODE         = 16,  // block all incoming damage
    CMD_INFINITE_AMMO    = 17,  // refill ammo after every shot
    CMD_NO_RELOAD        = 18,  // zero reload time
    CMD_NOCLIP           = 19,  // disable collision
    CMD_TELEPORT         = 20,  // teleport to saved coords
    CMD_TELEPORT_SAVE    = 21,  // save current position as target
    CMD_SILENT_AIM       = 22,  // correct bullet angle server-side only
    CMD_AUTO_HEADSHOT    = 23,  // force bone target to HEAD always
    CMD_FULL_AIMBOT      = 24,  // lock + track nearest enemy head
    CMD_ANTI_AIM         = 25,  // randomise our own aim angles vs enemy aimbots
    CMD_AUTO_REVIVE      = 26,  // auto trigger revive on downed teammate
    CMD_WALL_SHOOT       = 27,  // disable ray-cast line-of-sight check on fire
    CMD_BULLET_DAMAGE    = 28,  // multiply outgoing bullet damage before each shot
};

namespace Features {
    void init();
    void apply(int cmd, bool enable);
    void applyIntensity(int cmd, int intensity); // 0-100 percent
}
