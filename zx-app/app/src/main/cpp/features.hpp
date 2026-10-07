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
};

namespace Features {
    void init();
    void apply(int cmd, bool enable);
    void applyIntensity(int cmd, int intensity); // 0-100 percent
}
