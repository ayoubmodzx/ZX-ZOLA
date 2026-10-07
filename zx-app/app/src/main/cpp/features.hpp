#pragma once

enum FeatureCmd {
    CMD_ANTI_RECOIL      = 1, CMD_NO_SPREAD       = 2,
    CMD_RAPID_FIRE       = 3, CMD_AIM_ASSIST       = 4,
    CMD_ESP              = 5, CMD_HEADSHOT_ASSIST  = 6,
    CMD_WIDE_POV         = 7,
    CMD_SPEED_HACK       = 8,  // risk: player move speed multiplier
    CMD_HIGH_JUMP        = 9,  // risk: jump height multiplier
    CMD_VEHICLE_SPEED    = 10, // risk: vehicle speed multiplier
    CMD_RAPID_FIRE_RISK  = 11, // risk: rapid fire with intensity
};

namespace Features {
    void init();
    void apply(int cmd, bool enable);
    void applyIntensity(int cmd, int intensity); // 0-100 percent
}
