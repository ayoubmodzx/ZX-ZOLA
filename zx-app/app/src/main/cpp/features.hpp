#pragma once

enum FeatureCmd {
    CMD_ANTI_RECOIL   = 1, CMD_NO_SPREAD    = 2,
    CMD_RAPID_FIRE    = 3, CMD_AIM_ASSIST   = 4,
    CMD_SPEED_HACK    = 5, CMD_HIGH_JUMP    = 6,
    CMD_VEHICLE_SPEED = 7, CMD_WIDE_POV     = 8,
    CMD_NO_GRASS      = 9, CMD_MAX_HEALTH   = 10,
    CMD_ANTI_DAMAGE   = 11,
};

namespace Features {
    void init();              // discover classes + install engine hooks (called once)
    void apply(int cmd, bool enable);
}
