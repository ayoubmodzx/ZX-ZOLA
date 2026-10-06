#pragma once

enum FeatureCmd {
    CMD_ANTI_RECOIL      = 1, CMD_NO_SPREAD       = 2,
    CMD_RAPID_FIRE       = 3, CMD_AIM_ASSIST       = 4,
    CMD_WIDE_POV         = 5,
    CMD_ESP              = 6,    // wall ESP + neon glow
    CMD_HEADSHOT_ASSIST  = 7,    // headshot accuracy assist
};

namespace Features {
    void init();              // discover classes + install engine hooks (called once)
    void apply(int cmd, bool enable);
}
