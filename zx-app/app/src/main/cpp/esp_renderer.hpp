#pragma once
#include <cstdint>

struct Vec2 { float x, y; };
struct Il2CppObject;

namespace ESP {
    void init();
    void setEnabled(bool on);
    void setHeadshotAssist(bool on);
    Vec2 getHeadTarget();
    bool hasHeadTarget();
    // World-space position of the nearest visible enemy head (for silent aim)
    bool getHeadWorldPos3(float *x, float *y, float *z);
    // Local player world position (for direction calculation)
    bool getLocalPos3(float *x, float *y, float *z);
}
