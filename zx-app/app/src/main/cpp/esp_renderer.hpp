#pragma once
#include <cstdint>
#include "zx_types.hpp"

struct Il2CppObject;

namespace ESP {
    void init();
    void setEnabled(bool on);
    void setHeadshotAssist(bool on);
    Vec2 getHeadTarget();
    bool hasHeadTarget();
    Vec3 getHeadWorldPos();  // world-space position of closest visible enemy head
    Vec3 getLocalPos();      // local player world position (updated every 50ms)
}
