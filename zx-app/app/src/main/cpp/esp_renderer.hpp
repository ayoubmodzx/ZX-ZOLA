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
}
