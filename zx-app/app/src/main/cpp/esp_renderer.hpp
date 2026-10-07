#pragma once
#include <cstdint>

struct Il2CppObject;

namespace ESP {
    // Called once from Features::init() after il2cpp is ready
    void init();

    // Called from features dispatch when ESP toggle changes
    void setEnabled(bool on);

    // Called from features dispatch when headshot assist toggle changes
    void setHeadshotAssist(bool on);

    Il2CppObject* getHeadTarget();
    bool          hasHeadTarget();
}
