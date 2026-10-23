#pragma once
#include <cstdint>

namespace AnoBypass {
    // Phase 1 — Hook libc.so: exit/_exit/abort/kill
    // libc.so is ALWAYS loaded. Call synchronously in postAppSpecialize
    // before any worker thread, so hooks fire before any game lib loads.
    void installEarly();

    // Phase 2 removed: Dobby hooks on libanogs.so exports trigger AnoSDK
    // code-integrity self-check → heartbeat carries detection → server ban.
    void startWatcher(); // no-op kept for ABI compat

    // Legacy combined entry-point (installEarly + startWatcher).
    bool install();

    void remove();
}
