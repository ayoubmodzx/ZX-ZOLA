#pragma once
#include <cstdint>

namespace AnoBypass {
    // Phase 1 — Hook libc.so: exit/_exit/abort/kill
    // libc.so is ALWAYS loaded. Call synchronously in postAppSpecialize
    // before any worker thread, so hooks fire before any game lib loads.
    void installEarly();

    // Phase 2 — Launch a detached watcher thread that polls for libanogs.so
    // every 100ms and installs SDK-level API hooks once it appears.
    // Call from the async worker thread.
    void startWatcher();

    // Legacy combined entry-point (installEarly + startWatcher).
    bool install();

    void remove();
}
