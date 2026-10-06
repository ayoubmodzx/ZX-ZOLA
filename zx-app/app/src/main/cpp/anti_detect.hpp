#pragma once

namespace AntiDetect {
    // Install all four bypass layers:
    //  1. libffutil.so page-hiding bypass
    //  2. /proc/self/maps sanitisation (openat hook)
    //  3. AnoSDK extended hooks (DelReportData, set_check_period)
    //  4. Dobby trampoline signature scrub
    void install();
}

// Called from dobby_impl.cpp after each hook installed — registers the
// hook target for the Layer 4 trampoline scrub pass.
void zx_register_scrub_target(void *hook_addr);
