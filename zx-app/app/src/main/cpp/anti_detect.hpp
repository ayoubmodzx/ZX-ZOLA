#pragma once
#include <cstddef>
#include <cstdint>

namespace AntiDetect {
    // Install all six bypass layers — call first thing in payload_init()
    void install();
}

// Called by dobby_impl.cpp after each anonymous RWX trampoline page allocation.
// Registers the page so Layer 2 /proc hider filters it from maps/smaps output.
void zx_track_rwx_page(void *p, size_t sz);

// Called by dobby_impl.cpp after each DobbyHook() to register the trampoline
// address for the Layer 4 signature scrub pass.
void zx_register_scrub_target(void *hook_addr);
