#pragma once
#include <cstddef>
#include <cstdint>

// Hides the module from AnoSDK memory scans via two techniques:
//   1. Zero ELF header bytes through /proc/self/mem (destroys library signature)
//   2. prctl(PR_SET_VMA_ANON_NAME) removes .so name from /proc/self/maps
namespace MemoryGuard {
    bool  init();
    bool  hideSelf();          // hide this module's loaded pages from scanner
    bool  hideRegion(void *addr, size_t size);
    void  restore();
}
