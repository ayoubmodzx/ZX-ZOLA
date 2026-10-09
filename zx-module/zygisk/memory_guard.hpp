#pragma once
#include <cstddef>
#include <cstdint>

// Uses libffutil.so's own unmap functions to hide our .so from AnoSDK memory scans
// libffutil exports: ffutil_UnmapAddr, ffutil_UnmapSize, ffutil_Unmap
namespace MemoryGuard {
    bool  init();
    bool  hideSelf();          // hide this module's loaded pages from scanner
    bool  hideRegion(void *addr, size_t size);
    void  restore();
}
