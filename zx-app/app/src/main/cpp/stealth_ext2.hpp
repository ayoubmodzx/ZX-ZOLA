#pragma once
#include <cstddef>

void install_stealth_ext2();
void stx2_mask_thread_name();

// Called by dobby_impl.cpp when it allocates a trampoline page.
// Registers the page in the in-memory RWX registry so mincore + tp_syscall
// hooks can spoof its residency without reading /proc/self/maps.
void stx2_register_rwx(void *page, size_t size);
