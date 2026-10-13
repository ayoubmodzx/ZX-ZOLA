#pragma once

struct KillShield {
    // Call once from postAppSpecialize.
    // - hooks android_dlopen_ext to patch libanogs/libanort the instant they load
    // - hooks pthread_create to deliver seccomp BPF to every new thread
    // - installs seccomp on the calling thread immediately
    static bool install();
};
