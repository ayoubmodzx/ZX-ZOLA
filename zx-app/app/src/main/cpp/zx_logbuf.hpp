#pragma once
// zx_logbuf.hpp — payload ring-buffer log forwarding
// Any TU in libzx_payload.so calls zx_buf_write(); the injector reads the buffer
// via /proc/PID/mem and prints to stderr, which ZxEngine shows in the console.

#include <android/log.h>
#include <cstdio>

#ifdef __cplusplus
extern "C" {
#endif
void zx_buf_write(const char *msg);
#ifdef __cplusplus
}
#endif

// LOGBUF_I / LOGBUF_E: write to BOTH logcat AND the ring buffer
#define LOGBUF_I(tag_, fmt_, ...) \
    do { \
        __android_log_print(ANDROID_LOG_INFO,  tag_, fmt_, ##__VA_ARGS__); \
        char _zb_[512]; \
        snprintf(_zb_, sizeof(_zb_), "[" tag_ "] " fmt_, ##__VA_ARGS__); \
        zx_buf_write(_zb_); \
    } while(0)

#define LOGBUF_E(tag_, fmt_, ...) \
    do { \
        __android_log_print(ANDROID_LOG_ERROR, tag_, fmt_, ##__VA_ARGS__); \
        char _zb_[512]; \
        snprintf(_zb_, sizeof(_zb_), "[" tag_ "!] " fmt_, ##__VA_ARGS__); \
        zx_buf_write(_zb_); \
    } while(0)
