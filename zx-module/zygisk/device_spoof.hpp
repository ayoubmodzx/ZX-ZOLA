#pragma once
#include <cstdint>
#include <jni.h>

// Device fingerprint spoofer — masks hardware IDs from AnoSDK and game telemetry.
// Hooks:
//   __system_property_get  → spoof ro.serialno / ro.boot.serialno / ro.boot.wifi_macaddr
//   open/read              → intercept /sys/class/net/wlan0/address (MAC)
//   JNIEnv vtable          → spoof Settings.Secure.getString("android_id")
//
// IDs are derived from a stable seed (build fingerprint hash) so the spoofed
// values are consistent across game restarts on the same flash/ROM, but differ
// from the real hardware values AnoSDK would see.
namespace DeviceSpoof {
    void install(JNIEnv *env);   // call once after postAppSpecialize
    void setCustomAndroidId(const char *id16hex); // optional: override from server cmd
}
