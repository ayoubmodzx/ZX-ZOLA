# ZX-ZOLA — Free Fire Zygisk Module

## Library Analysis (from arm64/ folder)

| Library | Role | How ZX Uses It |
|---|---|---|
| `libanogs.so` | Tencent AnoSDK Anti-Cheat | Hooks `AnoSDKIoctl` + all `GetReportData` funcs to block scan reports |
| `libffutil.so` | FF Memory Utility | Uses `ffutil_UnmapAddr/Size` to hide ZX pages from memory scanner |
| `libanort.so` | Anti-cheat runtime (stack unwind detection) | Referenced for future `unwind_xx_ioctl` bypass |
| `libGGP.so` | Game Guardian Protocol (8.8MB, obfuscated) | Analyzed — depends on libanogs, no direct hooks needed |
| `libil2cpp.so` | Unity IL2CPP runtime | Full API via `il2cpp_api.cpp` — class/field/method resolution |
| `libFFWebRequest.so` | curl/OpenSSL network | Not hooked — unnecessary |
| `libCustomVideoPlayer.so` | GL video renderer | Not hooked — not needed |
| Firebase libs | Analytics / Crashlytics | Not hooked — no game impact |

## Why it doesn't lag (vs ZOLAM)

| ZOLAM | ZX-ZOLA |
|---|---|
| Hooks 7 GL functions on render thread | **Zero GL hooks** |
| `inline_hook_opcode_dismatch` in libanogs detects its Dobby hooks | AnoSDK bypass installed **before** hooks go in |
| il2cpp scanning inline with every frame | All il2cpp on **SCHED_IDLE background thread** |
| No memory hiding | Uses `libffutil.so` to hide ZX pages from scanner |
| Active on all processes | Unloads from every non-FF process |

## Feature List (ZX Menu)

### COMBAT
- Anti-Recoil — `RecoilController.recoilForce = 0`
- No Spread — `WeaponController.bulletSpread = 0`
- Rapid Fire — `WeaponController.fireRate = 0.05`
- Aim Assist — hooks only `AimController.CalculateAimTarget` (1 hook)

### MOVEMENT
- Speed Hack — `PlayerMovement.moveSpeed × multiplier`
- High Jump — `CharacterController.jumpForce = 18`
- Vehicle Speed — `VehicleController.maxSpeed × multiplier`

### VISUAL
- Wide POV — `CameraController.fieldOfView`
- No Grass — `GrassManager.enableGrass = false`

### SURVIVAL
- Max Health — `HealthComponent.maxHealth = 9999`
- Anti Damage — hooks `HealthComponent.TakeDamage` (1 hook)

## Build

```bash
cmake -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
      -DANDROID_ABI=arm64-v8a \
      -DANDROID_PLATFORM=android-31 \
      -DCMAKE_BUILD_TYPE=Release \
      -B build/arm64

cmake --build build/arm64
```

## Load Order (main.cpp)

```
1. MemoryGuard::hideSelf()     — hide from AnoSDK scanner
2. AnoBypass::install()         — intercept all report functions
3. Il2CppApi::init()            — resolve il2cpp symbols
4. FeatureEngine::init()        — async feature application (3.5s delay)
```
