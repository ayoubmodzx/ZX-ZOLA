# ZX by AYOUB — Project Archive

**App:** ZX Mod Menu for Free Fire  
**Target:** ARM64 Android, Unity IL2CPP  
**Package:** `com.zx.zola`  
**Version:** v3.0  

---

## Project Structure

```
zx-app/
├── app/
│   ├── src/main/
│   │   ├── AndroidManifest.xml          — permissions, overlay service, activity-alias for icon hide
│   │   ├── cpp/
│   │   │   ├── CMakeLists.txt           — NDK build config
│   │   │   ├── zx_engine.cpp            — IL2CPP hook implementations
│   │   │   └── zx_engine.h              — hook declarations
│   │   ├── java/com/zx/zola/
│   │   │   ├── MainActivity.kt          — app entry, service launcher
│   │   │   ├── ZxEngine.kt              — JNI bridge to native hooks
│   │   │   └── ZxOverlayService.kt      — floating overlay UI, all features
│   │   └── res/
│   │       ├── drawable/
│   │       │   ├── bg_card_glow.xml     — card with purple top glow
│   │       │   ├── bg_hero_section.xml  — hero dark+purple gradient bg
│   │       │   ├── bg_wolf_ring.xml     — oval glow ring for wolf logo
│   │       │   └── ic_logo_wolf.webp    — wolf logo (460KB, main brand asset)
│   │       ├── layout/
│   │       │   └── activity_main.xml    — wolf-aesthetic hero UI
│   │       └── values/
│   │           ├── colors.xml           — ZX purple #7C4DFF, risk colors
│   │           └── strings.xml
│   └── build.gradle                     — compileSdk 34, minSdk 26, NDK arm64-v8a
└── build.gradle
```

---

## Features

### AIM Tab
| Feature | Risk | Notes |
|---|---|---|
| Auto Headshot | RISK | High headshot ratio = detectable |
| Silent Aim | DANGER | High detection by anti-cheat |
| No Recoil | SAFE | Spread modifier only |
| Rapid Fire | SAFE | Fire-rate modifier |
| Bullet Speed | SAFE | Projectile speed boost |

### MOVE Tab
| Feature | Risk | Notes |
|---|---|---|
| Speed Hack | DANGER | Movement speed = highly detectable |
| Jump Boost | RISK | Physics modifier |
| Vehicle Speed | RISK | Physics modifier = detectable |
| No Knockback | SAFE | Impulse multiplier |
| Auto Loot | SAFE | Range modifier |

### VISUAL Tab
| Feature | Risk | Notes |
|---|---|---|
| ESP | SAFE | Render-only |
| Wide FOV | SAFE | Camera FOV slider (60–150°) |
| No Grass | SAFE | Vegetation render toggle |
| **Hide Icon** | SAFE | Disables launcher icon via PackageManager alias |
| **Hide Screen** | SAFE | Enables FLAG_SECURE on overlay (blocks screenshots/recording) |

---

## Key Architecture

### Overlay System
- `WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY`
- `FLAG_SECURE` dynamic toggle via `wm.updateViewLayout()`
- Draggable FAB + expandable panel on `HandlerThread`

### Icon Hide
- `activity-alias` in AndroidManifest (`MainLauncher`)
- MainActivity has no LAUNCHER intent-filter — only the alias does
- `PackageManager.setComponentEnabledSetting(ComponentName, DISABLED/ENABLED, DONT_KILL_APP)`

### ZxEngine Commands
```kotlin
object Cmd {
    const val AUTO_HEADSHOT = 1
    const val SILENT_AIM    = 2
    const val NO_RECOIL     = 3
    const val RAPID_FIRE    = 4
    const val BULLET_SPEED  = 5
    const val SPEED_HACK    = 6
    const val JUMP_BOOST    = 7
    const val VEHICLE_SPEED = 8
    const val NO_KNOCKBACK  = 9
    const val AUTO_LOOT     = 10
    const val ESP           = 11
    const val WIDE_POV      = 12
    const val NO_GRASS      = 13
}
// Local-only (no ZxEngine dispatch):
// CMD_ICON_HIDE   = -1
// CMD_SCREEN_HIDE = -2
```

### Local-Only Features
Features with `isLocalOnly = true` bypass `ZxEngine.toggle()` and route to `handleLocalFeature(cmd, on)` in `ZxOverlayService`. These work without the game running.

---

## Build Instructions

Requires:
- Android Studio Hedgehog+
- NDK r25c (arm64-v8a)
- compileSdk 34, minSdk 26 (Android 8.0+)

```bash
cd zx-app
./gradlew assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk
```

---

## Design System

| Token | Value |
|---|---|
| Background | `#04040E` |
| Card | `#0D0D1C` |
| Accent Purple | `#7C4DFF` |
| Risk Yellow | `#FFD600` |
| Danger Red | `#FF1744` |
| Safe Green | `#00E676` |
| Border | `#2A2A48` |

Wolf logo: `ic_logo_wolf.webp` — dark wolf, purple lightning, ZX lettering.

---

## Git Branch

Branch: `claude/gifted-pasteur-1jwfad`  
Repo: `ayoubmodzx/ZX-ZOLA`
