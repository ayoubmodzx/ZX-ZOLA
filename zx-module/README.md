# ZX-ZOLA Zygisk Module

## Why it's faster than ZOLAM

| ZOLAM | ZX-ZOLA |
|-------|---------|
| Hooks 7 GL functions on render thread | Zero GL hooks |
| il2cpp scan inline with frame calls | il2cpp scan on SCHED_IDLE background thread |
| Injected binary via Termux path | Clean Zygisk .so injection |
| No double-hook protection | Double-hook guard built-in |
| Hooks all apps | Only activates on FF package |

## Build

```bash
# NDK r25c or newer
cmake -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
      -DANDROID_ABI=arm64-v8a \
      -DANDROID_PLATFORM=android-31 \
      -DCMAKE_BUILD_TYPE=Release \
      -B build/arm64

cmake --build build/arm64 --config Release
```

## Project Structure

```
zx-module/
├── include/
│   ├── zygisk.hpp        # Zygisk API v4
│   ├── dobby.h           # Dobby hook API
│   └── il2cpp_types.hpp  # Il2Cpp type definitions
├── zygisk/
│   ├── main.cpp          # Module entry — only activates on FF
│   ├── il2cpp_api.cpp    # Symbol resolver, cached pointers
│   ├── hook_engine.cpp   # Dobby wrapper, double-hook guard
│   ├── async_worker.cpp  # SCHED_IDLE background thread
│   └── feature_engine.cpp # All features live here
├── scripts/
│   ├── customize.sh      # Magisk/KSU installer
│   └── service.sh        # Boot script
├── module.prop
└── CMakeLists.txt
```

## Adding Features

Edit `feature_engine.cpp` — add a method, call it from `init()`. Done.
