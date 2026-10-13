cmake_minimum_required(VERSION 3.22.1)
project(zx_zola)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Aggressive optimization — do NOT pass -fvisibility=hidden globally; it would
# hide zygisk_module_entry even with the per-symbol default attribute when LTO
# merges translation units. Each internal symbol is hidden via per-TU attributes.
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -flto -ffunction-sections -fdata-sections")
set(CMAKE_SHARED_LINKER_FLAGS "-Wl,--gc-sections -Wl,--strip-all -Wl,-z,relro,-z,now")

add_library(zx_zola SHARED
    zygisk/main.cpp
    zygisk/il2cpp_api.cpp
    zygisk/hook_engine.cpp
    zygisk/async_worker.cpp
    zygisk/feature_engine.cpp
    zygisk/anosdk_bypass.cpp
    zygisk/memory_guard.cpp
)

target_include_directories(zx_zola PRIVATE include)

# Hide all symbols by default at the target level; zygisk_module_entry is
# explicitly marked visibility("default") in the REGISTER_ZYGISK_MODULE macro.
target_compile_options(zx_zola PRIVATE -fvisibility=hidden -fvisibility-inlines-hidden)

target_link_libraries(zx_zola
    android
    log
    dl
)
