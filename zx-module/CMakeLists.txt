cmake_minimum_required(VERSION 3.22.1)
project(zx_zola)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Dobby inline hook engine ──────────────────────────────────────────────────
include(FetchContent)
FetchContent_Declare(
    Dobby
    GIT_REPOSITORY https://github.com/jmpews/Dobby.git
    GIT_TAG        main
    GIT_SHALLOW    TRUE
    GIT_PROGRESS   FALSE
)
set(DOBBY_DEBUG                          OFF CACHE BOOL "" FORCE)
set(Plugin.SymbolResolver                ON  CACHE BOOL "" FORCE)
set(Plugin.Darwin.HideLibrary            OFF CACHE BOOL "" FORCE)
set(Plugin.Android.BionicLinkerRestriction OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(Dobby)

# ── Global flags — no LTO or visibility here; set per-target below ────────────
set(CMAKE_CXX_FLAGS_RELEASE   "-O2 -ffunction-sections -fdata-sections")
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

# Per-target: hide everything by default; zygisk_module_entry has explicit default attr
target_compile_options(zx_zola PRIVATE
    -fvisibility=hidden
    -fvisibility-inlines-hidden
)

target_link_libraries(zx_zola
    android
    log
    dl
    dobby
)
