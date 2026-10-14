cmake_minimum_required(VERSION 3.22.1)
project(zx_zola)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Dobby inline hook engine ──────────────────────────────────────────────────
include(FetchContent)
FetchContent_Declare(
    Dobby
    GIT_REPOSITORY https://github.com/jmpews/Dobby.git
    GIT_TAG        master
    GIT_SHALLOW    TRUE
    GIT_PROGRESS   FALSE
)
set(DOBBY_DEBUG                            OFF CACHE BOOL "" FORCE)
set(Plugin.SymbolResolver                  OFF CACHE BOOL "" FORCE)
set(Plugin.Darwin.HideLibrary              OFF CACHE BOOL "" FORCE)
set(Plugin.Android.BionicLinkerRestriction OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(Dobby)

# dobby_static carries libc++_shared in its INTERFACE_LINK_LIBRARIES on Android.
# Clearing it prevents libc++_shared.so from appearing in our NEEDED list.
# C++ symbols are still resolved from libc++_static (absorbed via ANDROID_STL=c++_static).
foreach(_t dobby_static dobby)
    if(TARGET ${_t})
        set_property(TARGET ${_t} PROPERTY INTERFACE_LINK_LIBRARIES "")
    endif()
endforeach()

# Patch macOS-only @PAGE/@PAGEOFF ARM64 ASM relocations → ELF :lo12: syntax.
# Dobby master ships Mach-O style relocations in the closure bridge ASM; the
# Android NDK clang (Linux host, ELF target) rejects them at assemble time.
set(_dobby_asm
    "${dobby_SOURCE_DIR}/source/TrampolineBridge/ClosureTrampolineBridge/arm64/closure_bridge_arm64.asm")
if(EXISTS "${_dobby_asm}")
    file(READ "${_dobby_asm}" _asm)
    string(REPLACE "common_closure_bridge_handler@PAGEOFF"
                   ":lo12:common_closure_bridge_handler" _asm "${_asm}")
    string(REPLACE "common_closure_bridge_handler@PAGE"
                   "common_closure_bridge_handler" _asm "${_asm}")
    file(WRITE "${_dobby_asm}" "${_asm}")
endif()

# ── Global flags ──────────────────────────────────────────────────────────────
set(CMAKE_CXX_FLAGS_RELEASE   "-O2 -ffunction-sections -fdata-sections")
set(CMAKE_SHARED_LINKER_FLAGS "-Wl,--gc-sections -Wl,--as-needed -Wl,--strip-all -Wl,-z,relro,-z,now")

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
    log
    dl
    dobby_static
    c++_static          # absorb static C++ runtime; prevents libc++_shared.so in NEEDED
)
