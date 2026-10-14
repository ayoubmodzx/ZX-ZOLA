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

# The NDK's c++_static imported target carries libc++_shared in INTERFACE_LINK_LIBRARIES.
# Dobby's targets do the same. ZygiskNext's linker namespace cannot reach libc++_shared.so,
# so we must absorb ALL C++ runtime symbols statically — no shared C++ dep at runtime.
# Clearing every interface dep here stops libc++_shared from appearing in NEEDED.
foreach(_t dobby_static dobby c++_static c++abi c++)
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

target_link_libraries(zx_zola PRIVATE
    log
    dl
    dobby_static
)

# Static C++ runtime absorption — runs AFTER objects so lld sees references first.
# Order matters: compiler-rt builtins (provides __emutls_get_address, __muldc3, etc.)
# must precede c++_static/c++abi so their internal refs are resolved within the bracket.
# target_link_options appends AFTER object files; add_link_options prepends BEFORE
# objects (lld would see no references yet and pull nothing in from the archive).
target_link_options(zx_zola PRIVATE
    -Wl,--push-state,-Bstatic
    -lclang_rt.builtins-aarch64-android
    -lc++_static
    -lc++abi
    -Wl,--pop-state
    -Wl,--exclude-libs,libc++_static.a:libc++abi.a:libclang_rt.builtins-aarch64-android.a
)
