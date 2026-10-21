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
# cmake string(REPLACE) misses occurrences when symbol names differ; use sed
# across ALL .asm/.S files under dobby_SOURCE_DIR for reliability.
execute_process(
    COMMAND find "${dobby_SOURCE_DIR}" "(" -name "*.asm" -o -name "*.S" ")"
    OUTPUT_VARIABLE _dobby_asm_files
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(_dobby_asm_files)
    string(REPLACE "\n" ";" _dobby_asm_files "${_dobby_asm_files}")
    foreach(_f IN LISTS _dobby_asm_files)
        execute_process(COMMAND sed -i
            "s/\\([A-Za-z_][A-Za-z0-9_]*\\)@PAGEOFF/:lo12:\\1/g"
            "${_f}")
        execute_process(COMMAND sed -i
            "s/\\([A-Za-z_][A-Za-z0-9_]*\\)@PAGE/\\1/g"
            "${_f}")
        message(STATUS "Dobby @PAGE patch: ${_f}")
    endforeach()
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
# compiler-rt builtins (provides __emutls_get_address) live in the clang lib dir
# which is NOT in the NDK sysroot's default search path — find it explicitly.
execute_process(
    COMMAND ${CMAKE_CXX_COMPILER} --print-file-name=libclang_rt.builtins-aarch64-android.a
    OUTPUT_VARIABLE _compiler_rt_path
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(NOT IS_ABSOLUTE "${_compiler_rt_path}")
    file(GLOB _compiler_rt_candidates
        "${CMAKE_ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/lib/clang/*/lib/linux/libclang_rt.builtins-aarch64-android.a")
    list(GET _compiler_rt_candidates 0 _compiler_rt_path)
endif()
if(NOT _compiler_rt_path OR NOT EXISTS "${_compiler_rt_path}")
    message(FATAL_ERROR "Cannot find libclang_rt.builtins-aarch64-android.a in NDK ${CMAKE_ANDROID_NDK}")
endif()
message(STATUS "compiler-rt builtins: ${_compiler_rt_path}")
get_filename_component(_compiler_rt_dir "${_compiler_rt_path}" DIRECTORY)

target_link_options(zx_zola PRIVATE
    -Wl,--push-state,-Bstatic
    -L${_compiler_rt_dir}
    -lclang_rt.builtins-aarch64-android
    -lc++_static
    -lc++abi
    -Wl,--pop-state
    -Wl,--exclude-libs,libc++_static.a:libc++abi.a:libclang_rt.builtins-aarch64-android.a
)
