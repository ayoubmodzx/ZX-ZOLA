cmake_minimum_required(VERSION 3.22.1)
project(gfx_pipe)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Dobby inline hook engine (PAYLOAD only) ──────────────────────────────────
include(FetchContent)
FetchContent_Declare(
    Dobby
    GIT_REPOSITORY https://github.com/jmpews/Dobby.git
    GIT_TAG        687ff82
    GIT_SHALLOW    FALSE
    GIT_PROGRESS   FALSE
)
set(DOBBY_DEBUG                            OFF CACHE BOOL "" FORCE)
set(Plugin.SymbolResolver                  OFF CACHE BOOL "" FORCE)
set(Plugin.Darwin.HideLibrary              OFF CACHE BOOL "" FORCE)
set(Plugin.Android.BionicLinkerRestriction OFF CACHE BOOL "" FORCE)
set(DOBBY_GENERATE_SHARED                  OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(Dobby)

foreach(_t dobby_static dobby c++_static c++abi c++)
    if(TARGET ${_t})
        set_property(TARGET ${_t} PROPERTY INTERFACE_LINK_LIBRARIES "")
    endif()
endforeach()

# Patch macOS-only @PAGE/@PAGEOFF ARM64 ASM relocations → ELF :lo12: syntax.
execute_process(
    COMMAND find "${dobby_SOURCE_DIR}" "(" -name "*.asm" -o -name "*.S" ")"
    OUTPUT_VARIABLE _dobby_asm_files
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(_dobby_asm_files)
    string(REPLACE "\n" ";" _dobby_asm_files "${_dobby_asm_files}")
    foreach(_f IN LISTS _dobby_asm_files)
        execute_process(COMMAND sed -i
            "s/\\(cdecl([^)]*))\\)@PAGEOFF/:lo12:\\1/g;s/\\([A-Za-z_][A-Za-z0-9_]*\\)@PAGEOFF/:lo12:\\1/g"
            "${_f}")
        execute_process(COMMAND sed -i
            "s/\\(cdecl([^)]*))\\)@PAGE/\\1/g;s/\\([A-Za-z_][A-Za-z0-9_]*\\)@PAGE/\\1/g"
            "${_f}")
    endforeach()
endif()

# ── Global flags ─────────────────────────────────────────────────────────────
set(CMAKE_CXX_FLAGS_RELEASE   "-Oz -ffunction-sections -fdata-sections -flto=thin")
set(CMAKE_SHARED_LINKER_FLAGS "-Wl,--gc-sections -Wl,--as-needed -Wl,--strip-all -Wl,-z,relro,-z,now -flto=thin")

# ── compiler-rt builtins (shared by both targets) ───────────────────────────
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
    message(FATAL_ERROR "Cannot find libclang_rt.builtins-aarch64-android.a")
endif()
get_filename_component(_compiler_rt_dir "${_compiler_rt_path}" DIRECTORY)

if(TARGET dobby_static)
    set(_dobby_link_target dobby_static)
else()
    set(_dobby_link_target dobby)
endif()

# ═══════════════════════════════════════════════════════════════════════════════
# TARGET 1: ENTRY STUB  (loaded by ZygiskNext — must stay < 250 KB)
#   No Dobby, no heavy deps — just the Zygisk API shim that dlopen's payload.so
# ═══════════════════════════════════════════════════════════════════════════════
add_library(zx_entry SHARED
    zygisk/entry.cpp
)

set_target_properties(zx_entry PROPERTIES
    PREFIX ""
    SUFFIX ".so"
    OUTPUT_NAME "arm64-v8a"
)

target_include_directories(zx_entry PRIVATE include)

target_compile_options(zx_entry PRIVATE
    -fvisibility=hidden
    -fvisibility-inlines-hidden
)

target_link_libraries(zx_entry PRIVATE log dl)

target_link_options(zx_entry PRIVATE
    -Wl,--push-state,-Bstatic
    -L${_compiler_rt_dir}
    -lclang_rt.builtins-aarch64-android
    -lc++_static
    -lc++abi
    -Wl,--pop-state
    -Wl,--exclude-libs,libc++_static.a:libc++abi.a:libclang_rt.builtins-aarch64-android.a
)

# ═══════════════════════════════════════════════════════════════════════════════
# TARGET 2: PAYLOAD  (dlopen'd at runtime — no size limit)
#   Full bypass engine + Dobby + all hooks
# ═══════════════════════════════════════════════════════════════════════════════
add_library(zx_payload SHARED
    zygisk/main.cpp
    zygisk/il2cpp_api.cpp
    zygisk/hook_engine.cpp
    zygisk/async_worker.cpp
    zygisk/feature_engine.cpp
    zygisk/anosdk_bypass.cpp
    zygisk/memory_guard.cpp
)

set_target_properties(zx_payload PROPERTIES
    PREFIX ""
    SUFFIX ".so"
    OUTPUT_NAME "payload"
)

target_include_directories(zx_payload PRIVATE include)

target_compile_options(zx_payload PRIVATE
    -fvisibility=hidden
    -fvisibility-inlines-hidden
)

target_link_libraries(zx_payload PRIVATE
    log
    dl
    ${_dobby_link_target}
)

target_link_options(zx_payload PRIVATE
    -Wl,--push-state,-Bstatic
    -L${_compiler_rt_dir}
    -lclang_rt.builtins-aarch64-android
    -lc++_static
    -lc++abi
    -Wl,--pop-state
    -Wl,--exclude-libs,libc++_static.a:libc++abi.a:libclang_rt.builtins-aarch64-android.a
)
