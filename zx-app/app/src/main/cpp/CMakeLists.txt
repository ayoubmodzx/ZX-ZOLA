cmake_minimum_required(VERSION 3.22.1)
project(zx_ayoub)
enable_language(ASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS_RELEASE "-O3 -flto -fvisibility=hidden -ffunction-sections -fdata-sections -fstack-protector-strong -DZX_RELEASE")
set(CMAKE_SHARED_LINKER_FLAGS "-Wl,--gc-sections -Wl,--strip-debug")
set(CMAKE_EXE_LINKER_FLAGS    "-pie -Wl,--gc-sections -Wl,--strip-all")

# ── Payload .so — dlopen'd into FF address space ────────────────────────────────────────────
add_library(zx_payload SHARED
    payload.cpp
    features.cpp
    esp_renderer.cpp
    anosdk_bypass.cpp
    anti_detect.cpp
    stealth_ext.cpp
    stealth_ext2.cpp
    stealth_ext3.cpp
    stealth_ext4.cpp
    stealth_ext5.cpp
    stealth_ext6.cpp
    stealth_ext7.cpp
    stealth_ext8.cpp
    il2cpp_scanner.cpp
    dobby_impl.cpp
)
target_include_directories(zx_payload PRIVATE .)
target_link_libraries(zx_payload log dl)
# libc++_shared.so is NOT in FF's classloader-namespace so dlopen fails.
# Statically bundle the C++ runtime into the .so to make it self-contained.
if(ANDROID_ABI STREQUAL "arm64-v8a")
    # no_pac.s is AArch64-ONLY. Including it on armeabi-v7a causes:
    #   ld.lld: error: .note.gnu.property: program property is too short
    # because the ARM32 linker does not understand AArch64 GNU_PROPERTY types.
    # PAC does not exist on 32-bit ARM — the file is irrelevant there anyway.
    target_sources(zx_payload PRIVATE no_pac.s)
    # -mbranch-protection=none: prevents PACIA/AUTIA in compiled code.
    # Together with no_pac.s (AND=0), ensures plain BR X16 PLT stubs throughout.
    target_compile_options(zx_payload PRIVATE -mbranch-protection=none)
endif()
target_link_options(zx_payload PRIVATE
    # -Bsymbolic: internal references to default-visibility symbols (like
    # __g_sdktbl1) are resolved directly instead of through GOT/PLT.
    # This eliminates R_AARCH64_GLOB_DAT relocations that FF's bionic linker
    # would otherwise try — and fail — to resolve from its namespace.
    -Wl,-Bsymbolic
    # -z,now (BIND_NOW): force bionic to resolve ALL symbols at dlopen time,
    # not lazily on first call. Without this, GOT entries hold PLT-resolver
    # stub addresses at dlopen BRK time, so pac_strip sees 0 PAC-tagged slots.
    # First call then triggers lazy resolution which writes back PAC-signed
    # addresses, causing BR X16 crashes. With BIND_NOW, GOT is fully resolved
    # before our BRK fires, and pac_strip cleans every PAC-tagged entry.
    -Wl,-z,now
    -nostdlib++
    -l:libc++_static.a
    -l:libc++abi.a
)

# ── Standalone root injector binary ────────────────────────────────────────────
add_executable(zx_injector
    injector.cpp
    proc_mem.cpp
)
target_include_directories(zx_injector PRIVATE .)
target_link_libraries(zx_injector log dl)
# The injector runs via `su -c` outside the app's LD_LIBRARY_PATH where
# libc++_shared.so is not present.  ANDROID_STL=c++_static (build.gradle) is
# set but NDK r27 doesn't always propagate it to add_executable targets.
# Force the static C++ runtime explicitly so the binary is fully self-contained.
target_link_options(zx_injector PRIVATE
    -nostdlib++
    -l:libc++_static.a
    -l:libc++abi.a
)
if(ANDROID_ABI STREQUAL "arm64-v8a")
    target_compile_options(zx_injector PRIVATE -mbranch-protection=none)
endif()

# Package injector as libzx_injector.so in jniLibs so the system installs it
# into nativeLibraryDir at install time — that directory is exec-allowed, unlike
# /data/local/tmp or filesDir which are noexec on most Android 10+ ROMs.
add_custom_command(TARGET zx_injector POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
        "${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}"
    COMMAND ${CMAKE_COMMAND} -E copy
        "$<TARGET_FILE:zx_injector>"
        "${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libzx_injector.so"
    COMMENT "Packaging zx_injector -> jniLibs/${ANDROID_ABI}/libzx_injector.so"
)
