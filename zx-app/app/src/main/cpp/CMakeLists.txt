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
    no_pac.s
)
target_include_directories(zx_payload PRIVATE .)
target_link_libraries(zx_payload log dl)
# libc++_shared.so is NOT in FF's classloader-namespace so dlopen fails.
# Statically bundle the C++ runtime into the .so to make it self-contained.
if(ANDROID_ABI STREQUAL "arm64-v8a")
    # Opt out of PAC entirely for the payload .so — two-part fix.
    #
    # Part 1 — no_pac.s (see that file for full explanation):
    #   Explicitly emits GNU_PROPERTY_AARCH64_FEATURE_1_AND = 0 so lld generates
    #   plain BR X16 PLT stubs instead of BRAA stubs.
    #   WHY this is needed: -mbranch-protection=none makes the compiler emit NO
    #   property note (not PAC=0). lld treats an absent note as "all features" in
    #   the AND. libc++_static.a has PAC=1 → AND keeps PAC=1 → BRAA stubs anyway
    #   → PAC auth fail in FF's linker namespace → PC=0xd67faa90c6ffc → SIGSEGV.
    #   no_pac.s contributes AND=0 → clears PAC from the AND → plain BR X16.
    #
    # Part 2 — -mbranch-protection=none (this line):
    #   Prevents PACIA/AUTIA in our compiled code. Belt-and-suspenders in case
    #   the GNU property were re-enabled by a toolchain change.
    #
    # Result: bionic treats all JUMP_SLOT relocations as plain pointer writes,
    # BR X16 works on every device (PAC-capable or not), FF's linker cannot
    # mis-sign our GOT entries.
    target_compile_options(zx_payload PRIVATE -mbranch-protection=none)
endif()
target_link_options(zx_payload PRIVATE
    # -Bsymbolic: internal references to default-visibility symbols (like
    # __g_sdktbl1) are resolved directly instead of through GOT/PLT.
    # This eliminates R_AARCH64_GLOB_DAT relocations that FF's bionic linker
    # would otherwise try — and fail — to resolve from its namespace.
    -Wl,-Bsymbolic
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
