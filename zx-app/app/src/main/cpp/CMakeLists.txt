cmake_minimum_required(VERSION 3.22.1)
project(zx_ayoub)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS_RELEASE "-O3 -flto -fvisibility=hidden -ffunction-sections -fdata-sections -fstack-protector-strong -DZX_RELEASE")
set(CMAKE_SHARED_LINKER_FLAGS "-Wl,--gc-sections -Wl,--strip-all")
set(CMAKE_EXE_LINKER_FLAGS    "-pie -Wl,--gc-sections -Wl,--strip-all")

# ── Payload .so — dlopen'd into FF address space ──────────────────────────────
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
    il2cpp_scanner.cpp
    dobby_impl.cpp
)
target_include_directories(zx_payload PRIVATE .)
target_link_libraries(zx_payload log dl GLESv3 EGL)
# Payload is loaded from /data/local/tmp into classloader-namespace which does
# not resolve libc++_shared.so for external libraries.  Bundle the C++ runtime
# statically so the .so has zero libc++ DT_NEEDED entries.
target_link_options(zx_payload PRIVATE
    # Force __g_sdktbl1 into .dynsym even under -fvisibility=hidden + -flto.
    # The attribute on the declaration is correct but LTO can still drop the
    # export; --export-dynamic-symbol guarantees it survives the link pass.
    -Wl,--export-dynamic-symbol=__g_sdktbl1
    -nostdlib++
    -l:libc++_static.a
    -l:libc++abi.a
)

# ── Standalone root injector binary ──────────────────────────────────────────
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
