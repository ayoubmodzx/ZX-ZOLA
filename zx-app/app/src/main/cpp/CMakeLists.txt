cmake_minimum_required(VERSION 3.22.1)
project(zx_zola)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS_RELEASE "-O3 -flto -fvisibility=hidden -ffunction-sections -fdata-sections")
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
    il2cpp_scanner.cpp
    dobby_impl.cpp
)
target_include_directories(zx_payload PRIVATE .)
target_link_libraries(zx_payload log dl GLESv3 EGL)

# ── Standalone root injector binary ──────────────────────────────────────────
add_executable(zx_injector
    injector.cpp
    proc_mem.cpp
)
target_include_directories(zx_injector PRIVATE .)
target_link_libraries(zx_injector log dl)

# Copy injector binary to assets so Gradle packages it into the APK
add_custom_command(TARGET zx_injector POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
        "${CMAKE_SOURCE_DIR}/../assets/arm64-v8a"
    COMMAND ${CMAKE_COMMAND} -E copy
        "$<TARGET_FILE:zx_injector>"
        "${CMAKE_SOURCE_DIR}/../assets/arm64-v8a/zx_injector"
    COMMENT "Copying zx_injector -> assets/arm64-v8a/"
)
