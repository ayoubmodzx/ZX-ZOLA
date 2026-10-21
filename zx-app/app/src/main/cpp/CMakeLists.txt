cmake_minimum_required(VERSION 3.22.1)
project(zx_ayoub)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_EXE_LINKER_FLAGS "-pie -Wl,--gc-sections -Wl,--strip-all")

# ── Root client binary — connects to Zygisk module via abstract Unix socket ──
add_executable(zx_client
    zx_client.cpp
)
target_include_directories(zx_client PRIVATE .)
target_link_libraries(zx_client log)
target_link_options(zx_client PRIVATE
    -nostdlib++
    -l:libc++_static.a
    -l:libc++abi.a
)
if(ANDROID_ABI STREQUAL "arm64-v8a")
    target_compile_options(zx_client PRIVATE -mbranch-protection=none)
endif()

# Package as libzx_client.so in jniLibs so the APK installs it to
# nativeLibraryDir (exec-allowed on Android 10+).  Java runs it via:
#   su -c <nativeLibraryDir>/libzx_client.so --loop
add_custom_command(TARGET zx_client POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
        "${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}"
    COMMAND ${CMAKE_COMMAND} -E copy
        "$<TARGET_FILE:zx_client>"
        "${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libzx_client.so"
    COMMENT "Packaging zx_client -> jniLibs/${ANDROID_ABI}/libzx_client.so"
)
