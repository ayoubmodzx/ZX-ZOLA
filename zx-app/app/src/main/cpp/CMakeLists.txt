cmake_minimum_required(VERSION 3.22.1)
project(zx_ayoub)

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
    # Opt out of PAC entirely for the payload .so.
    #
    # -mbranch-protection=none prevents the compiler from emitting PACIA/AUTIA
    # instructions AND suppresses the GNU_PROPERTY_AARCH64_FEATURE_1_PAC note in
    # our object files. Without that note, lld does NOT emit BRAA pac-plt stubs,
    # and bionic does NOT apply pacia() to our GOT entries during dlopen.
    # The result is plain BR X16 PLT stubs on raw unsigned GOT addresses — no PAC
    # authentication anywhere in our library's PLT path.
    #
    # Why not use -z,pac-plt + -z,now (our previous approach):
    #   With -z,pac-plt the linker emits BRAA stubs and sets the GNU property.
    #   Bionic then calls pacia(fn_addr, &GOT[n]) for each slot. BRAA X16,X17
    #   authenticates using X17=&GOT[n] as modifier. This works when bionic's own
    #   linker runs the library. BUT our injector calls do_dlopen() inside FF's
    #   linker (a different bionic instance, different namespace). FF's linker's
    #   PAC signing path leaves early GOT entries (slots ~10 to ~250 depending on
    #   build) with an incorrect or absent signature → BRAA auth failure →
    #   PC=0xd67faa90c6ffc (corrupted by auth fail bit) → SIGSEGV. The crash
    #   shifted each build cycle as PLT layout changed but never went away.
    #
    # Without PAC property: bionic treats all JUMP_SLOT relocations as plain
    # pointer writes, BR X16 works on every device, PAC-capable or not.
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
