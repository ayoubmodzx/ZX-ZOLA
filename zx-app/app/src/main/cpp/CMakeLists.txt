cmake_minimum_required(VERSION 3.22.1)
project(zx_injector)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -flto -fvisibility=hidden -ffunction-sections -fdata-sections -fPIE")
set(CMAKE_EXE_LINKER_FLAGS "-pie -Wl,--gc-sections -Wl,--strip-all")

# ── Standalone injector binary (not a .so — runs as executable via root) ──────
add_executable(zx_injector
    injector.cpp
    proc_mem.cpp
    il2cpp_scanner.cpp
)
target_link_libraries(zx_injector log dl)

# ── Payload .so — loaded into FF address space via dlopen ─────────────────────
add_library(zx_payload SHARED
    payload.cpp
    features.cpp
    anosdk_bypass.cpp
)
target_include_directories(zx_payload PRIVATE .)
target_link_libraries(zx_payload log dl)
