cmake_minimum_required(VERSION 3.16)
project(Fragment C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# The injected shared object. NOTE: the CMake TARGET name must differ from the
# loader target below, so the library target is "fragment_lib" and OUTPUT_NAME
# pins the shipped file name to libfragment.so. (A single target named
# "fragment" for both the library and the executable would collide.)
add_library(fragment_lib MODULE main.c curl.h util.h log.h config.h hook.h)
set_target_properties(fragment_lib PROPERTIES OUTPUT_NAME fragment PREFIX "lib")
target_link_libraries(fragment_lib PRIVATE dl pthread)

# Hide everything except the interposed symbols (curl_easy_setopt, curl_url_set,
# dlopen) and the rtld-audit entry points, which main.c marks default-visible.
target_compile_options(fragment_lib PRIVATE -fvisibility=hidden -fPIC)
# Pin the module: never let a stray dlclose unmap us while our interposers /
# audit hooks are live (the analogue of the Windows build pinning its DLL).
target_link_options(fragment_lib PRIVATE -Wl,-z,nodelete)

# End-user loader/injector, shipped alongside the library in releases.
add_executable(fragment_cli tools/fragment.c)
set_target_properties(fragment_cli PROPERTIES OUTPUT_NAME fragment)
target_link_libraries(fragment_cli PRIVATE dl)

# On aarch64 the inline-hook relay reaches the detour with an indirect branch,
# so build with branch protection: the detour entry then carries a BTI landing
# pad and the jump is legal under a BTI-enforcing kernel.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    target_compile_options(fragment_lib PRIVATE -mbranch-protection=standard)
endif()

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")

# The release workflow passes -DFRAGMENT_VERSION=<git tag>; otherwise the
# in-development default in common/version.h is used.
if(DEFINED FRAGMENT_VERSION)
    add_compile_definitions(FRAGMENT_VERSION="${FRAGMENT_VERSION}")
endif()
