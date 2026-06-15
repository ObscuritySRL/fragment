cmake_minimum_required(VERSION 3.24)
project(Fragment C)

set(CMAKE_C_STANDARD 17)

# The injected DLL. NOTE: do not add another target whose name differs from
# "Fragment" only by case (e.g. "fragment") -- on case-insensitive Windows the
# Visual Studio generator collides their project files and builds only one.
add_library(Fragment MODULE main.c curl.h util.h log.h config.h hook.h)

# End-user loader/injector, shipped alongside the DLL in releases.
# The CMake TARGET name must differ from the DLL target "Fragment" by more than
# case: on case-insensitive Windows the Visual Studio generator would otherwise
# emit colliding project files (both -> Fragment.vcxproj) and silently build
# only one target, so `cmake -A x64` (CI + release) would produce no Fragment.dll.
# OUTPUT_NAME keeps the shipped binary named fragment.exe. (Ninja keys off the
# output filenames, which already differ by extension, so it was unaffected.)
add_executable(fragment_cli tools/fragment.c)
set_target_properties(fragment_cli PROPERTIES OUTPUT_NAME fragment)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")

if(MSVC)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()