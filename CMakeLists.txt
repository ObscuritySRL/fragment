cmake_minimum_required(VERSION 3.16)
project(Fragment C)

# Single entry point for the whole project: `cmake -S . -B build` builds the
# host platform's Fragment (Fragment.dll + fragment.exe on Windows,
# libfragment.so + fragment on Linux/macOS). The shared core lives in common/:
# per-arch engine backends in common/arch/<arch>/, pulled in by each OS glue
# through a relative include. The platform-specific code, build, and tests live
# under windows/, linux/, macos/ -- each its own self-contained CMake project
# dispatched here by host OS.
if(WIN32)
    add_subdirectory(windows)
elseif(APPLE)
    add_subdirectory(macos)
else()
    add_subdirectory(linux)
endif()
