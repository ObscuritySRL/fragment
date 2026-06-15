@echo off
REM Build the Fragment DLL with whatever Visual Studio (2017+) is installed.
REM Toolchain is auto-detected via vswhere -- no hardcoded machine paths.
REM Usage: build.bat [Debug|Release]
setlocal
set CFG=%1
if "%CFG%"=="" set CFG=Release

call "%~dp0find_vcvars.bat" || (echo ERROR: Visual Studio 2017+ with the C++ x64 toolset was not found.& exit /b 1)
call "%VCVARS_BAT%" || exit /b 1

REM Prefer CMake/Ninja on PATH; otherwise use the copies bundled with this VS.
set "CMAKE=cmake"
where cmake >nul 2>&1 || set "CMAKE=%VSINSTALL%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
set "NINJA="
where ninja >nul 2>&1 && set "NINJA=ninja"
if not defined NINJA if exist "%VSINSTALL%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe" set "NINJA=%VSINSTALL%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"

set "BUILDDIR=%~dp0build"
if defined NINJA goto :ninja
"%CMAKE%" -S "%~dp0." -B "%BUILDDIR%" -A x64 || exit /b 1
goto :build
:ninja
"%CMAKE%" -S "%~dp0." -B "%BUILDDIR%" -G Ninja -DCMAKE_MAKE_PROGRAM="%NINJA%" -DCMAKE_BUILD_TYPE=%CFG% || exit /b 1
:build
"%CMAKE%" --build "%BUILDDIR%" --config %CFG% || exit /b 1

echo.
echo === Build OK -- artifacts in %BUILDDIR% (Fragment.dll, fragment.exe) ===
endlocal
