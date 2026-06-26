@echo off
REM ---------------------------------------------------------------------------
REM Locate Visual Studio's vcvars64.bat via vswhere -- works with any edition
REM (BuildTools / Community / Professional / Enterprise) 2017+ that has the
REM C++ x64 toolset, with no hardcoded machine paths.
REM
REM On success: sets VSINSTALL and VCVARS_BAT, returns 0.
REM On failure: returns 1.  (No setlocal, so the vars reach the caller.)
REM ---------------------------------------------------------------------------
set "VCVARS_BAT="
set "VSINSTALL="

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" exit /b 1

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSINSTALL=%%i"
if not defined VSINSTALL exit /b 1

set "VCVARS_BAT=%VSINSTALL%\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS_BAT%" exit /b 1
exit /b 0
