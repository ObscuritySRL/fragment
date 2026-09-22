@echo off
REM Use the caller's active MSVC architecture (x64, x86 or ARM64).
setlocal
set "OUT=%~1"
if not defined OUT set "OUT=%~dp0..\build"
if not exist "%OUT%" mkdir "%OUT%"
set "CL=/D_CRT_SECURE_NO_WARNINGS"
cl /nologo /std:c17 /O2 /MD /W3 "%~dp0host_winhttp.c" /Fe"%OUT%\host_winhttp.exe" /Fo"%OUT%\host_winhttp.obj" || exit /b 1
cl /nologo /std:c17 /O2 /MD /W3 "%~dp0host_schannel.c" /Fe"%OUT%\host_schannel.exe" /Fo"%OUT%\host_schannel.obj" /link ws2_32.lib || exit /b 1
cl /nologo /std:c17 /O2 /MD /W3 "%~dp0schanneltest.c" /Fe"%OUT%\schanneltest.exe" /Fo"%OUT%\schanneltest.obj" || exit /b 1
cl /nologo /std:c17 /O2 /MD /W3 "%~dp0capturetest.c" /Fe"%OUT%\capturetest.exe" /Fo"%OUT%\capturetest.obj" || exit /b 1
cl /nologo /std:c17 /O2 /MD /W3 "%~dp0host_network.c" /Fe"%OUT%\host_network.exe" /Fo"%OUT%\host_network.obj" /link ws2_32.lib || exit /b 1
cl /nologo /std:c17 /O2 /MD /W3 "%~dp0networktest.c" /Fe"%OUT%\networktest.exe" /Fo"%OUT%\networktest.obj" || exit /b 1
cl /nologo /std:c17 /O2 /MD /W3 "%~dp0host_openssl.c" /Fe"%OUT%\host_openssl.exe" /Fo"%OUT%\host_openssl.obj" /link ws2_32.lib || exit /b 1
cl /nologo /std:c17 /O2 /MD /W3 "%~dp0openssltest.c" /Fe"%OUT%\openssltest.exe" /Fo"%OUT%\openssltest.obj" || exit /b 1
cl /nologo /std:c17 /Od /MD /W3 /LD "%~dp0mockssl.c" /Fe"%OUT%\mockssl.dll" /Fo"%OUT%\mockssl.obj" || exit /b 1
cl /nologo /std:c17 /O2 /MD /W3 "%~dp0host_openssl_mock.c" /Fe"%OUT%\host_openssl_mock.exe" /Fo"%OUT%\host_openssl_mock.obj" || exit /b 1
endlocal
