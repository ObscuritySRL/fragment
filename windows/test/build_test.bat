@echo off
REM Compile the test host/injector/unit-test binaries with MSVC (x64).
REM Toolchain auto-detected via vswhere -- no hardcoded machine paths.
setlocal
call "%~dp0..\find_vcvars.bat" || (echo ERROR: Visual Studio 2017+ with the C++ x64 toolset was not found.& exit /b 1)
call "%VCVARS_BAT%" || exit /b 1

REM The test harness uses the classic CRT string functions deliberately; silence
REM the deprecation noise (the CL env var is prepended to every cl invocation).
set "CL=/D_CRT_SECURE_NO_WARNINGS"

set OUT=%~dp0..\build
if not exist "%OUT%" mkdir "%OUT%"

cl /nologo /O2 /MD /W3 "%~dp0host.c"        /Fe"%OUT%\host.exe"        /Fo"%OUT%\host.obj"        || exit /b 1
cl /nologo /O2 /MD /W3 "%~dp0host_urlapi.c" /Fe"%OUT%\host_urlapi.exe" /Fo"%OUT%\host_urlapi.obj" || exit /b 1
cl /nologo /O2 /MD /W3 "%~dp0inject.c"      /Fe"%OUT%\inject.exe"      /Fo"%OUT%\inject.obj"      || exit /b 1
cl /nologo /O2 /MD /W3 "%~dp0hooktest.c"    /Fe"%OUT%\hooktest.exe"    /Fo"%OUT%\hooktest.obj"    || exit /b 1
cl /nologo /O2 /MD /W3 "%~dp0host_stress.c" /Fe"%OUT%\host_stress.exe" /Fo"%OUT%\host_stress.obj" || exit /b 1
cl /nologo /O2 /MD /W3 "%~dp0host_bench.c"  /Fe"%OUT%\host_bench.exe"  /Fo"%OUT%\host_bench.obj"  || exit /b 1

REM WinHTTP backend exerciser (dynamically resolves winhttp -- no winhttp.lib).
cl /nologo /O2 /MD /W3 "%~dp0host_winhttp.c" /Fe"%OUT%\host_winhttp.exe" /Fo"%OUT%\host_winhttp.obj" || exit /b 1

REM Self-contained integration test: a mock libcurl DLL + a host that asserts
REM the setopt rewrite/idempotency/option-drop behaviour with no real libcurl,
REM so it runs anywhere (incl. CI) without the third-party corpus.
cl /nologo /O2 /MD /W3 /LD "%~dp0mockcurl.c" /Fe"%OUT%\mockcurl.dll" /Fo"%OUT%\mockcurl.obj" || exit /b 1
cl /nologo /O2 /MD /W3     "%~dp0host_mock.c" /Fe"%OUT%\host_mock.exe" /Fo"%OUT%\host_mock.obj" || exit /b 1

REM Transitive-load fixture: an import library for the curl-for-win DLL, a
REM plugin that statically imports it, and a host that loads the plugin. Built
REM only when the (git-ignored) corpus DLL is present.
set CFWDLL=%~dp0curl\libcurl-cfw820.dll
if not exist "%CFWDLL%" goto :nofixture
> "%OUT%\libcurl-cfw820.def" echo LIBRARY libcurl-cfw820.dll
>> "%OUT%\libcurl-cfw820.def" echo EXPORTS
>> "%OUT%\libcurl-cfw820.def" echo curl_global_init
>> "%OUT%\libcurl-cfw820.def" echo curl_easy_init
>> "%OUT%\libcurl-cfw820.def" echo curl_easy_setopt
>> "%OUT%\libcurl-cfw820.def" echo curl_easy_perform
>> "%OUT%\libcurl-cfw820.def" echo curl_easy_cleanup
lib /nologo /def:"%OUT%\libcurl-cfw820.def" /out:"%OUT%\libcurl-cfw820.lib" /machine:x64 || exit /b 1
cl /nologo /O2 /MD /W3 /LD "%~dp0plugin.c" "%OUT%\libcurl-cfw820.lib" /Fe"%OUT%\plugin.dll" /Fo"%OUT%\plugin.obj" || exit /b 1
cl /nologo /O2 /MD /W3 "%~dp0host_plugin.c" /Fe"%OUT%\host_plugin.exe" /Fo"%OUT%\host_plugin.obj" || exit /b 1
:nofixture

echo === Test binaries built in %OUT% ===
endlocal
