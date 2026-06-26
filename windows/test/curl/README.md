# libcurl test corpus (not committed)

These real-world libcurl builds are used by `test/run.py` to prove the
DLL hooks every reasonably-possible curl version/compiler. They are
third-party binaries and are intentionally git-ignored.

Reproduce locally:

| File                         | libcurl | Compiler        | Source |
|------------------------------|---------|-----------------|--------|
| `libcurl-audacity.dll`       | 7.82    | MSVC            | copy of `libcurl.dll` from any Audacity install (e.g. `D:\Audacity\libcurl.dll`) |
| `libcurl-git786.dll`         | 7.86    | MinGW-GCC       | copy of `libcurl-4.dll` from Git for Windows (`<git>\mingw64\bin\libcurl-4.dll`) |
| `libcurl-cfw820.dll`         | 8.20    | LLVM/clang      | `bin/libcurl-x64.dll` from https://curl.se/windows (win64-mingw zip) |
| `curl-cfw820.exe`            | 8.20    | LLVM (static)   | `bin/curl.exe` from the same curl-for-win zip |
| `curl-vs2010-730-static.exe` | 7.30    | MSVC VS2010     | `tools/native/v100/x64/Release/static/curl.exe` from NuGet `curl` 7.30.0.2 |
| `curl-vs2012-730-static.exe` | 7.30    | MSVC VS2012     | `tools/native/v110/x64/Release/static/curl.exe` from NuGet `curl` 7.30.0.2 |

`run.py` loads every target from this directory. These third-party binaries
are intentionally **not committed** (see the title), so a fresh checkout has
none of them: stage the files above per the table and the corresponding rows
run; leave them out and those rows simply report `SKIP`. The matrix is
corpus-only and deterministic by default -- it never silently substitutes a
different libcurl that happens to be installed on the machine. Set
`FRAGMENT_TEST_ALLOW_EXTERNAL=1` to opt into a convenience fallback that uses
a local Git-for-Windows / Audacity install when its corpus copy is missing
(the run prints the resolved path and flags it as an external fallback).

NuGet packages are plain zips:
`https://api.nuget.org/v3-flatcontainer/curl/7.30.0.2/curl.7.30.0.2.nupkg`

The matrix spans libcurl 7.30 → 8.20 (2013 → 2025) and five compilers
(VS2010, VS2012, modern MSVC, MinGW-GCC, LLVM/clang), covering both the
export-resolution path (DLLs) and the static signature-scan path (EXEs).
