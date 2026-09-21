# Verification — September 21, 2026

Windows x64, MSVC 19.44.35228, Bun 1.4.1 canary.

## Locally observed results

- Pre-release rerun: 30/30 Windows curl/engine/state cases passed with the staged
  curl-for-win 8.20 DLL and executable, including four embedded-curl POST cases
  (already loaded, loaded later, bare, disabled). WinHTTP rerun: 19/19 passed;
  Bun: 7 tests / 47 assertions passed; TypeScript type checking passed.
- The earlier broader corpus run below is historical evidence, not a claim that
  all those fixtures were included in this pre-release rerun.
- WinHTTP: 19/19 integration cases passed. Real Windows WinHTTP, including POST
  payload preservation, disabled/bare controls, nonstandard origin ports, query
  strings, proxy settings, mount paths, session teardown, launch-and-inject, and
  480 concurrent requests with no unexpected destinations.
- Curl: 61/61 cases passed using Git for Windows' installed libcurl, the official
  curl-for-win 8.20.0_1 and 8.22.0_1 DLLs, and both official static executables.
  Includes engine/mock assertions, URL and CURLU APIs, every Windows loader mode,
  negative controls, option neutralization, transitive DLL imports, real launcher
  injection, and 480-request stress runs for each shared libcurl.
- Bun tests cover malformed binary files, signature structure and the observed
  Clang signature regression, strict harness outcomes, and forwarding proxy
  payload/status/redirect/compression behavior. TypeScript type checking passes.
- The existing local WSL Ubuntu installation could not boot because its VHDX
  file is missing. Linux x64/ARM64 verification runs in GitHub Actions instead.

Official corpus downloads (not committed):

- https://curl.se/windows/dl-8.20.0_1/curl-8.20.0_1-win64-mingw.zip
- https://curl.se/windows/dl-8.22.0_1/curl-8.22.0_1-win64-mingw.zip
  — SHA-256 `7f23b039f6ea4197362d4468e1a0e71428201222e1bef3b680d5ef7b2aefb714`

The older Clang setopt prefix matched an unrelated entry at file offset 0x47940
in the 8.22 executable; the real entry is at 0x90ff0. Tightening the old signature
against the 8.20 export and adding the observed 8.22 body fixed the actual traffic
test. Signature scanning now rejects duplicate matches and conflicting targets.

## Applications requested by the owner

- Epic Games Launcher: ordinary PID attachment loaded Fragment; the process
  module list confirmed the exact DLL. This proves loading, **not request
  capture**. The running application has several separate EpicWebHelper processes
  and loads CEF/WinINet, which are outside the implemented backend/process scope.
- RobloxPlayerBeta at version-4310300497aa4917: ordinary PID attachment did not
  load Fragment. The module list contained no Fragment DLL, and the updated
  launcher returned failure (exit 5). No compatibility or capture claim is made.
- The existing development service on port 9020 was preserved. Automated tests
  used their own local recording servers, not that service's traffic.

## Scope still outside the guarantee

`BRIEF.md` describes future WinINet/TLS/socket/process-tree work. This change
finishes and tests the WinHTTP PR, not that entire roadmap. Unknown/stripped
static builds remain best-effort; unsupported signatures stay unhooked.
`CURLOPT_CURLU` read-back requires URL API exports in the same Windows module;
missing exports produce a warning. Existing WinHTTP connection handles cannot
recover origin metadata on late attach. Runtime hook installation into a busy
process retains the documented non-atomic patch limitations on x86/x64.
