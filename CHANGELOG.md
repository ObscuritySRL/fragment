# Changelog

All notable changes to **Fragment** are documented in this file.

## [Unreleased]

## [1.1.0] - 2026-06-26

### Added
- **Linux port** (`linux/`) — `libfragment.so` + a `fragment` loader bringing the same API-layer libcurl redirect to **x86-64 and aarch64**. Rewrites `CURLOPT_URL`, `curl_url_set`, and `CURLOPT_CURLU` to `http://127.0.0.1:9020/<original-url>` before connect/TLS, idempotently, and neutralizes the same divert options as the Windows build (`CURLOPT_RESOLVE` / `CONNECT_TO` / `PORT` / `UNIX_SOCKET_PATH` / `ABSTRACT_UNIX_SOCKET` dropped, `PROXY` / `PRE_PROXY` forced direct, `http_proxy` / `all_proxy` scrubbed at load).
- **Symbol interposition** as the portable primary interception: the preloaded `.so` exports `curl_easy_setopt` / `curl_url_set` and forwards through `dlsym(RTLD_NEXT)`, shadowing libcurl for a direct link, a transitive dependency, or a default-scope `dlopen` — no machine code, and an unversioned definition satisfies a versioned `@CURL_OPENSSL_4` reference.
- **Four interception modes** (`FRAGMENT_LOADER=auto|interpose|audit|hook`): `auto` layers interposition with an inline byte-patch of the real libcurl (so an injected process is covered too); `interpose` is interposition only; `audit` rebinds through the loader's rtld-audit interface (`LD_AUDIT` / `la_symbind64`); `hook` forces the inline byte-patch.
- **Exact symbol-table resolution** of the curl functions — reads `.dynsym` (shared) / `.symtab` (static) from the on-disk image via `dl_iterate_phdr`, immune to interposition and correct even when injected (where a plain `dlsym` resolves back to our own shadow) — with a prologue-signature scan as a stripped-binary fallback.
- **Inline-hook engine for x86-64 and aarch64** (`hook.h`): `mmap` / `mprotect` / `__builtin___clear_cache`, a near-block allocator that probes with `MAP_FIXED_NOREPLACE` (no `/proc/self/maps` dependence), fail-closed prologue relocation (RIP-relative / ADR / ADRP / literal-load / branch), an atomic single-word aarch64 patch and an aligned 8-byte x86-64 publish, and a BTI-correct relay (`LDR x16` / `BR x16` into a branch-protected detour).
- **`ptrace --pid` injection** — the `CreateRemoteThread` + `LoadLibrary` analog: the target is made to call `dlopen(libfragment.so)` through a hijacked register frame that returns to address 0, with `dlopen` located by `dladdr` (so it works whether it lives in libc ≥ 2.34 or libdl < 2.34), matched in the target by **inode** (refusing a mismatched libc rather than jumping into garbage), and a signal-delivery-stop loop so an unrelated signal cannot abandon the call mid-`dlopen`.
- **`dlopen` interposer** to catch a curl reached only through `dlsym` pointers or pulled in by a runtime plugin, and an `LD_PRELOAD` / `LD_AUDIT` launch path (`fragment -- <program>`).
- ELF signature validators — `test/elf.py` (prologue dumper), `test/sigcheck.py`, `test/verify_sigs.py` — that check the in-source signature tables against the live system libcurl (and, when staged, an extracted amd64 libcurl).
- A 29-row `test/run.py` matrix driving the **system libcurl** and the system `curl` binary through every path — interposition, the `curl_url` API (full URL and `CURLOPT_CURLU` from parts), a transitively pulled-in libcurl, a dlopen-then-`dlsym` curl, all four modes, runtime reconfiguration, bypass neutralization with non-vacuous negative controls, an 8×60 concurrency stress, a per-call benchmark, the end-user launcher, and a live ptrace injection — plus the engine unit test and the self-contained mock running for x86-64 under `qemu-x86_64`.

- **Version stamping** — `fragment --version` / `-V` on both ports and a version stamp in the attach log, defaulting to the in-development version (`common/version.h`) and injectable at release time (`-DFRAGMENT_VERSION`, set from the git tag).
- **Native aarch64 Linux** is built and tested in CI and shipped in releases (the matrix covers `ubuntu-latest` x86-64 and `ubuntu-24.04-arm` aarch64), alongside the Windows x64 archive.

### Changed
- **Unified into a single cross-platform project.** The Windows and Linux ports now live in one tree (`windows/`, `linux/`) over a shared, OS-independent core in `common/` — the x86-64 prologue decoder and the curl-ABI option ids live once. One root `CMakeLists.txt` builds the host platform; one `README.md`, one `LICENSE`, one `.gitignore`/`.gitattributes`. CI builds and smoke-tests both operating systems (`windows-latest` + `ubuntu-latest`) and a tagged `v*` release publishes both platform archives to one GitHub release.

### Fixed
- The x86-64 prologue decoder is now shared by both ports (`common/decode_x86_64.h`); the Windows engine thereby gains the relocation fix for a `mov` to/from a segment register carrying a RIP-relative operand, which the previously-duplicated Windows copy still carried as a latent bug.

### Security
- Proxy-environment scrub (`http_proxy` / `https_proxy` / `all_proxy` / …) at load on the Linux build, gated on `FRAGMENT_ENABLED` and applied in both the `.so` constructor and the rtld-audit `la_version` entry (an auditor runs before the target's own constructors, so the scrub lands before libcurl reads the variables).
- Bounds-checked on-disk ELF parsing: every section, symbol-table, and string-table offset is validated with overflow-safe (subtraction-form) comparisons, and a symbol name is bounded by the string-table size before comparison, so a malformed or truncated image cannot drive an out-of-bounds read.
- `ptrace` injection refuses a target whose `dlopen`-bearing object is not the byte-identical file (matched by inode) instead of applying a cross-build offset and executing garbage in the victim.

## [1.0.0] - 2026-06-15

### Added
- Initial release of **Fragment** — a Windows x64 DLL that transparently redirects a target process's libcurl traffic through a local reverse-proxy by hooking at the **API layer** (`curl_easy_setopt` / the `curl_url` API), before libcurl resolves, connects, or starts a TLS handshake, steering requests to your proxy without fighting certificate pinning.
- Rewrites `CURLOPT_URL` and URLs built through `curl_url_set` / `CURLOPT_CURLU` to `http://127.0.0.1:9020/<original-url>`, idempotently (re-set URLs and the `setopt`↔`url_set` interplay never double-prefix).
- Neutralizes the options that would divert traffic back off the proxy — `CURLOPT_RESOLVE`, `CURLOPT_CONNECT_TO`, `CURLOPT_PORT`, `CURLOPT_UNIX_SOCKET_PATH` / `CURLOPT_ABSTRACT_UNIX_SOCKET` dropped; `CURLOPT_PROXY` / `CURLOPT_PRE_PROXY` forced to a direct `""` — and scrubs `http_proxy` / `all_proxy` from the target's environment at load.
- **Finds libcurl** by export (`GetProcAddress`) for any shared libcurl — version-, compiler-, and bitness-invariant — with a per-compiler-family prologue-signature scan as a fallback for statically-linked curl, gated on the module actually containing the symbol name so it never false-matches.
- **Catches the module however it loads** by layering `LdrRegisterDllNotification` (every mapped image, including transitive static dependencies), an `LdrLoadDll` chokepoint hook (LoadLibrary A/W/Ex + delay-load), and `LoadLibraryA` / `W` detours, with an initial already-mapped sweep and a teardown-registry dedup keyed on the resolved target address. Selectable via `FRAGMENT_LOADER`.
- A standalone **x86-64 inline-hook engine** — its own length-decoder, ±2 GB trampolines, and a 5-byte relative-jump patch — that **fails closed** on any prologue it cannot decode with certainty.
- `fragment.exe` loader/injector: launch-and-inject (`-- <program>`) or attach to a running PID (`--pid`) via `VirtualAllocEx` + `WriteProcessMemory` + a remote `LoadLibraryA` thread; detects and refuses 32-bit (WOW64) targets.
- Environment-driven configuration read once at load (`FRAGMENT_PROXY` / `_HOST` / `_PORT`, `FRAGMENT_ENABLED` / `_DISABLE`, `FRAGMENT_LOG_LEVEL` / `_LOG_FILE` / `_LOG_CONSOLE`, `FRAGMENT_LOADER`) and a leveled, thread-safe, Release-capable logger.
- A test suite that proves behavior, not assertions — a hook-engine unit test (prologue relocation + fail-closed refusals), a self-contained mock-libcurl integration test (runs in CI with no third-party binaries), and a real-libcurl matrix spanning **libcurl 7.30 → 8.20 and five compilers** (VS2010, VS2012, modern MSVC, MinGW-GCC, LLVM/clang) across the export and static-signature paths, with non-vacuous negative controls. CI on `windows-latest`; tagging `v*` builds, smoke-tests, and publishes `Fragment.dll` + `fragment.exe`.
