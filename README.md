# Fragment

**Fragment** transparently redirects a target process's
[libcurl](https://curl.se/libcurl/) traffic through a local reverse-proxy. It
intercepts libcurl at its **API layer** and rewrites every outbound request URL
to

```
http://127.0.0.1:9020/<original-url>
```

Because the rewrite happens at the `curl_easy_setopt` / `curl_url` boundary —
**before** libcurl resolves, connects, or starts a TLS handshake — it steers the
request to your proxy *without* fighting certificate pinning. From the pinned
server's perspective there is no connection to pin against; libcurl simply makes
a plain-HTTP request to `127.0.0.1:9020`, and your proxy does whatever it likes
upstream (terminate TLS to the real host, inspect, rewrite, record, replay).

> Inspired by [Jaren8r/Fragment](https://github.com/Jaren8r/Fragment).

This is a single cross-platform project: one shared, OS-independent core, with
the OS-specific code segregated per platform and one build entry point.

| Path | Role |
|---|---|
| [`common/`](common) | The OS-independent core shared by both ports — the x86-64 prologue decoder and the curl-ABI option ids. |
| [`windows/`](windows) | The Windows port — `Fragment.dll` + `fragment.exe`. DLL injection + an inline-hook engine over libcurl's exports. |
| [`linux/`](linux) | The Linux port — `libfragment.so` + `fragment`. `LD_PRELOAD` symbol interposition (+ rtld-audit, `dlopen`, and an inline-hook engine), with `ptrace` injection. |

Both ports share the same `FRAGMENT_*` configuration, the same leveled
Release-capable logger, the same idempotent rewrite + option-neutralization
semantics, and the same "fail closed / honest boundaries" philosophy.

---

## Why the API layer

Most "redirect a program's HTTPS somewhere else" tricks operate at the socket or
DNS layer, where the request is already committed to a host and (for HTTPS)
encrypted — so cert pinning defeats them. Fragment intercepts the *intent*: the
URL the application hands to libcurl. It:

- **Rewrites** `CURLOPT_URL` and URLs built through the `curl_url` API
  (`curl_url_set`, and `CURLOPT_CURLU` handles) to the proxy prefix. The rewrite
  is **idempotent**, so re-setting a URL — or the interplay between the
  `setopt` and `curl_url_set` paths — never double-prefixes.
- **Neutralizes options that would divert traffic back off the proxy**:
  `CURLOPT_RESOLVE` and `CURLOPT_CONNECT_TO`, `CURLOPT_PORT`,
  `CURLOPT_UNIX_SOCKET_PATH` / `CURLOPT_ABSTRACT_UNIX_SOCKET`, and
  `CURLOPT_PROXY` / `CURLOPT_PRE_PROXY` (forced to a direct `""`). It also scrubs
  `http_proxy` / `https_proxy` / `all_proxy` from the target's environment at
  load so an app that never sets a proxy through the API can't inherit one.

The "rewrite at the curl API before the connection" property is the whole point;
everything else — interposition, the inline-hook engine, the way the module is
delivered into the process — is just implementation.

---

## Quick start

```sh
# Windows  (Visual Studio 2017+ with the C++ x64 toolset)
cd windows && build.bat
build\fragment.exe -- curl.exe https://api.example.com/health   # launch & inject
build\fragment.exe --pid 1234                                   # inject into a PID

# Linux  (any C compiler; cmake optional)
cd linux && ./build.sh
./build/fragment -- curl https://api.example.com/health         # launch & preload
./build/fragment --pid 1234                                     # ptrace-inject into a PID
```

Or build the host platform from the repository root with the single CMake entry:
`cmake -S . -B build && cmake --build build`.

You provide the proxy listening on `127.0.0.1:9020`. It receives requests whose
path is the full original URL (e.g. `GET /https://api.example.com/health`) and
is expected to forward them upstream and relay the response. `fragment --help`
lists every option.

---

## Configuration

All knobs are read **once at load time from the environment**, so the *same*
shipped binary can be re-pointed, toggled, or made verbose with no recompile.

| Variable | Meaning | Default |
|---|---|---|
| `FRAGMENT_PROXY` | Full proxy base, e.g. `http://127.0.0.1:9020`. Wins if set. | — |
| `FRAGMENT_PROXY_HOST` | Proxy host (when `FRAGMENT_PROXY` is unset). | `127.0.0.1` |
| `FRAGMENT_PROXY_PORT` | Proxy port (when `FRAGMENT_PROXY` is unset). | `9020` |
| `FRAGMENT_ENABLED` | `0`/`false`/`no`/`off` → load but do not rewrite. | `1` |
| `FRAGMENT_DISABLE` | `1`/`true`/`yes`/`on` → load but do not rewrite (overrides `FRAGMENT_ENABLED`). | `0` |
| `FRAGMENT_LOG_LEVEL` | `off`\|`error`\|`warn`\|`info`\|`debug`. | `off` (Release) |
| `FRAGMENT_LOG_FILE` | Write diagnostics to a file; if unset, to the debugger (Windows) / stderr (Linux). | — |
| `FRAGMENT_LOG_CONSOLE` | `1` → also surface logs on a console / stderr. | `0` |
| `FRAGMENT_LOADER` | Interception strategy — Windows: `auto`\|`notify`\|`ldrloaddll`\|`loadlibrary`; Linux: `auto`\|`interpose`\|`audit`\|`hook`. | `auto` |

A malformed `FRAGMENT_PROXY` (empty, scheme-less, or collapsing to `/`) is
rejected with a warning and the default is used, so a typo can never silently
disable rewriting. Diagnostics work in **Release**: when the level is `off` the
hot path costs a single comparison.

---

## How interception works

Both ports rewrite at the same curl-API boundary and ship their **own**
inline-hook engine — no third-party dependency. The engine length-decodes the
target prologue, relocates it into a trampoline within reach, and patches a
jump; the decoder **fails closed** (anything it cannot relocate with certainty
is refused, leaving the target untouched). The x86-64 prologue decoder is the
OS-independent part and lives once in [`common/decode_x86_64.h`](common/decode_x86_64.h),
shared by both ports.

### Windows

**Finding libcurl** by **export** (`GetProcAddress`) for any shared libcurl
(version-, compiler-, bitness-invariant), with a per-compiler-family
prologue-signature scan as a fallback for statically-linked curl, gated on the
module containing the symbol name. **Catching the module however it loads** by
layering `LdrRegisterDllNotification` (every mapped image, incl. transitive
static imports), an `LdrLoadDll` chokepoint hook (LoadLibrary A/W/Ex +
delay-load), and `LoadLibraryA`/`W` detours, plus an already-mapped sweep, with
a dedup keyed on the resolved address. The engine relocates into a trampoline
within ±2 GB and patches a 5-byte jump. **Delivery** is `CreateRemoteThread` +
`LoadLibrary` (`fragment.exe`); 32-bit (WOW64) targets are refused.

### Linux

**Symbol interposition** is the portable primary: the preloaded `.so` exports
`curl_easy_setopt` / `curl_url_set` and forwards through `dlsym(RTLD_NEXT)`,
shadowing libcurl for a direct link, a transitive dependency, or a default-scope
`dlopen`, on **x86-64 and aarch64**, with no machine code. `FRAGMENT_LOADER`
selects/forces among `auto` (interposition + an inline byte-patch of the real
libcurl, which also covers an injected process), `interpose`, `audit` (the
loader's rtld-audit `la_symbind` rebind), and `hook`. The functions to patch are
resolved by reading the owning object's `.dynsym` / `.symtab` (immune to
interposition, correct even when injected), with a prologue-signature scan as a
stripped-binary fallback. The aarch64 backend patches a single naturally-aligned
4-byte word (atomic, BTI-correct). **Delivery** is `LD_PRELOAD` / `LD_AUDIT`
launch, or `ptrace` injection that makes the target `dlopen` the library
(`dlopen` located by `dladdr` and matched in the target by inode).

---

## Building

```sh
# Windows: auto-detects any VS 2017+ x64 toolset via vswhere -- no hardcoded paths.
cd windows && build.bat            # Release   (build.bat Debug for chatty logging)

# Linux: prefers CMake (Ninja if present), falls back to a direct cc build.
cd linux && ./build.sh             # Release   (./build.sh Debug; or `make`)

# Either platform, from the repo root:
cmake -S . -B build && cmake --build build
```

Continuous integration ([`.github/workflows/ci.yml`](.github/workflows/ci.yml))
builds on clean `windows-latest` and `ubuntu-latest` runners and runs the
self-contained engine unit test and the mock-libcurl integration on every push.

---

## Testing

```sh
python3 windows/test/run.py        # Windows matrix (needs the third-party corpus)
python3 linux/test/run.py          # Linux matrix   (uses the system libcurl + curl)
```

Each suite proves behavior, not assertions: a **hook-engine unit test**
(prologue relocation + fail-closed refusals), a self-contained **mock-libcurl
integration test** (no third-party binaries, CI-runnable), and a **real-libcurl
matrix**. Windows spans libcurl 7.30 → 8.20 and five compilers across the export
and static-signature paths. Linux drives the system libcurl and `curl` binary
through interposition, the `curl_url` API, a transitive dependency, dlopen-then-
`dlsym`, all four modes, runtime config, bypass neutralization with non-vacuous
negative controls, a concurrency stress, a benchmark, the launcher, and a live
`ptrace --pid` injection — plus the x86-64 subset under `qemu-x86_64`.

---

## Limitations (honest boundaries)

- **x86-64 (both) / aarch64 (Linux) only** for the inline-hook layers. The
  Linux symbol interposition itself is architecture-independent; the byte-patch
  engine, caller stubs, and static-curl signatures are not.
- **API-layer interception is bypassable below it** — a custom
  `CURLOPT_OPENSOCKETFUNCTION` / `CURLOPT_SOCKOPTFUNCTION`, or an app that opens
  its own raw sockets, is invisible.
- **Static-curl support is symbol-table-based, then best-effort.** A stripped
  static curl falls to a prologue-signature scan that **fails closed** when the
  symbol name is absent from loaded memory.
- **Linux `audit` mode rebinds call sites, not captured addresses**, and needs
  `LD_AUDIT` at startup (launch-only). The other modes do not share this.
- **Injection needs the right privileges** (an injectable target, and on Linux
  `CAP_SYS_PTRACE` / root / `ptrace_scope=0`); a manually-mapped or fully-static
  target may not be reachable. Config for an injected target comes from *its*
  environment.

If total interception matters for your use case, treat these as the edges of the
guarantee, not footnotes.

---

## Layout

```
common/      shared, OS-independent core (x86-64 prologue decoder, curl-ABI ids)
windows/     Windows port: DllMain hooks, PE resolution, the Win32 engine, loader, tests
linux/       Linux port: interposers + rtld-audit + ELF resolution, the POSIX engine, loader, tests
CMakeLists.txt   one entry point -> builds the host platform from common/ + windows|linux
```

Each port's directory carries its own platform build script and a `test/`
suite; both pull the shared core in through a relative include.

---

## License

See [LICENSE](LICENSE).

Fragment is a traffic-redirection and inspection tool. Use it only on software
and systems you are authorized to analyze.
