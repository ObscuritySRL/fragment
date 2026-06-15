# Fragment

**Fragment** is a small Windows x64 DLL that transparently redirects a target
process's [libcurl](https://curl.se/libcurl/) traffic through a local
reverse-proxy. It injects into the process, hooks libcurl at its **API layer**,
and rewrites every outbound request URL to

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

---

## Why the API layer

Most "redirect a program's HTTPS somewhere else" tricks operate at the socket or
DNS layer, where the request is already committed to a host and (for HTTPS)
encrypted — so cert pinning defeats them. Fragment intercepts the *intent*: the
URL the application hands to libcurl. It:

- **Rewrites** `CURLOPT_URL` and URLs built through the `curl_url` API
  (`curl_url_set`, and `CURLOPT_CURLU` handles) to the proxy prefix. The rewrite
  is **idempotent**, so re-setting a URL — or the interplay between the
  `setopt` and `curl_url_set` hooks — never double-prefixes.
- **Neutralizes options that would divert traffic back off the proxy**:
  `CURLOPT_RESOLVE` and `CURLOPT_CONNECT_TO` (a DNS/host pin), `CURLOPT_PORT`
  (a port override), `CURLOPT_UNIX_SOCKET_PATH` / `CURLOPT_ABSTRACT_UNIX_SOCKET`
  (a local socket in place of the TCP path to the proxy), and `CURLOPT_PROXY` /
  `CURLOPT_PRE_PROXY` (an upstream proxy that would carry the rewritten request
  off-box). The proxy options are forced to `""` (a *direct* connection that
  also overrides the environment proxy variables), and Fragment scrubs
  `http_proxy` / `https_proxy` / `all_proxy` (and friends) from the target's
  environment at load time so an app that never sets a proxy through the API
  can't inherit one either.

The "rewrite at the curl API before the connection" property is the whole point;
everything else — the hooking engine, the way the module is intercepted, the
configuration — is just implementation.

---

## Quick start

```sh
# Build (auto-detects any VS 2017+ with the C++ x64 toolset; no hardcoded paths)
build.bat Release

# Launch a program with its libcurl redirected to http://127.0.0.1:9020
build\fragment.exe -- curl.exe https://api.example.com/health

# ...or inject into an already-running process
build\fragment.exe --pid 1234
```

You provide the proxy listening on `127.0.0.1:9020`. It receives requests whose
path is the full original URL (e.g. `GET /https://api.example.com/health`) and
is expected to forward them upstream and relay the response.

`fragment.exe --help` lists every option; all of them simply set the environment
variables below for the launched target.

---

## Configuration

All knobs are read **once at load time from the environment**, so the *same*
shipped DLL can be re-pointed, toggled, or made verbose with no recompile.

| Variable | Meaning | Default |
|---|---|---|
| `FRAGMENT_PROXY` | Full proxy base, e.g. `http://127.0.0.1:9020` or `https://10.0.0.5:8888`. Wins if set. | — |
| `FRAGMENT_PROXY_HOST` | Proxy host (when `FRAGMENT_PROXY` is unset). | `127.0.0.1` |
| `FRAGMENT_PROXY_PORT` | Proxy port (when `FRAGMENT_PROXY` is unset). | `9020` |
| `FRAGMENT_ENABLED` | `0`/`false`/`no`/`off` → load but do not hook. | `1` |
| `FRAGMENT_DISABLE` | `1`/`true`/`yes`/`on` → load but do not hook (overrides `FRAGMENT_ENABLED`). | `0` |
| `FRAGMENT_LOG_LEVEL` | `off`\|`error`\|`warn`\|`info`\|`debug`. | `off` (Release) |
| `FRAGMENT_LOG_FILE` | Write diagnostics to a file; if unset, logs go to the debugger (`OutputDebugString`). | — |
| `FRAGMENT_LOG_CONSOLE` | `1` → allocate a console and tee logs there. | `0` |
| `FRAGMENT_LOADER` | Module-load interception strategy: `auto`\|`notify`\|`ldrloaddll`\|`loadlibrary`. | `auto` |

A malformed `FRAGMENT_PROXY` (empty, scheme-less, or collapsing to `/`) is
rejected with a warning and the default is used, so a typo can never silently
disable rewriting.

Diagnostics work in **Release**, not just debug builds: set `FRAGMENT_LOG_LEVEL`
(and optionally `FRAGMENT_LOG_FILE`) and the leveled, thread-safe logger is
active. When the level is `off` the hot path costs a single comparison.

---

## How interception works

**Finding libcurl.** For shared libcurl, Fragment resolves the hooked functions
by **export** (`GetProcAddress`) — version-, compiler-, and bitness-invariant,
because the export names are part of libcurl's stable ABI. It works for every
shared libcurl, forever, with no signatures. For *statically*-linked curl (no
export table) it falls back to a small per-compiler-family prologue-signature
scan, gated on the module actually containing the symbol name so it never
false-matches.

**Catching the module however it loads.** A curl module can enter a process many
ways — already mapped, `LoadLibrary`, `LoadLibraryEx`, delay-load, or pulled in
transitively as another DLL's dependency. Fragment layers independent
approaches and degrades gracefully (`FRAGMENT_LOADER` forces one):

1. **`LdrRegisterDllNotification`** — the loader's own load-notification
   callback. Fires for *every* mapped image regardless of load path, including
   transitive static-import dependencies. The default and broadest.
2. **`LdrLoadDll` hook** — the single ntdll chokepoint that `LoadLibrary`
   A/W/Ex and the delay-load helper all funnel through. Used if the
   notification API is unavailable.
3. **`LoadLibraryA`/`W` detours** — a last-resort fallback.

Plus an initial sweep of already-mapped modules at attach. Overlap between
approaches is collapsed by a dedup keyed on the resolved target address (sourced
from the hook registry, so it is unbounded — no fixed cap).

**Hooking.** Fragment ships its **own** x86-64 inline-hook engine — no
third-party dependency. It length-decodes the target prologue, relocates it into
a trampoline within ±2 GB, and patches a 5-byte jump. The decoder **fails
closed**: anything it cannot decode with certainty (an unknown opcode, a short
branch leaving the copied window, an out-of-range relocation) is refused and the
target is left untouched, so a mis-decode can never corrupt the process.

---

## Building

Requires Visual Studio 2017+ with the C++ x64 toolset (any edition, including
Build Tools). `build.bat` locates it via `vswhere` — no machine-specific paths —
and prefers a CMake/Ninja on `PATH`, otherwise the copies bundled with VS.

```sh
build.bat            # Release
build.bat Debug      # Debug (chatty logging by default)
```

CMake presets are provided (`cmake --preset release|debug|msvc`). Continuous
integration (`.github/workflows/ci.yml`) builds on a clean `windows-latest`
runner and runs the self-contained engine and mock-libcurl tests on every push;
tagging `v*` builds, smoke-tests, and publishes a release artifact
(`Fragment.dll` + `fragment.exe`).

---

## Testing

```sh
python test\run.py            # full matrix (Release)
python test\run.py --debug    # Debug build
```

The suite proves behavior, not assertions:

- A **hook-engine unit test** exercises prologue relocation (RIP-relative loads,
  rel32 branches) and the fail-closed refusals.
- A **mock-libcurl integration test** (no servers, no real libcurl) proves the
  export-resolution → `setopt` rewrite → idempotency → option-drop path; it runs
  in CI on a clean machine.
- A **real-libcurl matrix** spanning libcurl 7.30 → 8.20 and five compilers
  (VS2010, VS2012, modern MSVC, MinGW-GCC, LLVM/clang), covering shared-library
  (export) and static (signature) resolution, the `curl_url` API, every
  interception approach in isolation, runtime reconfiguration, a concurrency
  stress test, and a per-call overhead/injection-latency benchmark.
- **Non-vacuous negative controls** prove the divert options (`RESOLVE`,
  `CONNECT_TO`, `PORT`, `PROXY`, the `http_proxy` env var) really *do* divert
  when not neutralized, and that the narrower interception modes really miss
  what the broadest one catches.

The real-libcurl binaries are third-party and intentionally not committed; see
[`test/curl/README.md`](test/curl/README.md) to reproduce the corpus.

Typical measured per-call overhead of the `setopt` detour is on the order of a
few tens of nanoseconds — negligible against a real request, which the
benchmark reports honestly (it does not pretend the request-level throughput
difference is a hook cost).

---

## Limitations (honest boundaries)

Fragment is precise about what it does *not* cover:

- **x64 only.** The hook engine, caller stubs, and static-curl signatures are
  x86-64; `fragment.exe` detects and refuses 32-bit (WOW64) targets.
- **API-layer interception is bypassable below it.** Anything that reaches the
  network beneath the URL API is invisible: a custom
  `CURLOPT_OPENSOCKETFUNCTION` / `CURLOPT_SOCKOPTFUNCTION`, or an app that opens
  its own raw sockets. (A Unix-domain socket requested the normal way, via
  `CURLOPT_UNIX_SOCKET_PATH`, *is* neutralized — it flows through the hooked
  `setopt` — but a socket created entirely outside libcurl is not.)
- **Static-curl support is signature-based and therefore best-effort.** Shared
  libcurl (export-resolved) is universal; statically-linked curl relies on
  prologue signatures for known compiler families and **fails closed** (no hook,
  traffic un-proxied) on an unrecognized prologue — silent unless logging is on.
  A statically-linked curl living inside a *dynamically*-loaded DLL whose name
  lacks "curl" is also skipped by the (name-gated) signature scan.
- **`FRAGMENT_LOADER=ldrloaddll` misses statically-imported curl.** A libcurl
  pulled in as a static import of another DLL is mapped by the loader's internal
  dependency walker, which the exported `LdrLoadDll` does not see. The default
  `auto`/notification mode *does* catch it (and the test suite locks this in as
  a negative control). Prefer the default unless you have a reason not to.
- **Proxy neutralization covers the cases Fragment can see.** It forces
  `CURLOPT_PROXY`/`PRE_PROXY` direct and scrubs the standard proxy environment
  variables at load. A proxy set on a handle *before* Fragment's hook is
  installed (a racy pre-injection configuration) would not be re-overridden.
- **Narrow torn-write window on the load-notification path.** Curl hooks
  installed from the loader-notification callback use an atomic 8-byte publish
  where alignment allows; for the rare wide/unaligned prologue a thread calling
  curl at the exact instant the module appears could read a torn instruction.
  In the normal flow, hooks land before curl is exercised.
- **Injection needs the right privileges**, and **manually-mapped** modules
  (loaded without the OS loader, so no load event fires) are not seen.

If total interception matters for your use case, treat these as the edges of the
guarantee, not footnotes.

---

## Layout

```
main.c        injection entry, the curl detours, loader-interception strategy
hook.h        the standalone x86-64 inline-hook engine (decoder, trampolines)
util.h        export/signature resolution, caller stubs, PE/region helpers
config.h      environment-driven configuration
log.h         leveled, thread-safe, Release-capable logger
curl.h        the slice of libcurl's stable ABI Fragment depends on
tools/        fragment.exe — the end-user loader/injector
test/         the engine, mock, and real-libcurl test suite
```

---

## License

See [LICENSE](LICENSE).

Fragment is a traffic-redirection and inspection tool. Use it only on software
and systems you are authorized to analyze.
