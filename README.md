# Fragment

**Redirect a process's libcurl or Windows WinHTTP requests through a proxy you control.**

Fragment is a C17 library and launcher for Windows and Linux. It changes the
request destination at the HTTP API boundary, before the connection to the
original server, and sends the original URL to your proxy in the request path:

```text
Target requests:  https://api.example.com/health
Proxy receives:  GET /https://api.example.com/health
Proxy address:   http://127.0.0.1:9020  (configurable)
```

Your proxy forwards the request upstream and returns the response. It can also
inspect, modify, record, or replay traffic. Fragment supplies the redirection;
what gets recorded depends on the proxy. For a redirected HTTPS request using
an HTTP proxy base, the target makes no TLS connection to the original server.
This does not guarantee compatibility with every application's pinning or
response-validation logic.

[Releases](https://github.com/ObscuritySRL/fragment/releases) ·
[Agent usage guide](AGENTS.md#help-someone-use-fragment) ·
[Verification notes](docs/verification.md) · [Changelog](CHANGELOG.md)

Inspired by [Jaren8r/Fragment](https://github.com/Jaren8r/Fragment).

## What it supports

| Request stack | Platform | How Fragment redirects it |
|---|---|---|
| libcurl | Windows, Linux | Rewrites `CURLOPT_URL` and curl URL API values; neutralizes options that would divert the request away from the proxy. |
| WinHTTP | Windows | Redirects the connection handle, remembers its original destination, and reconstructs the URL when a request handle is created. |
| WinINet, Chromium/CEF networking, direct TLS or socket APIs, QUIC | No implemented backend | Loading Fragment does not establish coverage for these requests. |

Both implemented backends use the same proxy contract and configuration. On
Windows, they are discovered automatically; you do not select a libcurl versus
WinHTTP mode. The `--loader` option changes discovery/interception strategy,
not the networking stack used by the application.

WinHTTP and WinINet are separate Windows APIs; a WinHTTP hook does not cover a
program using WinINet. Schannel and OpenSSL operate at the TLS layer and are not
standalone Fragment backends. An application may use either underneath a
supported HTTP API, but direct calls to those TLS libraries are not intercepted.

Coverage is per process. A launcher and its networking helper may be different
processes, and children are not automatically injected. macOS is documentation
only. [BRIEF.md](BRIEF.md) describes possible future backends, not shipping support.

## Get started

### 1. Get the right build

Download and extract a matching asset from
[Releases](https://github.com/ObscuritySRL/fragment/releases), or follow
[Building from source](#building-from-source). GitHub's source ZIP/tarball is a
source checkout, not a compiled package.

| Release package | Keep together |
|---|---|
| Windows x64 | `fragment.exe` and `Fragment.dll` |
| Linux X64 | `fragment` and `libfragment.so` |
| Linux ARM64 | `fragment` and `libfragment.so` |

Match the library to the target architecture. The Windows x64 archive does not
include the separately built `Fragment32.dll` needed for a 32-bit WOW64 target.
Other engine architectures exist in source; check release assets before assuming
there is a package for them. Compiled releases do not require a compiler.

### 2. Start a compatible proxy

From the repository or a package containing the script, run in one terminal:

```sh
bun tools/proxy.ts 19020
```

Leave it running. This optional forwarding proxy requires Bun and no package
installation. It listens on loopback and prints the request method, URL, and
upstream response status. It does not record response bodies. URLs and any
payloads you choose to record can contain sensitive data.

Release v1.2.1 includes `tools/proxy.ts` and `AGENTS.md`. Existing
v1.2.0 archives omit them: obtain the [v1.2.0 proxy script](https://github.com/ObscuritySRL/fragment/blob/v1.2.0/tools/proxy.ts)
from the repository, or use your own compatible proxy.

A compatible proxy accepts `/<original-url>` paths and relays responses. An
ordinary CONNECT or SOCKS proxy cannot be substituted without an adapter. The
included script serves this contract at `/`; a custom mount such as `/inspect`
requires a proxy that understands that mount.

The examples use port **19020**; Fragment defaults to **9020**. If the chosen
port is occupied, use another free port in both the proxy and launch command.

### 3. Launch your program

Open a second terminal in the extracted package directory. Replace the example
program and arguments with your target.

**Windows — PowerShell:**

```powershell
.\fragment.exe --version
.\fragment.exe --proxy http://127.0.0.1:19020 --log debug --log-file fragment.log -- "C:\Path\To\program.exe" arg1
```

**Linux:**

```sh
./fragment --version
./fragment --proxy http://127.0.0.1:19020 --log debug --log-file fragment.log -- /path/to/program arg1
```

Everything after `--` belongs to the target. If it needs a particular working
directory, run there and use an absolute path to Fragment. An absolute
`--log-file` path also makes diagnostics easier to locate. `--help` lists the
options for the installed version.

For a source build, use `windows/build/fragment.exe` or `linux/build/fragment`
instead. Visual Studio multi-configuration builds place Windows binaries under
`windows/build/Release/` (or `Debug/`); use the actual output directory.

### 4. Verify a request

Trigger a known action in the target and distinguish three results:

| Result | Evidence |
|---|---|
| Library loaded | Launcher confirmation or the target's module list. |
| Hooks installed | `[hook]` diagnostics; WinHTTP also logs `[winhttp] backend ready`. |
| Request redirected | The expected original URL appears at the proxy and the target receives the expected response. |

A loaded DLL alone is not a successful capture. For a controlled local test,
check the exact path, method, body, target exit status, and absence of direct
origin hits. Compare a bare launch and a launch with `--off` before `--`.

To stop using Fragment, restart the target normally. Stopping only the proxy
leaves the instrumented process sending requests to an unavailable destination.

## Attach to an existing process

From the package directory, after identifying the correct PID:

```powershell
# Windows
.\fragment.exe --pid 1234
```

```sh
# Linux
./fragment --pid 1234
```

**Configuration comes from the target's existing environment.** Supplying
`--proxy` or logging options alongside `--pid` cannot change that environment.
Prefer launching with Fragment when you need to choose configuration or capture
requests from startup. Existing WinHTTP connections lack the origin metadata
needed for rewriting and pass through.

Attachment requires access to the target. Linux ptrace policy or target
protections can prevent it. An injection failure is not capture success;
changing `--loader` does not provide an alternative DLL injection mechanism.

## WinHTTP backend

WinHTTP builds a request across session, connection, and request handles, rather
than accepting one complete URL. Fragment hooks five exports from `winhttp.dll`:

| Entry point | Behavior while the backend is active |
|---|---|
| `WinHttpOpen` | Forces a direct session so the application's upstream proxy does not intercept the redirected connection. |
| `WinHttpConnect` | Connects to the configured proxy and stores the original host/port against the returned handle. |
| `WinHttpOpenRequest` | Rebuilds `/<scheme>://<host>[:port]/<path>` from the connection metadata and request flags. Sets the secure flag according to the proxy scheme. |
| `WinHttpSetOption` | Neutralizes later `WINHTTP_OPTION_PROXY` overrides. Other options pass through. |
| `WinHttpCloseHandle` | Removes connection metadata, including entries belonging to a closed session. |

For example, an HTTPS POST to `api.example.com:8443/orders?id=7`, with a proxy
base of `http://127.0.0.1:19020`, arrives as:

```http
POST /https://api.example.com:8443/orders?id=7
```

The request method and body are preserved. Origin ports, query strings, and a
configured proxy mount are included in the reconstructed path. An HTTP proxy
base receives plain HTTP even for HTTPS origins; an HTTPS proxy base uses TLS
to the proxy and requires suitable certificates and a compatible proxy server.
The supplied Bun proxy listens over HTTP.

Fragment handles WinHTTP already loaded at injection and discovered later.
Redirection activates only after all five hooks install; partial installation
stays inactive. Failure to retain origin metadata or allocate the rewritten
path returns an error instead of sending an incorrectly reconstructed request.

The real-WinHTTP test matrix covers GET/POST, body preservation, query strings,
nonstandard ports, application proxy overrides, mount paths, session teardown,
launcher injection, disabled/bare controls, and 480 concurrent requests. Separate
state tests exercise partial activation and allocation failures.

Limits include connections created before activation, the simple proxy-address
parser (use a hostname or IPv4 address rather than relying on IPv6 literal
support), and unverified WebSocket/streaming behavior. Fragment does not hook
Schannel or capture TLS plaintext as a general fallback. Fixture success does
not establish compatibility with a particular third-party application.

## libcurl backend

Fragment rewrites `CURLOPT_URL`, `curl_url_set`, and `CURLOPT_CURLU` URLs before
connection setup. Rewriting is idempotent, so an already-prefixed URL is not
prefixed again. It neutralizes diversion through `RESOLVE`, `CONNECT_TO`, `PORT`,
Unix-socket options, `PROXY`, and `PRE_PROXY`, and removes inherited HTTP proxy
environment settings when enabled.

On **Windows**, exported curl functions are the primary discovery route.
Embedded/static curl uses compiler-specific signatures only when the module
contains the relevant symbol-name marker. Module filenames need not contain
"curl". Ambiguous matches and unsupported instruction relocation are refused.
The default discovery strategy combines loader notifications, loader hooks, and
an already-loaded module sweep. `CURLOPT_CURLU` read-back needs URL API exports
in the same module.

On **Linux**, symbol interposition is combined with inline hooking by default.
Resolution uses ELF symbol tables, with signatures as a fallback for stripped
binaries. The available strategies are `auto`, `interpose`, `audit`, and `hook`;
`audit` requires startup configuration and cannot rebind function pointers that
were already captured. Launching uses `LD_PRELOAD` or `LD_AUDIT`; PID attachment
uses ptrace to load the library.

Unknown static builds remain best-effort. Fully static processes, custom socket
callbacks, and requests made through another networking library can fall outside
coverage. x86/x64 installation into a busy process retains documented
non-atomic patch limitations.

## Configuration

Configuration is read once from the target's environment when Fragment loads.
Launcher flags set it for a new child. Use `--loader auto` unless diagnosing a
specific discovery problem.

| Variable | Meaning | Default |
|---|---|---|
| `FRAGMENT_PROXY` | Full proxy base; takes precedence over host/port variables. | Unset |
| `FRAGMENT_PROXY_HOST` | Proxy host when no full base is supplied. | `127.0.0.1` |
| `FRAGMENT_PROXY_PORT` | Proxy port when no full base is supplied. | `9020` |
| `FRAGMENT_ENABLED` | `0`, `false`, `no`, or `off` disables interception. | `1` |
| `FRAGMENT_DISABLE` | `1`, `true`, `yes`, or `on` disables interception, overriding `FRAGMENT_ENABLED`. | `0` |
| `FRAGMENT_LOG_LEVEL` | `off`, `error`, `warn`, `info`, or `debug`. | Normally `off` in Release |
| `FRAGMENT_LOG_FILE` | Diagnostic output path. Otherwise debugger output on Windows, stderr on Linux. | Unset |
| `FRAGMENT_LOG_CONSOLE` | `1` also sends diagnostics to console/stderr. | `0` |
| `FRAGMENT_LOADER` | Windows: `auto`, `notify`, `ldrloaddll`, `loadlibrary`. Linux: `auto`, `interpose`, `audit`, `hook`. | `auto` |

Use a well-formed HTTP(S) proxy base. Empty or scheme-less configuration can
fall back to the default; configuration validation is not a proxy reachability
check. Enable diagnostics and confirm the destination actually observed.

## When the proxy stays empty

Check these in order:

1. **Proxy:** Is it listening on the configured host/port and serving the
   `/<original-url>` contract? A 502 from the included proxy means its upstream
   request failed; inspect its error output.
2. **Loading:** Did the correct library load into the intended PID? Check paths,
   target architecture, permissions, and the launcher's result.
3. **Hooks:** Inspect `fragment.log`. Release builds support diagnostic logging;
   you do not need a Debug build. A missing/unsupported signature or failed
   relocation leaves that target unhooked.
4. **Request path:** Does that process use libcurl or WinHTTP? Did the action
   issue a new request, or use a WinHTTP connection created before attachment?
5. **Process tree:** Is a child/helper doing the networking? A Chromium/CEF
   helper is not covered merely because its launcher loaded Fragment.

Use the [verification notes](docs/verification.md) to distinguish tested fixture
behavior from application observations. The [agent guide](AGENTS.md) walks
through setup and diagnosis for both source and downloaded copies.

## Building from source

Run from the repository root.

**Windows:** Visual Studio 2017+ with C++ x64 tools and CMake (the bundled Visual
Studio CMake/Ninja tools are detected when available).

```powershell
cmd /c windows\build.bat
# Optional: cmd /c windows\build.bat Debug
```

**Linux:** a C compiler; CMake is used when available, otherwise a direct compiler
build is supported.

```sh
bash linux/build.sh
# Optional: bash linux/build.sh Debug
```

Both produce the launcher and library. A shared CMake entry is also available:

```sh
cmake -S . -B build
cmake --build build --config Release
```

Engine backends exist for Windows x64/x86/ARM64 and Linux x64/i386/ARM64/armv7.
CI runs Windows x64/x86, WOW64 injection, Windows ARM64, and Linux x64/ARM64;
additional source architectures are not implied to have the same current CI
or release-package coverage.

## Testing

Native fixtures are C; new orchestration uses Bun. From a source checkout:

```sh
bun install --frozen-lockfile
bun run typecheck
bun test ./test

# On Windows:
bun windows/test/run.ts
bun windows/test/run_winhttp.ts

# On Linux:
bun linux/test/run.ts
```

The platform runners build their native fixtures; `--no-build` reuses an
existing build. Tests use **19020, 19021, and 19999**: stop a demo proxy you
started on one of those ports before running them. Missing optional fixtures
are reported as SKIP. The Windows engine, mock curl, and WinHTTP fixtures need
no downloaded curl corpus; Linux integration uses system curl/libcurl.

Windows accepts repeatable `--libcurl <dll>` and `--curl <exe>` arguments:

```powershell
bun windows/test/run.ts --libcurl "C:\Program Files\Git\mingw64\bin\libcurl-4.dll"
bun windows/test/pe.ts path/to/libcurl.dll curl_easy_setopt curl_url_set
bun windows/test/verify_sigs.ts path/to/libcurl.dll
```

The Windows runner also accepts `FRAGMENT_TEST_BUILD` for isolated build output
when using `--no-build`. Build `host_args.exe` from `windows/test/host_args.c`
alongside the other fixtures; `bun test windows/test/launcher.test.ts` checks
argument forwarding. When a curl DLL depends on sibling DLLs, put its directory
on the test process's `PATH` so relocated embedded fixtures can load them too.

Regression coverage includes Windows DLL unload/reload, 64-bit curl option
values on 32-bit targets, parsed-URL mutations, and real curl/WinHTTP redirect
chains with disabled controls. The forwarding proxy rewrites HTTP(S) redirect
locations back through itself. See [regression validation](docs/regression-validation.md)
for the tested platforms and remaining limitations.

Linux has corresponding `elf.ts`, `sigcheck.ts`, and `verify_sigs.ts` tools.
A signature miss does not imply an export-hook miss. Recording-server matrices
check destination, path, method, body, request count, and child exit status;
negative controls establish that bare/disabled requests are not rewritten.
Linux tests report restricted ptrace attachment and unavailable cross toolchains
as SKIP and do not change system ptrace policy. Python scripts remain legacy
references; the Bun runners do not invoke them.

## Repository layout

| Path | Purpose |
|---|---|
| `common/` | Shared instruction decoders, relocation helpers, curl ABI constants, and version. |
| `windows/` | DLL, launcher, libcurl/WinHTTP backends, hook engine, and Windows fixtures. |
| `linux/` | Shared library, launcher, interposition/audit/hook support, and Linux fixtures. |
| `tools/proxy.ts` | Optional Bun forwarding proxy. |
| `test/` | Shared Bun harness, binary/signature tools, and tooling tests. |
| `docs/verification.md` | Observed validation results and boundaries. |
| `AGENTS.md` | Practical usage flow and contributor instructions for agents. |
| `BRIEF.md` | Multi-backend roadmap. |

## License

See [LICENSE](LICENSE). Use Fragment only on software and systems you are
authorized to analyze.
