# Fragment

**Redirect HTTP requests, or observe a Windows process's TLS plaintext and socket activity.**

Fragment helps you inspect traffic from a program on your own machine. It is a
C17 library and launcher, with two ways to work:

| Mode | Use it when you want to… | Available on |
|---|---|---|
| **Redirect** (the default) | Send supported HTTP requests through a proxy that you control. The proxy can inspect, change, record, or replay them. | Windows and Linux |
| **Observe** | Keep the application's connections and record supported TLS plaintext, socket activity, and optionally raw socket bytes to a local file. | Windows |

In redirection mode, Fragment changes the destination at the HTTP API boundary,
before the connection to the original server. It puts the original URL in the
request path:

```text
Target requests:  https://api.example.com/health
Proxy receives:  GET /https://api.example.com/health
Proxy address:   http://127.0.0.1:9020  (configurable)
```

Your proxy forwards the request upstream and returns the response. Fragment
supplies the redirection; what gets recorded depends on the proxy. For a
redirected HTTPS request using an HTTP proxy base, the target makes no TLS
connection to the original server.
This does not guarantee compatibility with every application's pinning or
response-validation logic.

Observation works below the HTTP API. If a program uses a supported TLS
implementation, you can inspect the bytes it encrypts and decrypts even when
it does not use libcurl or WinHTTP. The offline viewer provides text, hex, and
individual chunk views. It does not need a proxy or an installed certificate.

[Releases](https://github.com/ObscuritySRL/fragment/releases) ·
[Agent usage guide](AGENTS.md#help-someone-use-fragment) ·
[Verification notes](docs/verification.md) · [Changelog](CHANGELOG.md)

Inspired by [Jaren8r/Fragment](https://github.com/Jaren8r/Fragment).

[Observe traffic](#observe-traffic-windows) · [Redirect HTTP](#redirect-http-through-a-proxy) ·
[Attach](#attach-to-an-existing-process) · [Configuration](#configuration) ·
[Build](#building-from-source) · [Test](#testing)

## What it supports

| Communication layer | Platform / mode | What Fragment does |
|---|---|---|
| libcurl | Windows, Linux | Rewrites `CURLOPT_URL` and curl URL API values; neutralizes options that would divert the request away from the proxy. |
| WinHTTP | Windows | Redirects the connection handle, remembers its original destination, and reconstructs the URL when a request handle is created. |
| Schannel / SSPI | Windows, observation mode | Captures bytes accepted by `EncryptMessage` and returned by successful `DecryptMessage`, including tested SSPI function-table calls. |
| Exported OpenSSL | Windows, observation mode | Captures successful `SSL_read`/`SSL_write` and available `_ex` variants in loaded DLLs. |
| Winsock TCP/UDP | Windows, observation mode | Records numeric IPv4/IPv6 endpoints, API outcomes and synchronous byte counts; optional raw bytes. Pending asynchronous calls are explicitly unverified. |
| Plain HTTP, DNS, custom TCP/UDP protocols | Windows, observation mode with `--socket-data` | Records successful synchronous send/receive bytes, including binary data and datagram chunks. System DNS activity may happen in another process. |
| HTTP/2, gRPC, WebSocket, custom TLS protocols | Windows, observation mode | Records plaintext bytes when they pass through supported TLS calls. Protocol decoding is not included. |
| Chromium/CEF/Electron, Go, Rust, Java, NSS, statically linked TLS | Partial or unverified | Winsock activity may be visible; plaintext depends on the actual TLS implementation, exports, and networking process. |

Both redirection backends use the same proxy contract and configuration. On
Windows, they are discovered automatically; you do not select a libcurl versus
WinHTTP mode. Observation mode selects the TLS/socket observers instead. The
two modes are separate; one run does not combine redirection and observation.
The `--loader` option changes discovery/interception strategy, not the
networking stack used by the application.

WinHTTP and WinINet are separate Windows APIs; a WinHTTP hook does not cover a
program using WinINet. Observation mode can inspect WinINet's TLS bytes if they
pass through the hooked Schannel dispatcher; it does not add WinINet URL
redirection. TLS and socket observations do not depend on a libcurl/WinHTTP hook.

Coverage is per process. A launcher and its networking helper may be different
processes, and children are not automatically followed or verified. There is
no general QUIC plaintext, raw AFD, registered I/O, `ConnectEx`/`AcceptEx`, or
kernel networking backend. Named pipes, Unix sockets, shared memory, and other
local IPC have no observation backend. macOS is documentation only; Linux has
libcurl redirection but no TLS/socket observation mode.

Windows observation was added in v1.3.0. Check your executable's `--help` and the
files in its package before using the examples; older releases do not include
this mode. You can also [build from source](#building-from-source).
[BRIEF.md](BRIEF.md) is a roadmap, not a list of implemented features.

## Observe traffic (Windows)

Build from the repository root with `cmd /c windows\build.bat`, then launch
your program with a **new** capture filename:

```powershell
.\windows\build\fragment.exe --observe capture.jsonl --log debug --log-file fragment.log -- "C:\Path\To\program.exe" arg1
```

The launcher waits for the program to exit. After the recording finishes, turn
it into a report, still from the repository root:

```powershell
bun tools/observe.ts capture.jsonl --out capture.html
```

For a Visual Studio multi-configuration build, use
`.\windows\build\Release\fragment.exe`. In an extracted package that includes
observation, use `.\fragment.exe` and the package's `tools/observe.ts`.
Bun is needed to generate the HTML report, but not to launch or record a process.
Opening the report only needs a browser.

Add `--socket-data` when you also want raw synchronous TCP/UDP payloads:

```powershell
.\windows\build\fragment.exe --observe raw.jsonl --socket-data -- "C:\Path\To\program.exe" arg1
```

Without that flag, socket events contain metadata and supported TLS calls
contain plaintext. With it, you can also inspect unencrypted HTTP, DNS packets,
and custom binary protocols. Raw socket bytes may be ciphertext. Use individual
chunks for UDP so datagrams from different peers are not mistaken for a stream.

Observation preserves the original destination, TLS validation, application
proxy configuration, return values and payloads. `--off` disables all hooks and
capture. `--observe` cannot be combined with proxy flags. To configure an existing
target for later attachment, set `FRAGMENT_MODE=observe` and an absolute
`FRAGMENT_CAPTURE_FILE` **before that target starts**; flags cannot reconfigure
another process's environment. See [attachment](#attach-to-an-existing-process)
for the limits of starting a capture after a program is already running.

### Read the capture

Open `capture.html` in a browser. It is a self-contained, offline report with
no external scripts or network requests. The socket table can be filtered by
endpoint, API, transport, PID, or outcome. Payloads are grouped by context with
separate inbound and outbound views: UTF-8 text, exact hex bytes, or individual
chunks. Traffic is displayed as text, so an HTML response is not executed.
If `--out` is omitted, the output is named `<input>.html`.

Keep the JSONL as the original record. It preserves binary bytes as base64,
timestamps, process and thread IDs, sequence numbers, backend names, context
IDs, byte counts, truncation, and explicit gaps. Its record types distinguish
file initialization (`session`), observer readiness (`backend`), payloads
(`data`), socket activity (`network`), and capture failures (`gap`). A session
record alone means the file opened, not that traffic was observed. Backend
records are emitted on runtime calls, so they may not appear immediately after
the hooks install.

Socket outcomes need a little care:

| Outcome | Meaning |
|---|---|
| `completed` | The API completed; transfer calls have a measured byte count where available. This is not proof of delivery to the peer. |
| `pending` | An asynchronous operation or nonblocking connection attempt was submitted. Its later completion is not traced. |
| `completed-unmeasured` | The API returned success, but its transfer count was not safely inspected, including immediate overlapped completions. Zero in this row does not mean zero bytes transferred. |
| `would-block` | The call could not complete now; no asynchronous operation was queued by this call. |
| `failed` | The API failed; the socket error code is retained. |

TLS context IDs and socket IDs are separate; Fragment does not automatically
match them. IDs describe observed lifetimes, not HTTP requests. A successful
encryption call proves that bytes reached the TLS API, not that a server
received them. HTTP/2, gRPC, WebSocket, compression, and custom application
protocols need their own decoders. The viewer does not reconstruct HTTP
request/response pairs or decrypt arbitrary encrypted socket data.

### Capture limits and failure behavior

Every capture and report needs a fresh filename. The capture's parent directory
must exist; the launcher resolves relative capture paths from its working
directory and supports Unicode capture paths. A capture initialization failure
fails DLL loading, and an observation launch stops its newly created target if
injection fails. This does not turn an injection success into a coverage guarantee.

Recording writes synchronously to disk and can change application timing.
There is no automatic rotation or total file-size cap. A payload record retains
up to 1 MiB and marks omitted bytes. Tracking and buffer lists are also bounded;
unreadable buffers, allocation failures, and tracking failures produce gaps
when the file is still writable. A disk write failure stops recording while
the application continues and reports the error to the debugger.

The viewer accepts captures up to 128 MiB and shows at most 2,000 matching socket
rows at once; filtering narrows that list. The JSONL retains all recorded rows.
Malformed records, missing sequence numbers, and incomplete final records are
rejected rather than silently repaired. Finish the capture before generating
the report. Store JSONL and HTML files outside source control: both can contain
credentials and application plaintext. See [observation coverage and format](docs/observation.md)
for the full schema and validation notes.

## Redirect HTTP through a proxy

### 1. Get the right build

Download and extract a matching asset from
[Releases](https://github.com/ObscuritySRL/fragment/releases), or follow
[Building from source](#building-from-source). GitHub's source ZIP/tarball is a
source checkout, not a compiled package.

| Package type | Keep together |
|---|---|
| Windows x64 | `fragment.exe` and `Fragment.dll` |
| Linux X64 | `fragment` and `libfragment.so` |
| Linux ARM64 | `fragment` and `libfragment.so` |

Match the library to the target architecture. A matching Windows launcher uses
`Fragment.dll`, including an x86 launcher with an x86 target. A 64-bit launcher
can also inject an x86 target using a separately built `Fragment32.dll`; the
x64 package does not bundle it. Other architecture mismatches are rejected.
Check the actual release assets before assuming a package exists for an engine
architecture. Compiled releases do not require a compiler or Bun to run.

### 2. Start a compatible proxy

From the repository or a package containing the script, run in one terminal:

```sh
bun tools/proxy.ts 19020
```

Leave it running. This optional forwarding proxy requires Bun and no package
installation. It listens on loopback and prints the request method, URL, and
upstream response status. It does not record response bodies. URLs and any
payloads you choose to record can contain sensitive data.

Older archives, including v1.2.0, omit the script and agent guide. If they are
absent, obtain `tools/proxy.ts` from the matching repository tag, or use your
own compatible proxy. The current release workflow includes the proxy and
offline observation viewer in both platform packages. The viewer can inspect a
Windows capture on Linux; recording itself remains Windows-only.

A compatible proxy accepts `/<original-url>` paths and relays responses. An
ordinary CONNECT or SOCKS proxy cannot be substituted without an adapter. The
included script serves this contract at `/`; a custom mount such as `/inspect`
requires a proxy that understands that mount.

The included proxy forwards methods, request bodies, response status, and
compressed response bytes. It removes hop-by-hop headers and rewrites HTTP(S)
redirect locations through itself so subsequent requests keep passing through
the proxy. Upstream failures or its 30-second timeout produce a 502. It accepts
HTTP(S) destinations without URL-embedded credentials; it is not a WebSocket
upgrade server or a general TCP/UDP proxy.

The examples use port **19020**; Fragment defaults to **9020**. If the chosen
port is occupied, use another free port in both the proxy and launch command.

### 3. Launch your program

Open a second terminal in the extracted package directory. Replace the example
program and arguments with your target.

**Windows — PowerShell:**

```powershell
.\fragment.exe --version
.\fragment.exe --help
.\fragment.exe --proxy http://127.0.0.1:19020 --log debug --log-file fragment.log -- "C:\Path\To\program.exe" arg1
```

**Linux:**

```sh
./fragment --version
./fragment --help
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

A loaded library alone is not a successful redirect. For a controlled local test,
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

For Windows observation, the target must already have `FRAGMENT_MODE=observe`
and `FRAGMENT_CAPTURE_FILE` set to a new absolute path. Set
`FRAGMENT_SOCKET_DATA=1` there as well if raw bytes are wanted. The launcher
rejects `--observe` or `--socket-data` with `--pid`; it cannot apply those
settings retroactively. Attachment sees future supported calls, not earlier
traffic, and it does not recursively attach to helpers or children.

A newly launched Windows target of the same architecture stays suspended until
injection completes. The 64-bit-to-x86 bridge has to resume its target to locate
the remote loader, so early traffic can escape capture. Use the matching x86
launcher and DLL when startup coverage matters. This distinction also applies
when choosing a launcher for a proxy redirection test.

Attachment requires access to the target. Linux ptrace policy or target
protections can prevent it. The Linux attach implementation is for x86-64 and
AArch64; `audit` mode requires process startup. An injection failure is not
capture success; changing `--loader` does not provide an alternative injection
mechanism. To remove Fragment or change its settings, restart the target with
the desired environment. `--off` is a launch setting, not a command to disable
an already injected process.

## Finding networking code in loaded modules

Fragment does not assume that the main executable sends every request. On
Windows it first installs its module-load observer, then sweeps modules already
mapped into the process. Later loads go through the same backend discovery.
This covers a networking DLL present before injection as well as one loaded
later, subject to the selected loader strategy and hook compatibility.

For libcurl, Windows checks exports in each module, regardless of its filename.
An embedded curl may live in an application DLL whose name never mentions curl.
When exports are absent, Fragment tries known compiler-specific signatures only
if the module contains the relevant function-name marker. Conflicting candidates
and unsupported instruction relocation are refused. Finding a marker is not
enough to establish a working hook.

OpenSSL observation likewise checks loaded modules for its public API exports
instead of looking for a particular DLL filename. WinHTTP, Schannel, and Winsock
use their Windows API backends. The selected mode determines which backends are
installed: curl/WinHTTP for redirection, TLS/Winsock for observation.

The default Windows `auto` strategy uses the first mechanism that installs:
loader notifications, then `LdrLoadDll`, then `LoadLibraryA/W` detours. The first
two cover more load paths, including `LoadLibraryEx` and delay loading. The
legacy `LoadLibraryA/W` fallback misses loads made only through other entry
points. Notifications include dependency loads; the detour fallbacks inspect
the returned module and may miss newly loaded transitive dependencies. The
initial sweep remains enabled in every strategy; unload notifications are also
attempted so bookkeeping can retire stale module state.

Linux uses different discovery rules, described under [libcurl](#libcurl-backend).
A module scan cannot find traffic in another process, infer an unknown TLS ABI,
or make an unsupported function prologue safe to patch.

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
support), and unverified WebSocket/streaming redirection. TLS plaintext capture
is available separately in observation mode. Fixture success does not establish
compatibility with a particular third-party application.

## libcurl backend

Fragment rewrites `CURLOPT_URL`, `curl_url_set`, and `CURLOPT_CURLU` URLs before
connection setup. Rewriting is idempotent, so an already-prefixed URL is not
prefixed again. It neutralizes diversion through `RESOLVE`, `CONNECT_TO`, `PORT`,
Unix-socket options, `PROXY`, and `PRE_PROXY`, and removes inherited HTTP proxy
environment settings when enabled.

On **Windows**, discovery follows the [loaded-module scan](#finding-networking-code-in-loaded-modules)
above. `CURLOPT_CURLU` read-back needs URL API exports in the same module.

On **Linux**, the default combines symbol interposition with inline hooking.
The inline resolver reads ELF dynamic/static symbol tables before trying gated
signatures for stripped builds. That sweep currently considers the main
executable and object paths containing `curl`; it does not have Windows' broad
filename-independent embedded-library scan. Dynamic interposition is a separate
route. Later `dlopen` calls can trigger another search while curl has not yet
been hooked.

The available Linux strategies are `auto`, `interpose`, `audit`, and `hook`.
`audit` currently implements the 64-bit binding callback, requires startup
configuration, and cannot rebind function pointers that were already captured.
The `interpose` strategy relies on ordinary symbol resolution; explicit
`dlsym` lookups on a library handle can bypass it. Launching uses `LD_PRELOAD`
or `LD_AUDIT`; PID attachment uses ptrace to load the library. Preload
inheritance can affect Linux children,
but Fragment does not provide process-tree discovery or verify their coverage.

Unknown static builds remain best-effort. Fully static processes, custom socket
callbacks, and requests made through another networking library can fall outside
coverage. x86/x64 installation into a busy process retains documented
non-atomic patch limitations.

## TLS and socket observers

These backends run in Windows observation mode. They watch API calls and leave
the application's destination, data, and TLS verification in place.

**Schannel** captures data buffers before `EncryptMessage` changes them, then
records them only if the call succeeds. It records inbound buffers after a
successful `DecryptMessage`. Only contexts positively identified as Schannel
are accepted; Kerberos and NTLM contexts are excluded. Direct calls and tested
`InitSecurityInterfaceA/W` function-table calls, including tables obtained
before injection, reach the hooked dispatcher. Informational results such as
renegotiation and shutdown, readonly buffers, and control data are not ordinary
plaintext records.

**OpenSSL** captures successful `SSL_read` and `SSL_write`, plus `SSL_read_ex`
and `SSL_write_ex` when exported. It records the accepted byte count, including
partial writes, and avoids duplicate records when those entry points call each
other. Failed or retrying calls produce no successful payload record.
`SSL_free` and `SSL_clear` hooks are required to manage context lifetimes. Multiple
exported libraries and unload/reload generations are supported, with a limit of
32 module generations in one process; further generations remain unhooked.

OpenSSL support depends on the public exports and safely relocatable code.
Static or hidden OpenSSL/BoringSSL, `SSL_peek`, custom BIO-only paths, and newer
QUIC APIs are outside this backend. A required hook failure leaves the backend
inactive. For example, an OpenSSL 1.1 build tested from Git had an unsupported
`SSL_free` prologue, while tested OpenSSL 3.0 builds passed. A filename or library
version alone cannot establish compatibility.

**Winsock** observes `connect`, `WSAConnect`, `send`, `recv`, `sendto`, `recvfrom`,
`WSASend`, `WSARecv`, `WSASendTo`, `WSARecvFrom`, and `closesocket`. It records
numeric local/remote addresses without making DNS queries, distinguishes TCP
from UDP when known, and retains API status and socket errors. With
`--socket-data`, successful synchronous calls also retain raw payloads,
including scatter/gather buffers. `MSG_PEEK` and `MSG_OOB` calls are labelled
in metadata and excluded from ordinary raw payload records to avoid duplicating
peeked bytes or mixing urgent bytes into the stream.

Overlapped Winsock calls record submission and immediate outcome only.
Completion callbacks and IOCP completions are not traced, and asynchronous
buffers are never read for payload capture, even on immediate success. Socket
activity can therefore be present without a complete byte stream. Supported
synchronous send/receive calls on an accepted socket can be observed, but
there are no dedicated `accept`, `AcceptEx`, or `ConnectEx` hooks.

All three observers track context/socket lifetimes and retire IDs before
deallocation so recycled handles are not merged. A failed close/delete or a
reference-counted `SSL_free` may conservatively split an ID. TLS plaintext and
encrypted socket bytes can describe the same traffic; adding their byte counts
does not measure network usage. See [the observation guide](docs/observation.md)
for buffer bounds, capture ordering, and detailed test evidence.

## Configuration

Configuration is read once from the target's environment when Fragment loads.
Launcher flags set it for a new child. Use `--loader auto` unless diagnosing a
specific discovery problem.

| Launcher option | Purpose |
|---|---|
| `--proxy <url>` | Full proxy base for redirection. |
| `--host <host>`, `--port <port>` | Construct an HTTP proxy base when no full base is configured. |
| `--observe <new.jsonl>` | Windows: select observation and its output file. |
| `--socket-data` | Windows: add raw synchronous bytes to an observation capture. |
| `--log <level>`, `--log-file <path>` | Set diagnostics independently of the traffic capture. |
| `--loader <strategy>` | Select a discovery/interception strategy from the table below. |
| `--off` | Disable interception/capture for a newly launched target. |
| `--dll <path>` / `--so <path>` | Override the Windows DLL / Linux shared-library location. Otherwise use the library next to the launcher. |
| `--pid <pid>` | Attach to an existing process, using its existing environment. |
| `-h`, `--help` / `-V`, `--version` | Print available options / version. |
| `-- <program> [args...]` | End Fragment options and pass the remaining arguments to the target. |

The environment is also useful when an existing launcher or debugger loads
Fragment. Do not set observation variables globally unless every affected
process is intended to use them; captures require separate filenames.

| Variable | Meaning | Default |
|---|---|---|
| `FRAGMENT_PROXY` | Full proxy base; takes precedence over host/port variables. | Unset |
| `FRAGMENT_PROXY_HOST` | Proxy host when no full base is supplied. | `127.0.0.1` |
| `FRAGMENT_PROXY_PORT` | Proxy port when no full base is supplied. | `9020` |
| `FRAGMENT_ENABLED` | `0`, `false`, `no`, or `off` disables interception. | `1` |
| `FRAGMENT_DISABLE` | `1`, `true`, `yes`, or `on` disables interception, overriding `FRAGMENT_ENABLED`. | `0` |
| `FRAGMENT_LOG_LEVEL` | `off`, `error`, `warn`, `info`, or `debug`. | Release: `off`, or `info` when file/console output is requested. Debug: `debug`. |
| `FRAGMENT_LOG_FILE` | Diagnostic output path. Otherwise debugger output on Windows, stderr on Linux. | Unset |
| `FRAGMENT_LOG_CONSOLE` | `1` enables console output on Windows, or also sends diagnostics to stderr on Linux. | `0` |
| `FRAGMENT_LOADER` | Choose a platform-specific strategy below. | `auto` |
| `FRAGMENT_MODE` | Windows: `redirect` or `observe`. Invalid values fail DLL initialization when interception is enabled. | `redirect` |
| `FRAGMENT_CAPTURE_FILE` | Windows observation mode: new JSONL file path. Required for `observe`; no overwrite. Prefer an absolute path when setting it directly. | Unset |
| `FRAGMENT_SOCKET_DATA` | Windows observation mode: also record raw synchronous socket bytes. | `0` |

| Platform | Loader strategy | Behavior |
|---|---|---|
| Windows | `auto` | First available: loader notifications, `LdrLoadDll`, then `LoadLibraryA/W`. Always sweep already-loaded modules. |
| Windows | `notify` | Use loader notifications for later module discovery. |
| Windows | `ldrloaddll` | Hook the native DLL-load entry point. |
| Windows | `loadlibrary` | Legacy `LoadLibraryA/W` detours; misses other load entry points. |
| Linux | `auto` | Combine interposition with the inline curl resolver. |
| Linux | `interpose` | Use ordinary preload symbol interposition without the inline sweep; explicit library-handle symbol lookups can bypass it. |
| Linux | `audit` | Use `LD_AUDIT` symbol rebinding at startup; the implemented binding callback is 64-bit. |
| Linux | `hook` | Force inline curl hooking, including dynamic curl. |

Unknown loader values warn and fall back to `auto`. When interception is enabled,
invalid Windows mode values fail initialization rather than accidentally
enabling redirection. There is no
`--redirect` switch: redirection is the default; clear or set `FRAGMENT_MODE`
to `redirect` if it was inherited as `observe`. An inherited full
`FRAGMENT_PROXY` still takes precedence over `--host` and `--port`.

Use a well-formed HTTP(S) proxy base. Empty or scheme-less configuration can
fall back to the default; configuration validation is not a proxy reachability
check. Enable diagnostics and confirm the destination actually observed.

## Troubleshooting

### The proxy stays empty

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

### The capture is empty or incomplete

First check the launcher's result and diagnostics. A missing capture can mean
injection failed, observation was disabled, or the path could not be created.
An existing filename is deliberately refused. Invalid mode configuration does
not fall back to redirection.

If the file has only a session record, confirm that the intended process made
a new request and inspect hook diagnostics. A backend-ready record establishes
that observer's activation, not that every networking path is covered. Socket
rows without TLS payloads can mean an unsupported TLS implementation, a helper
process doing the TLS work, or traffic that did not use the hooked TLS APIs.
Raw bytes need `--socket-data` and supported synchronous socket calls.

For a local observation test, compare the exact binary request and response
with what the origin receives and sends, and check the target's exit status.
The origin should receive traffic normally in this mode. Compare bare and
`--off` runs: both should still communicate and neither should create a capture.
Check gaps, truncation, and asynchronous outcomes before treating a stream as
complete. When the viewer rejects a file, keep the original JSONL and inspect
the reported error; a crash or disk failure may have left a partial last record.

Use the [verification notes](docs/verification.md) to distinguish tested fixture
behavior from application observations. The [agent guide](AGENTS.md) walks
through setup and diagnosis for both source and downloaded copies.

## Building from source

Run from the repository root.

**Windows:** Visual Studio C++ tools with a C17-capable compiler and CMake 3.24
or newer. The script discovers the x64 toolchain and uses bundled Visual Studio
CMake/Ninja tools when available.

```powershell
cmd /c windows\build.bat
# Optional: cmd /c windows\build.bat Debug
```

The script builds x64. With a Visual Studio generator, an isolated x86 build is:

```powershell
cmake -S windows -B windows/build/x86 -A Win32
cmake --build windows/build/x86 --config Release
```

Use `-A ARM64` and a separate directory for ARM64, with the corresponding
toolchain installed. Each build produces its own `fragment.exe` and
`Fragment.dll`; keep the matching pair together. To use the 64-bit-to-x86
bridge, copy the x86 DLL next to the x64 launcher as `Fragment32.dll`, or select
it with `--dll`. A multi-configuration generator puts binaries under `Release/`
or `Debug/`; Ninja normally puts them directly in the build directory.

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
The CI workflow includes Windows x64/x86/ARM64, WOW64 injection, and Linux
x64/ARM64. An engine implementation, a configured CI job, a locally verified
build, and a published package are different things. See the validation notes
for what was actually exercised. If a build cache references a removed compiler,
use a fresh build directory or remove only its generated cache.

## Testing

Native fixtures are C; new orchestration uses Bun. From a source checkout,
using the default Ninja output layout for the Windows commands:

```sh
bun install --frozen-lockfile
bun run typecheck
bun test ./test

# On Windows:
bun windows/test/run.ts                  # Builds x64 binaries/fixtures; engine and mock tests run first
bun windows/test/run_winhttp.ts --no-build
bun run test:observe                     # Uses the already-built observation fixtures

# On Linux:
bun linux/test/run.ts
```

The curl, WinHTTP, Schannel, network, and OpenSSL runners build the library and
fixtures unless given `--no-build`. The aggregate `test:observe` script and
`run_capture.ts` do **not** build: run the Windows matrix first as above, or build
explicitly with `cmd /c windows\build.bat` and
`cmd /c windows\test\build_test.bat`. These batch scripts select x64.

Redirection tests use **19020, 19021, and 19999**. Stop a demo proxy you started
on one of those ports, or resolve the conflict, before running them. Observation
integrations use dynamically allocated loopback ports. Missing optional fixtures
are SKIP; a missing required fixture is a failure. Engine, mock curl, WinHTTP,
Schannel, socket, and mock OpenSSL tests need no downloaded curl/OpenSSL corpus.
Linux integration uses system curl/libcurl.

Windows accepts repeatable `--libcurl <dll>` and `--curl <exe>` arguments:

```powershell
bun windows/test/run.ts --libcurl "C:\Program Files\Git\mingw64\bin\libcurl-4.dll"
bun windows/test/pe.ts path/to/libcurl.dll curl_easy_setopt curl_url_set
bun windows/test/verify_sigs.ts path/to/libcurl.dll
```

The Windows runner also accepts `FRAGMENT_TEST_BUILD` for isolated build output
when using `--no-build`. For a multi-configuration build, point this at the
directory containing the actual executables, fixtures, and DLL, not its parent.
The WinHTTP and observation runners also accept `FRAGMENT_TEST_DLL` to select a separate
Fragment DLL. `bun test windows/test/launcher.test.ts` checks argument forwarding
using the built `host_args.exe`. When a curl DLL depends on sibling DLLs, put
its directory on the test process's `PATH` so relocated embedded fixtures can
load them too.

With a Visual Studio generator, the library and launcher land under `Release/`
while `build_test.bat` puts fixtures in `windows/build/`. After building both,
stage the matching pair alongside the fixtures before using the runners:

```powershell
Copy-Item windows/build/Release/Fragment.dll windows/build/Fragment.dll
Copy-Item windows/build/Release/fragment.exe windows/build/fragment.exe
bun windows/test/run.ts --no-build
bun windows/test/run_winhttp.ts --no-build
bun run test:observe
```

The observation suite covers the binary JSONL sink, Schannel, Winsock, and
OpenSSL. Tests check exact binary request/response bytes, negative controls,
already-loaded and later-loaded modules, multiple OpenSSL libraries and reloads,
partial transfers, buffer bounds, lifecycle reuse, and failure paths. Shared
Bun tests also validate the capture parser and escaped offline report.
The TLS certificate and key under `windows/test/fixtures` are public local-test
fixtures; no machine certificate-store changes are needed.

Real OpenSSL integration is optional and requires a DLL matching the fixture
architecture, with its dependencies available:

```powershell
bun windows/test/run_openssl.ts --no-build --libssl "C:\Path\To\libssl-3.dll"
```

Alternatively, set `FRAGMENT_TEST_OPENSSL` before `bun run test:observe`.
Without a real DLL, those checks report SKIP while the native state and exported
mock-library tests still run. An explicitly supplied missing DLL is an error.
You can run `run_capture.ts`, `run_schannel.ts`, `run_network.ts`, or
`run_openssl.ts` individually under `windows/test/`.

For x86 or ARM64 observation fixtures, enter a developer command prompt for
that architecture and run `windows\test\build_observe.bat <output-directory>`.
Unlike `build_test.bat`, this helper keeps the active compiler architecture.
Build Fragment separately, place the fixtures alongside the matching binaries,
set `FRAGMENT_TEST_BUILD`, and run with `--no-build` (or `bun run test:observe`).
The helper does not build the complete engine/curl fixture set; use the CI
workflow as the reference for a full alternate-architecture run.

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
| `windows/` | DLL lifecycle, module discovery, curl redirection, hook engine, and configuration. |
| `windows/winhttp.h` | WinHTTP handle tracking and redirection. |
| `windows/schannel.h`, `windows/openssl_capture.h`, `windows/network.h` | TLS and socket observers. |
| `windows/capture.h` | Bounded binary JSONL writer and observation session state. |
| `windows/tools/fragment.c`, `linux/tools/fragment.c` | Launch/attach tools. |
| `windows/test/`, `linux/test/` | Native fixtures and platform test runners. |
| `linux/` | Shared library, launcher, interposition/audit/hook support, and Linux fixtures. |
| `tools/proxy.ts` | Optional Bun forwarding proxy. |
| `tools/observe.ts` | Capture validation and self-contained HTML viewer. |
| `test/` | Shared Bun harness, binary/signature tools, and tooling tests. |
| `docs/observation.md` | Observation coverage, JSONL format, limits, and validation. |
| `docs/verification.md`, `docs/regression-validation.md` | Recorded validation results and boundaries. |
| `AGENTS.md` | Practical usage flow and contributor instructions for agents. |
| `BRIEF.md` | Multi-backend roadmap. |

## License

See [LICENSE](LICENSE). Use Fragment only on software and systems you are
authorized to analyze.
