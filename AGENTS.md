# Using and working on Fragment

Fragment is a C17 library and launcher for debugging traffic from a selected
process. It has two separate modes:

- **Redirect:** Windows and Linux rewrite supported libcurl calls; Windows also
  redirects WinHTTP. An operator-provided proxy receives `/<original-url>`.
- **Observe:** Windows preserves the target's connections and writes local JSONL
  containing supported TLS plaintext and Winsock activity. Raw synchronous socket
  bytes are optional. Observation needs no proxy.

Use the actual checkout, launcher `--help`, and runtime evidence as the authority.
Loading Fragment, installing hooks, observing calls, and verifying traffic at an
endpoint are separate claims. A successful fixture does not prove that an
arbitrary application, child process, protocol, or library build is covered.
`BRIEF.md` is a roadmap. New source features are not necessarily in published
releases. See [README.md](README.md) for the product overview and
[docs/observation.md](docs/observation.md) for the capture format and limitations.

## Help someone use Fragment

### Identify the target and choose a mode

Inspect the host OS, target executable and architecture, the process actually
sending traffic, source checkout versus extracted package, and available proxy
before asking for missing details. If the agent cannot run commands on the
user's machine, give commands for their shell and explain what evidence to check.

Use redirect mode when the target uses supported libcurl or WinHTTP and the user
wants requests to pass through a compatible proxy. Use Windows observation when
the user wants to inspect supported TLS or socket activity while retaining the
original destination, TLS validation, and proxy settings. Do not combine the
modes or assume observing TLS provides HTTP redirection.

| Target behavior | Current coverage |
| --- | --- |
| libcurl HTTP requests | Windows/Linux redirection through supported URL APIs; exports, ELF symbols, and guarded signature paths have different coverage. |
| WinHTTP requests | Windows redirection of connections opened after hooks install. |
| Schannel TLS | Windows observation of successful SSPI encryption/decryption after positive Schannel identification. |
| Exported OpenSSL TLS | Windows observation through public `SSL_read`/`SSL_write` APIs and available `_ex` variants, subject to hook installation. |
| TCP/UDP through hooked Winsock APIs | Windows call activity, endpoints, outcomes, and synchronous byte counts; optional raw synchronous payloads. |
| HTTP/2, gRPC, WebSocket, or a custom TLS protocol | Bytes may be visible through a supported TLS backend; Fragment does not decode these protocols. |
| WinINet, Chromium/CEF/Electron, Go, Rust, Java, NSS, or another stack | No blanket application or plaintext support. A process may still expose observable Schannel, OpenSSL, or Winsock calls. Verify the actual backend. |
| QUIC, direct AFD, Winsock extension APIs, RIO, kernel traffic, or other IPC | No complete backend. UDP activity is not decrypted QUIC; pipes/shared memory are not covered. |
| Linux observation or macOS | No implementation. Linux currently redirects curl; macOS is documentation only. |

Identify the networking process rather than assuming it is the visible parent.
Fragment does not automatically discover and inject child processes. Same-bitness
Windows launches remain suspended until injection finishes. The 64-bit launcher
can inject an x86 DLL into an x86 target, but that bridge resumes startup to find
the target loader; use a matching x86 launcher/DLL when startup capture matters.
Linux descendants may inherit `LD_PRELOAD` or `LD_AUDIT` and load Fragment again
unless the environment is cleared; this inheritance is not guaranteed discovery
or coverage of every child process.

### Obtain a matching build

- A checkout contains `windows/`, `linux/`, and `tools/proxy.ts`.
- A Windows package contains `fragment.exe` and `Fragment.dll`; keep them
  together. The x64 package does not supply `Fragment32.dll`. Cross-bitness
  injection needs a separately built x86 DLL, supplied with `--dll` or placed
  beside the x64 launcher under that name.
- A Linux package contains `fragment` and `libfragment.so`; keep them together
  and match the target architecture.
- Check actual assets at
  [the releases page](https://github.com/ObscuritySRL/fragment/releases).
  An engine architecture or packaging rule in source does not prove an existing
  downloadable release supports it. Inspect that release's `--help` before
  suggesting observation flags.

Prefer an existing matching release for ordinary use when it has the needed
feature. A release needs no compiler. Bun is needed for the included proxy,
offline viewer, and development scripts; native launch/injection itself does not
need Bun. The proxy and viewer can run without `bun install`.

For a source build, run only the host platform's build from the repository root:

```powershell
# Windows x64: Visual Studio C++ tools and CMake
cmd /c windows\build.bat
.\windows\build\fragment.exe --help
```

```sh
# Linux: a C compiler; the script uses CMake when available
bash linux/build.sh
./linux/build/fragment --help
```

The Windows script discovers Visual Studio with `windows/find_vcvars.bat` and
uses Ninja when available. A Visual Studio multi-configuration build puts
artifacts in `windows/build/Release/` or `Debug/`; inspect the actual output and
adjust commands. The Windows helper selects x64. For x86/ARM64, use CMake with
the matching toolchain as described under development below. Native fixtures
and TypeScript development dependencies are not prerequisites for a normal run.

### Redirect through a proxy

Start a compatible proxy first and leave it running in a separate terminal:

```sh
bun tools/proxy.ts 19020
```

The port must be free. Choose another consistently if occupied; do not stop an
unrelated service to take its port. Fragment defaults to port 9020, while these
examples explicitly select 19020.

The proxy contract is a request such as `GET /https://example.com/path`. The
proxy extracts the original URL, forwards the method/body, and relays the
response. This is not conventional HTTP CONNECT or SOCKS configuration. The
included loopback proxy supports HTTP/HTTPS destinations, removes hop-by-hop
headers, and keeps upstream redirects on the proxy. It prints method, URL, and
status; it is not a persistent body recorder or a general protocol proxy. Use a
recording proxy when the user needs stored HTTP payloads. The launcher does not
start the proxy.

Older archives, including v1.2.0, omit the proxy script and this guide. Obtain
the script from the matching repository tag or use a compatible existing proxy;
do not give a command for a missing file without explaining how to obtain it.

From a Windows package directory, in PowerShell:

```powershell
.\fragment.exe --version
.\fragment.exe --help
.\fragment.exe --proxy http://127.0.0.1:19020 --log debug --log-file fragment.log -- "C:\Path\To\program.exe" arg1
```

From a Linux package directory:

```sh
./fragment --version
./fragment --help
./fragment --proxy http://127.0.0.1:19020 --log debug --log-file fragment.log -- /path/to/program arg1
```

Substitute the built launcher path when using a checkout. Everything after `--`
belongs to the target. Keep its required working directory; invoke Fragment by
absolute path when needed. Prefer absolute log paths. Use `curl.exe` explicitly
in PowerShell, and verify the particular curl build rather than assuming its
name implies compatibility.

### Observe Windows TLS and sockets

With a current source build:

```powershell
.\windows\build\fragment.exe --observe capture.jsonl --log debug --log-file fragment.log -- "C:\Path\To\program.exe" arg1
bun tools/observe.ts capture.jsonl --out capture.html
```

Choose a new capture filename for every run. The launcher resolves it against
its working directory, and its parent directory must already exist. Fragment
creates the capture exclusively and never appends to or overwrites an existing
file. If capture initialization fails, the DLL fails to load. The launcher
terminates its newly launched observation target when injection fails rather
than silently letting it run unobserved.

By default, the file contains supported TLS plaintext and socket activity
metadata. Add `--socket-data` when raw synchronous TCP/UDP bytes are needed:

```powershell
.\windows\build\fragment.exe --observe raw.jsonl --socket-data -- "C:\Path\To\program.exe"
bun tools/observe.ts raw.jsonl --out raw.html
```

Raw socket bytes may be ciphertext. TLS and socket data are separate views of
activity, so do not sum their lengths as total network usage. Socket IDs and TLS
context IDs are not automatically correlated. UDP chunks retain datagram
boundaries; one UDP socket may contact multiple peers. TCP/TLS chunks are API
observations, not application messages, packets, or guaranteed wire ordering.

The viewer is a self-contained offline HTML file with filters, endpoints,
outcomes, text/hex payload views, and individual chunks. Payload text is not
executed. It does not parse HTTP/2 framing, HPACK, gRPC, WebSocket frames, DNS, or
custom protocols. It rejects malformed records, sequence gaps, and files larger
than 128 MiB; it displays up to 2,000 filtered network rows while the JSONL
retains all records. The output HTML must also be a new file.

Captures and reports may contain credentials, cookies, URLs, and application
data. Keep them local to the intended debugging workflow and out of commits.
Capture writes are synchronous and can affect timing. Payload snapshots are
bounded to 1 MiB with explicit truncation, but the file has no total-size cap or
rotation; use a bounded recording period. A write failure stops capture and
emits a debugger diagnostic independently of the normal log level, while the
target continues. A crash
or full disk can leave an incomplete final record. Absence of a gap record is
not proof of complete capture or successful disk writes.

### Configuration and attachment

Configuration is read once when the library loads. Launch flags set environment
variables inherited by the new target; unspecified values may already be in the
launcher's environment. Changing the shell later does not reconfigure an
injected process. Check inherited settings when behavior differs from defaults.

| Setting | Flag/environment | Behavior |
| --- | --- | --- |
| Proxy base | `--proxy`, `FRAGMENT_PROXY` | Full base URL; overrides host/port fallback. Default `http://127.0.0.1:9020`. |
| Proxy host/port | `--host`, `--port`; `FRAGMENT_PROXY_HOST`, `FRAGMENT_PROXY_PORT` | Used when `FRAGMENT_PROXY` is unset. |
| Windows mode | `--observe <file>`; `FRAGMENT_MODE=observe`, `FRAGMENT_CAPTURE_FILE` | Default mode is `redirect`; capture is required for observe. Unknown modes fail initialization when enabled. |
| Raw Windows socket bytes | `--socket-data`, `FRAGMENT_SOCKET_DATA=1` | Opt-in synchronous raw capture in observe mode. |
| Disable | `--off`, `FRAGMENT_ENABLED=0`, `FRAGMENT_DISABLE=1` | Disables rewriting/hooks/capture; `FRAGMENT_DISABLE` overrides enabled. No observation file is created. |
| Diagnostic level | `--log`, `FRAGMENT_LOG_LEVEL` | `off`, `error`, `warn`, `info`, `debug`. Release logging is off unless enabled by configuration. |
| Diagnostic file | `--log-file`, `FRAGMENT_LOG_FILE` | Without a file, Windows uses debugger output and Linux uses stderr. A file enables default info logging unless an explicit level overrides it. |
| Diagnostic console | `FRAGMENT_LOG_CONSOLE=1` | Windows allocates a console; Linux can tee file logging to stderr. |
| Loader strategy | `--loader`, `FRAGMENT_LOADER` | Platform-specific values described below; normally leave `auto`. |
| Injected library | Windows `--dll <path>`; Linux `--so <path>` | Select a matching library instead of the one beside the launcher. |

Observation, including inherited observation mode, rejects explicit
proxy/host/port flags. `--socket-data` requires
observation selected by the flag or inherited `FRAGMENT_MODE=observe`. There is
no `--redirect` flag: unset `FRAGMENT_MODE` or set it to `redirect` before a new
launch to override inherited observation configuration. Enabled redirection
scrubs conventional proxy environment settings and neutralizes supported
per-request routing options; observation leaves those settings intact.

For attachment, confirm the actual PID, then use `.\fragment.exe --pid 1234` or
`./fragment --pid 1234`. Attachment uses the target's existing environment.
`--proxy`, `--log`, and similar flags cannot update it; Windows rejects
`--observe`/`--socket-data` with `--pid`. To observe an existing Windows process,
it must already have `FRAGMENT_MODE=observe` and a suitable
`FRAGMENT_CAPTURE_FILE` in its environment before injection, with
`FRAGMENT_SOCKET_DATA=1` if wanted. Prefer launching with the desired settings
when that environment was not prepared.

Attachment cannot recover earlier traffic, and preexisting WinHTTP connections
lack origin metadata and pass through. Linux attachment may be restricted by
ptrace policy; diagnose the actual error rather than automatically weakening
system policy. Linux audit mode is launch-only because `LD_AUDIT` must be present
at startup. To stop using Fragment, restart the target normally with Fragment
configuration removed. Stopping only a redirection proxy leaves requests failing.

## How discovery and capture work

### Windows module discovery

Fragment installs the selected loader mechanism and sweeps modules already
loaded in the process. Each eligible module is checked for the selected mode's
backends. It also checks later modules reported through the selected loader
mechanism; this is not a one-time scan and is not a polling system-wide monitor.

`auto` chooses the first available mechanism: `LdrRegisterDllNotification`, then
an `LdrLoadDll` detour, then legacy `LoadLibraryA/W` detours. These are fallbacks,
not three simultaneous discovery layers. Forced values are `notify`,
`ldrloaddll`, and `loadlibrary`. The initial sweep remains in every mode, and
Fragment attempts unload notification bookkeeping to retire module ownership.
Notification-based discovery sees normal loader image notifications, including
dependencies. The `LdrLoadDll` fallback sees the returned module rather than
every transitive dependency; legacy `LoadLibraryA/W` also misses paths through
`LoadLibraryEx`. A forced mode can reduce coverage.

Curl lookup checks exports in scanned modules without requiring a curl DLL
filename. If exports are absent, the static/embedded curl path requires a curl
function-name marker and a recognized compiler signature. Ambiguous matches or
instructions the engine cannot relocate are rejected. This is guarded support
for some embedded builds, not arbitrary static-library detection. Curl's parsed
URL-handle support also needs the associated URL get/set/free functions from
the same module. Redirect hooks preserve idempotency and supported URL updates
while neutralizing routing options such as proxy, custom resolution, connect-to,
port, and Unix-socket overrides that could bypass the selected proxy.

WinHTTP tracks session/connection/request ownership through its supported public
API hooks and reconstructs the original URL when a request opens. Its backend
requires all five hooks to install. A loaded DLL alone does not prove this state
machine is active, and a connection opened before injection is not retroactively
known.

### Linux curl discovery

`auto` combines symbol interposition with inline hooking of resolved curl
functions. Forced modes are `interpose`, `hook`, and startup-only `audit`.
`interpose` uses ordinary preload symbol interposition; it does not install a
`dlsym` detour or perform the later `dlopen` inline sweep. The current audit
implementation exports `la_symbind64`, not `la_symbind32`; do not infer 32-bit
audit support from the presence of 32-bit hook-engine backends.
The inline sweep first checks ELF `.dynsym`/`.symtab` entries, then a guarded
signature fallback. It considers the main executable and object paths containing
`curl`; it does not search every arbitrarily named plugin as Windows does.
Stripped static code without the required loaded marker remains unsupported.

The `dlopen` interposer can trigger another sweep while curl has not yet been
hooked. It stops that search after a successful setopt hook, so do not promise
continuous discovery of all later independent curl copies. Audit intercepts
loader symbol bindings; it does not retroactively rebind previously captured
function pointers. Fully static binaries, unusual namespaces/load paths, and
unsupported instruction sequences need explicit evidence rather than a generic
compatibility claim.

### Windows observation backends

- **Schannel:** Hooks dispatcher exports in `sspicli.dll`, including calls made
  through cached SSPI A/W function tables. It identifies the context's security
  package before treating buffers as TLS plaintext; generic SSPI use such as
  NTLM is not captured as Schannel. Outbound data is snapshotted before
  encryption and emitted only on success; inbound plaintext is read after
  successful decryption. Capture requires `SEC_E_OK`; informational
  renegotiation/shutdown statuses are conservatively omitted.
- **OpenSSL:** Scans for the required local public exports in any module name.
  It observes `SSL_read`, `SSL_write`, and available `SSL_read_ex`/`SSL_write_ex`,
  using actual successful byte counts. Required `SSL_free` and `SSL_clear`
  lifecycle hooks keep reused SSL pointers separate. There is no private-layout
  guessing, static OpenSSL signature scan, or blanket BoringSSL compatibility.
  `SSL_peek`, custom BIO-only paths, and
  newer QUIC APIs are not covered. Required hooks must all relocate successfully;
  finding exports is insufficient. Module-generation slots are bounded to 32;
  later unsupported generations remain unhooked with a diagnostic.
- **Winsock:** Hooks exports in `ws2_32.dll`: `connect`, `WSAConnect`, `send`,
  `recv`, `sendto`, `recvfrom`, `WSASend`, `WSARecv`, `WSASendTo`, `WSARecvFrom`,
  and `closesocket`. It records socket lifetime IDs, transport when known,
  numeric IPv4/IPv6 endpoints, outcomes, errors, and measured byte counts.
  It does not hook `ConnectEx`, `AcceptEx`, RIO, raw AFD, completion ports, or
  completion callbacks. DNS handled by a separate service is outside the
  selected process.

Pending calls are submissions, not completed traffic. `pending` covers accepted
overlapped work and nonblocking connection attempts that are still in progress;
`would-block` means a data call could not proceed; `failed` preserves the error.
`completed-unmeasured` covers immediate overlapped completion or a successful
synchronous WSA call whose output count cannot safely be read. Its zero bytes
mean unknown, not a zero-byte transfer.

Asynchronous payloads are never inspected, even when submission returns success,
because a completion thread can already have reused those buffers. Optional raw
capture reads only successful synchronous operations and their actual accepted
counts. `MSG_PEEK` and `MSG_OOB` calls are labeled in activity records and omitted
from raw payloads to avoid duplicate/urgent bytes in ordinary streams.

Capture records are versioned JSONL. `session` proves sink initialization;
`backend` readiness is emitted lazily outside loader callbacks; `data` carries
base64 bytes, direction, captured/original lengths, and truncation; `network`
carries call metadata; `gap` reports an omission when the sink still works.
Connection IDs represent observed lifetimes rather than requests. Closing,
deleting, or freeing a handle retires its identity before provider release so
reuse cannot merge unrelated streams; a failed close/delete or retained OpenSSL
reference may conservatively split an identity. See the observation guide for
the full schema and interpretation rules.

## Verify behavior and troubleshoot

Check separate layers, using a controlled local fixture when possible:

1. **Library loaded:** launcher/module-list evidence. Attachment success alone
   says nothing about hook installation or traffic.
2. **Backend active:** diagnostic `[hook]` entries, WinHTTP's
   `[winhttp] backend ready`, or the relevant observer readiness record/log.
   Observation readiness records are lazy; an empty session is not a traffic
   test. An unsupported prologue may deliberately leave a backend inactive.
3. **Expected behavior:** for redirection, the proxy sees the expected original
   URL/method/body and the origin receives no direct bypass. For observation,
   the original endpoint receives unchanged data and the capture matches known
   bytes/outcomes at the relevant layer. Check target response and exit status.

Compare a bare run and a fresh launch with `--off` before `--`. They must bypass
rewriting/capture. `--off` cannot disable a library already loaded in another
process. For observation, also compare metadata-only and `--socket-data` runs
where relevant, and distinguish TLS plaintext from raw encrypted transport.

For an empty proxy, check reachability/port, injected path and architecture,
hook diagnostics, actual stack and PID, and whether the connection predates
injection. For an empty or partial capture, also check the selected mode,
disable variables, new writable output path, backend readiness, unsupported or
asynchronous APIs, gap/truncation records, and disk-write diagnostics. More
permissive signatures or disabled TLS validation are not coverage fixes.

The self-contained WinHTTP suite is `bun windows/test/run_winhttp.ts`; curl
matrices are `bun windows/test/run.ts` and `bun linux/test/run.ts`. After building
fixtures, `bun run test:observe` checks native observer state and local traffic.
Optional third-party fixtures may be SKIP; mandatory fixtures must fail when
missing. Existing HTTP suites use ports 19020, 19021, and 19999. Stop a demo
proxy you started on those ports or resolve the conflict before testing; do not
kill unrelated services.

## Repository map

- `common/arch/`: shared instruction decoders and relocation helpers.
  `common/curl_abi.h` defines curl option IDs. Changes can affect several OSes.
- `windows/main.c`: DLL lifecycle, module discovery, curl resolution, and hook
  registration. `windows/winhttp.h`: WinHTTP ownership and redirection.
- `windows/schannel.h`, `windows/openssl_capture.h`, `windows/network.h`:
  observation backends. `windows/capture.h`: binary-safe JSONL sink.
- `windows/config.h`, `linux/config.h`: environment configuration and logging.
  `windows/util.h`, `linux/util.h`: platform helpers and URL rewriting.
- `windows/hook.h`, `linux/hook.h`: platform hook engines.
- `windows/tools/fragment.c`, `linux/tools/fragment.c`: launch/attach tools.
- `linux/main.c`: interposition, audit, ELF resolution, and inline hooking.
- `tools/proxy.ts`: forwarding proxy. `tools/observe.ts`: capture parser and
  offline HTML viewer. `test/`: Bun tooling tests and shared test harness.
- Platform `test/` directories: native fixtures and integration runners.
  `.github/workflows/`: build/test/release matrices, not proof a job has run.

## Development and validation

Use Bun for new TypeScript tooling and tests. Prefer `Bun.spawn`, `Bun.file`,
`Bun.write`, `Bun.Glob`, `Bun.serve`, and `bun:test` over Node APIs. Do not add
Node, npm, tsx, or Python dependencies to new tooling. Existing Python scripts
are legacy comparison/reference tools until their coverage is ported. Native
libraries and fixtures remain C; Bun orchestrates them.

For tooling changes:

```sh
bun install --frozen-lockfile
bun run typecheck
bun test ./test
```

For Windows x64, build the DLL/launcher and native fixtures, then run the engine
and mock checks before interpreting higher-level integration results:

```powershell
cmd /c windows\build.bat
cmd /c windows\test\build_test.bat
```

When the core build uses Visual Studio rather than Ninja, its DLL/launcher are
in `windows/build/Release/`, but `build_test.bat` puts fixtures in `windows/build/`.
Before running the suites, stage the matching core artifacts with the fixtures:

```powershell
# Only for that Release subdirectory layout; use Debug if that was built.
Copy-Item .\windows\build\Release\Fragment.dll .\windows\build\Fragment.dll
Copy-Item .\windows\build\Release\fragment.exe .\windows\build\fragment.exe
```

Then run:

```powershell
bun windows/test/run.ts --no-build
bun windows/test/run_winhttp.ts --no-build
bun run test:observe
```

`run.ts` includes launcher, engine, WinHTTP state, mock-curl, loader/reload, and
available real-curl checks. `test:observe` runs capture-sink, Schannel, Winsock,
and OpenSSL suites; these include mandatory native state tests and local
integration controls. The observer aggregate expects fixtures already built.
Individual Schannel/network/OpenSSL/WinHTTP runners can build unless passed
`--no-build`; `run_capture.ts` requires its existing fixture.

Real OpenSSL integration is optional unless a library is explicitly provided:

```powershell
bun windows/test/run_openssl.ts --no-build --libssl "C:\Path\To\libssl-3-x64.dll"
```

Use a matching architecture and its runtime dependencies. `FRAGMENT_TEST_OPENSSL`
is an alternative. Native/mocked OpenSSL checks still run without this library;
report a missing real-library case as SKIP. Curl's Windows matrix similarly
uses a local corpus or explicit `--libcurl`/`--curl` fixtures. Do not commit
downloaded binaries or infer support for other versions from a passing one.
The certificates/keys under `windows/test/fixtures/` are deliberately public
local test material; tests do not install a trust certificate into the user's
certificate store.

For multi-configuration or alternate-architecture Windows builds, keep artifacts
isolated. CMake's Visual Studio generator accepts `-A x64`, `-A Win32`, or
`-A ARM64`; select a fresh build directory instead of reusing an incompatible
cache. `build.bat` and `build_test.bat` select x64. In a matching MSVC developer
environment, `windows/test/build_observe.bat <output-directory>` honors that
environment's architecture. Put observer fixtures alongside the matching DLL
and launcher, set `FRAGMENT_TEST_BUILD` to that directory, and use `--no-build`
or the observer aggregate. Observer and WinHTTP runners also accept
`FRAGMENT_TEST_DLL` when the DLL is elsewhere; the main curl matrix expects it
in the selected build directory. Do not accidentally rebuild x86/ARM64 fixtures
with the x64 helper. Follow CI's explicit engine/mock compile steps for those
architectures.

On Linux:

```sh
bash linux/build.sh
bash linux/test/build_test.sh
bun linux/test/run.ts --no-build
```

The fixture build can run self-contained engine/mock tests without real libcurl;
real integration needs the development library. Cross-built engine/mock subsets
and QEMU jobs do not prove native application compatibility. CI covers additional
architectures; inspect its actual results and report untested platforms honestly.
If an old CMake cache names a removed compiler, reconfigure in a fresh directory
or clear only generated cache files. Do not remove unrelated files to repair a
build.

## Correctness boundaries

- Fail closed on unsupported relocation or ambiguous symbols. Never weaken a
  decoder, symbol-owner check, or signature gate just to make a target hook.
- Preserve URL rewrite idempotency, configuration, disable switches, option
  neutralization, and the `/<original-url>` contract. Observation must retain
  original destinations, proxy settings, application buffers, return statuses,
  and error state.
- Detours can run concurrently. Publish original function pointers before a
  hook becomes callable; do not hold runtime state locks across provider calls.
  Keep per-module generations and handle identities distinct during unload and
  reuse. Do not retire new state with delayed cleanup from an old handle.
- Do not call arbitrary loader APIs under loader notifications. Do not free
  remote injection arguments while their thread is still running. Respect the
  existing ownership and trampoline lifetime design.
- Treat target buffer pointers as fallible. Bound snapshots, descriptors, maps,
  and module slots; preserve accepted counts and truncation/gap semantics. Never
  read pending/overlapped receive buffers or describe submission as completion.
- Do not equate observed API chunks with packets, decoded requests, or complete
  protocol coverage. Keep TLS plaintext, raw socket bytes, and metadata separate.
- Verify at local endpoints with exact path/method/body or binary data, target
  exit status, and expected routing. Include bare/disabled controls and relevant
  failures, concurrency, reuse, delayed loading, and unload cases. Missing
  fixtures are SKIP or a mandatory-fixture error, never PASS.
- Run engine/mock checks before real-library integration; run the relevant
  observer/native/viewer checks for observation changes. Broaden testing when
  failures or changed shared code justify it, and state what was not tested.

## Change discipline

Read `git status` first and preserve unrelated modified and untracked user files.
Keep machine-specific binaries, downloaded corpora, logs, secrets, and captured
traffic out of commits. Update README, this guide, observation documentation,
and CI when commands or coverage change. Review the diff and run relevant checks
before committing; merge only when the user requested it and required checks
pass. Report the actual verified behavior and remaining gaps without claiming
universal application compatibility.
