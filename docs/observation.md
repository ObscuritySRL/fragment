# Windows traffic observation

Fragment has two separate modes. Redirection rewrites supported libcurl and
WinHTTP requests to `/<original-url>` at an operator proxy. Observation records
what a process does while retaining its destinations, TLS validation and proxy
settings. Observation is currently Windows-only.

```powershell
# From the repository; build with cmd /c windows\build.bat first.
.\windows\build\fragment.exe --observe capture.jsonl --log debug --log-file fragment.log -- "C:\Path\To\program.exe"
bun tools/observe.ts capture.jsonl --out capture.html

# Also retain raw synchronous socket bytes (for plain HTTP, DNS, custom protocols).
.\windows\build\fragment.exe --observe raw.jsonl --socket-data -- "C:\Path\To\program.exe"
```

The launcher resolves the capture path against its working directory. Every run
requires a new filename; directories must already exist. Failure to initialize
capture fails DLL loading, and the launcher stops its newly created observation
target on injection failure. A same-architecture target remains suspended until
injection completes. The existing 64-bit-to-x86 launch bridge resumes the target
to discover its loader, so startup coverage for that path is not guaranteed;
use a matching x86 launcher/DLL when capturing from startup is essential.

Neither mode automatically follows children. Inspect the process doing the
networking, including an application's separate network helper. Attachment
requires `FRAGMENT_MODE=observe` and `FRAGMENT_CAPTURE_FILE` in the target's
existing environment, set before it started. Optional `FRAGMENT_SOCKET_DATA=1`
enables raw bytes. `FRAGMENT_ENABLED=0` or `FRAGMENT_DISABLE=1` disables all
observers and produces no capture. Settings are read once at DLL load time.

## Coverage by communication layer

| Application communication | Available observation | Limits |
|---|---|---|
| Schannel TLS, through SSPI | Outbound plaintext before encryption; inbound plaintext after successful decryption | Only positively identified Schannel contexts. `SEC_E_OK` only; informational renegotiation/shutdown results excluded. Tested direct exports and cached A/W security-function tables. |
| Dynamically exported OpenSSL TLS | Successful `SSL_read`, `SSL_write`, and available `_ex` calls, including partial writes | Exported public ABI only. No guessed private layouts or static signatures. `SSL_peek`, custom BIO-only access, static OpenSSL/BoringSSL and newer QUIC APIs are not covered. |
| TCP sockets | Endpoint addresses, API result, synchronous byte counts; optional raw bytes | `connect`, `WSAConnect`, `send`, `recv`, `WSASend`, `WSARecv`, `closesocket`. Raw bytes may be ciphertext. |
| UDP / DNS / custom datagrams | Endpoints, result/count for `sendto`, `recvfrom`, `WSASendTo`, `WSARecvFrom`; optional raw synchronous datagrams | Observe datagram chunks separately; one socket can address multiple peers. System DNS service traffic can occur in another process. |
| HTTP/1, HTTP/2, gRPC, WebSocket, custom TLS protocols | Bytes when carried through a supported TLS implementation | The viewer is a stream/hex inspector, not an HTTP/2, HPACK, gRPC or WebSocket decoder. |
| Asynchronous Winsock | Submission and immediate result; pending is explicit | No IOCP/completion-routine tracking. Async payloads are never dereferenced, even after an immediate successful return, because a completion thread can already reuse them. |
| Chromium/Electron, Go, Rust, Java, NSS, custom crypto | Socket activity when the target uses observed Winsock APIs | No blanket plaintext claim; implementation, exports and networking PID determine coverage. |
| QUIC, raw AFD, registered I/O, ConnectEx/AcceptEx, kernel networking | No complete coverage | Some UDP/socket calls can be visible; no QUIC plaintext, arbitrary kernel/syscall interception, or extension-function hooks. |
| Named pipes, Unix sockets, shared memory, other IPC | No backend in this mode | These are distinct from the implemented TCP/UDP observers. |

No user-space HTTP or TLS hook is a universal network capture boundary. A ready
backend says hooks installed; a data event says bytes were observed at that API.
Neither implies complete process coverage or successful delivery to a peer.

## Reading the result

`capture.html` is self-contained and uses no external resources. Socket rows
show timestamps, PID, numeric endpoint addresses and API outcome. Payload groups
offer UTF-8, exact hex and individual chunk views. Use individual chunks for UDP.
Embedded traffic is treated as text, never executed as HTML or JavaScript.

Schannel/OpenSSL groups contain application plaintext. Winsock groups contain
raw bytes only when requested with `--socket-data`. Encrypted socket bytes and
TLS plaintext can both be present; do not add their sizes as network usage.
`MSG_PEEK` and `MSG_OOB` calls are explicitly labelled in socket metadata;
their raw payload is omitted to avoid duplicating peeked bytes or mixing urgent
bytes into the normal stream.
Socket IDs and TLS context IDs are separate and are not automatically correlated.

The JSONL file is the authoritative byte artifact. Each version-1 record contains
`type`, `session`, monotonically increasing `seq`, Unix-millisecond `time`, `pid`
and `tid`. Record types are:

| Type | Meaning |
|---|---|
| `session` | File initialized in observation mode. This alone proves no traffic coverage. |
| `backend` | Observer became active; emitted lazily from runtime, outside module-loading callbacks. |
| `data` | `backend`, `connection`, `direction` (`out`/`in`), base64 `data`, `captured`, original accepted `length`, and `truncated`. |
| `network` | Socket `connection`, API `event`, `transport`, numeric `local`/`remote`, completed `bytes`, `status`, Windows socket `error`. |
| `gap` | Explicit inability to capture or track an operation; `reason`, direction and context ID (0 when unavailable). |

`pending` means submitted but completion unverified, including nonblocking
connection attempts. `would-block` means no operation was queued.
`completed-unmeasured` indicates a successful return whose transfer count was
not safely inspected, including immediate overlapped completions or an unreadable
synchronous count. Zero in this row does not mean zero transferred bytes.
`failed` retains the socket error code. Application status codes and LastError
are preserved.

IDs describe observed context/socket lifetimes, not application request IDs.
Tracking retires before deallocation to avoid merging recycled handles. A failed
close/delete or reference-counted `SSL_free` can conservatively split an ID.
Concurrent directions are ordered by capture emission, not wire ordering.

## Bounds and failure behavior

Capture files are plaintext-sensitive local artifacts. No traffic is uploaded.
Recording uses synchronous file writes and can change application timing. File
size is not automatically capped or rotated; choose a suitable location and
record for a bounded period. The viewer accepts up to 128 MiB and displays at
most 2,000 socket rows at once after filtering; JSONL keeps every recorded row.

Payload records are bounded to 1 MiB; longer operations carry an explicit
truncation count. Descriptor arrays and live context/socket maps are bounded;
allocation/read/tracking failures emit gaps when the sink remains writable.
OpenSSL retains dispatch slots for up to 32 module generations per process;
additional library generations remain unhooked with a diagnostic. Unsupported
instruction relocation and partial hook installation leave an observer inactive.
No signature/decoder gates were relaxed for these backends.
For example, the tested Git OpenSSL 1.1 build's `SSL_free` prologue was refused;
the application still completed its traffic but produced no OpenSSL plaintext.
Passing another build does not establish compatibility with every libssl DLL.

A disk write failure stops recording and emits a debugger diagnostic, while the
application continues. A process crash or full disk can leave an incomplete last
record; the viewer rejects malformed/incomplete files and missing sequence
numbers rather than manufacturing bytes. Absence of a gap record is not proof
of complete traffic coverage or a healthy disk until process exit.

## Validation

Build fixtures with `cmd /c windows\test\build_test.bat`. Run engine and mock
tests first (`bun windows/test/run.ts`), then `bun run test:observe`. The new
native fixtures use loopback TLS/TCP/UDP and exact binary request/response
assertions; no external service or machine certificate-store changes are needed.
`run_openssl.ts` reports a missing real libssl fixture as SKIP. Supply
`--libssl <dll>` for an installed compatible library. CI covers native state
tests and local integrations; unavailable architectures are not inferred from
a passing x64 fixture.

The TLS certificate and key under `windows/test/fixtures` are deliberately public
test fixtures, not deployed credentials. Real captures, binaries and runtime
logs belong under ignored build output or outside the checkout.

Local validation on Windows (2026-09-22): x64 and x86 Schannel, TCP/UDP, capture
sink, native state and shared-library reload tests passed. Real TLS passed with
OpenSSL 3.0.18 x64 and 3.0.16 x86. System curl 8.21.0 using Schannel also passed a
local HTTPS POST with certificate verification enabled, exact origin request and
captured response bytes. The existing x64 curl matrix (44 checks) and WinHTTP
matrix (25 checks) passed. These are specific fixtures/builds, not blanket
application compatibility. ARM64 is wired into CI and was not executed locally;
Linux gains no observation backend from this change.

API references: [Schannel encryption](https://learn.microsoft.com/en-us/windows/win32/secauthn/encryptmessage--schannel),
[Schannel decryption](https://learn.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--schannel),
[SSPI function tables](https://learn.microsoft.com/en-us/windows/win32/secauthn/initializing-the-security-package),
[OpenSSL reads](https://docs.openssl.org/3.1/man3/SSL_read/),
[OpenSSL writes](https://docs.openssl.org/3.4/man3/SSL_write/), and
[overlapped Winsock sends](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasendto).
