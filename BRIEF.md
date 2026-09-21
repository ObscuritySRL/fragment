# Fragment — Multi-Backend Interception Brief

**Goal.** Today Fragment captures one HTTP stack (libcurl). This brief generalizes
it so that *every* common request stack a target uses is routed to the **same**
local proxy, preserving Fragment's existing invariant:

```
<any stack's outbound request>  ->  http://127.0.0.1:9020/<original-url>
```

**Scope.** Same as `README` — a traffic-redirection and inspection tool for use
only on software and systems you are authorized to analyze. The proxy is local
and operator-run; nothing here adds remote exfiltration, owner-evasion, or
targeting of machines you don't control. Out of scope by design.

---

## 1. The invariant: one proxy contract, many feeders

Keep the property that makes the curl path elegant: **redirect the intent
*before* TLS**, so the app speaks plain HTTP to your local proxy and there is no
handshake to pin against. Where a stack exposes no redirectable intent, fall back
to reading plaintext **inside** the app's own TLS session (pinning is irrelevant
there — it's the genuine connection, you're just above the crypto).

Three mechanisms, in preference order:

| # | Mechanism | Pre-TLS? | Pinning | Notes |
|---|---|---|---|---|
| **M1** | **Intent redirect** — rewrite request target to the proxy at the stack's request-build API | yes | not engaged | the current curl approach; cleanest |
| **M2** | **Proxy-config injection** — set the stack's *own* proxy setting to the local proxy | yes (CONNECT) | engaged on upstream leg | trivial where a stack honors a proxy; HTTPS arrives as a CONNECT tunnel unless proxy terminates |
| **M3** | **TLS-boundary capture** — read/forward plaintext at the stack's `SSL_read`/`SSL_write` (or `Encrypt`/`DecryptMessage`) | no (post-decrypt) | bypassed (inside real session) | backstop for closed stacks; inspection-grade, rewrite is harder |

A "backend" = `{ detect module, resolve funcs, mechanism, feed-to-proxy }`.
libcurl is just the first backend. The registry pattern already in `windows/main.c`
(resolve → dedup → install) generalizes directly.

**Proxy contract.** So the proxy stays stack-agnostic, normalize both feeders to
one shape: M1/M2 already deliver `GET /https://host/path` style requests;
M3 synthesizes the same from the captured request line + `Host`. Non-HTTP or
streaming plaintext goes on a side capture channel keyed by `(pid, conn-id)`.

---

## 2. Backends

Ordered by coverage-per-effort.

| Stack | Who uses it | Mechanism | Hook points |
|---|---|---|---|
| **libcurl** *(done)* | native/CLI, git, PHP | M1 | `curl_easy_setopt`, `curl_url_*` |
| **WinHTTP** | services, Office, WinUpdate, old .NET | M1 or M2 | `WinHttpOpenRequest`/`WinHttpConnect`; or `WinHttpSetOption(WINHTTP_OPTION_PROXY)` |
| **WinINet** | IE-era, installers, legacy webviews | M1 or M2 | `InternetConnect`/`HttpOpenRequest`; or `InternetSetOption` proxy |
| **Schannel** | **sweeps WinHTTP + WinINet + .NET + native-tls Rust** | M3 | `EncryptMessage`/`DecryptMessage`, `InitializeSecurityContext` |
| **.NET HttpClient** | C#/business apps | M2, or M3 via Schannel | managed `DefaultProxy`/handler; else Schannel catches it |
| **OpenSSL** | Python (`_ssl`), Node, OpenSSL-curl | M3 | `SSL_read`/`SSL_write` in `libssl` |
| **BoringSSL** | **Chromium/Electron — Chrome/Edge/Slack/Discord/VSCode/Teams** | M3 (sig-scan, static) or M2 | `SSL_read`/`SSL_write`; or Chromium `--proxy-server` |
| **Go `crypto/tls`** | Docker/k8s/modern CLI | M2 (sets `HTTP(S)_PROXY`) or M3 | env proxy (note: scrubbed today — here you *set* it); else sig-scan, brittle |
| **Java JSSE** | enterprise, JetBrains | M2 | `http.proxyHost`/`https.proxyHost` at launch |
| **NSS** | Firefox/Thunderbird | M3 or proxy config | `PR_Read`/`PR_Write` |

**The shortcut:** Schannel + OpenSSL + BoringSSL (M3) alone cover the large
majority of Windows desktop apps in cleartext. Schannel is export-clean (no
sig-scan); BoringSSL is the single biggest bucket and needs a static byte-sig
path — you already have that machinery for static curl.

---

## 3. Coverage you can actually guarantee

"Every request" splits in two — be honest about which:

1. **See every connection** — achievable. A socket-layer observer
   (`ws2_32` `WSASend`/`WSARecv`/`connect`, or `\Device\Afd`) enumerates every
   TCP/UDP flow. Inspection-only (ciphertext), but it's the completeness ledger.
2. **Read every plaintext** — no universal chokepoint; TLS lives inside each app.

So the deliverable guarantee is **reconciliation**, not omniscience:

```
{connections seen at socket layer}  -  {handled by a backend}  =  GAPS
        -> log endpoint + owning module, flag "unknown stack"
```

You can't promise plaintext on every request, but you *can* promise you'll know
exactly what slipped through and where. That matches the `README`'s
"honest boundaries" stance.

---

## 4. Known edges (carry forward into limitations)

- **Process tree.** A target spawns helpers — Chromium's network-service is a
  *separate* PID. "Point at a process" must mean the tree: hook `CreateProcess*`
  and inject children, or the renderer/network split hides everything.
- **QUIC / HTTP-3 over UDP.** Chromium et al. M3-on-TCP and Schannel both miss
  it; socket layer sees only UDP. Either add BoringSSL-QUIC hooks or force TCP
  fallback (`--disable-quic`, or drop UDP/443).
- **Raw sockets / `CURLOPT_OPENSOCKETFUNCTION`.** Already a documented curl-path
  limitation; the socket-layer ledger is what catches these as gaps.
- **Static/stripped Go & Rust.** No exports → sig-scan only → version-fragile;
  fail closed, log the miss.
- **Privileges & bitness.** Same constraints as today (injectable target;
  cross-bitness x86/x64/arm64 already handled by the engine).

---

## 5. Suggested phasing

1. **WinHTTP + WinINet** (M1/M2) — biggest native coverage, export-clean, no decrypt.
2. **Schannel** (M3) — one hook sweeps .NET, native-tls, and backstops phase 1.
3. **OpenSSL + BoringSSL** (M3) — Python/Node, then the Chromium/Electron bucket.
4. **Socket-layer ledger + child-process following** — turns "we hook these stacks"
   into "we know our coverage." Add Go/Java/NSS as specific targets demand.

Each backend ships behind the same registry + fail-closed discipline as the curl
backend, and feeds the one proxy contract in §1.
