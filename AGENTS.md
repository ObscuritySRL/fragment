# Using and working on Fragment

Fragment is a C17 library and launcher that redirect supported HTTP APIs to an
operator-provided proxy. Loading the library is not proof that hooks installed
or that a request reached the proxy. Keep those claims separate.

## Help someone use Fragment

When the user asks how to use Fragment, guide them through a working launch,
proxy setup, and verification. Start with the usage flow below; the development
instructions later in this file apply when source changes or builds are needed.
Use the files and `--help` from their actual version as the authority.

### 1. Identify their setup

Inspect what is available before asking for missing details: host OS, target
program and its architecture, source checkout versus extracted release, and
whether they already have a compatible proxy. If given only the GitHub repo,
read this guide and README, then help select a release for their machine or a
source build. Do not assume the agent can run commands on the user's machine;
when it cannot, give commands for their shell and explain what output to check.

- A source checkout contains `windows/`, `linux/`, and `tools/proxy.ts`.
- An extracted Windows package contains `fragment.exe` and `Fragment.dll`.
  Keep these together. The x64 package does not include `Fragment32.dll` for
  32-bit targets; that DLL requires a separate x86 build.
- An extracted Linux package contains `fragment` and `libfragment.so`.
  Keep these together and match the package architecture to the target.
- Published packages are listed at
  https://github.com/ObscuritySRL/fragment/releases. Check the actual assets;
  an engine backend in source does not imply a downloadable package exists.
- macOS has no implementation. libcurl and Windows WinHTTP are supported;
  WinINet, Chromium/CEF networking, other TLS stacks, and QUIC are not covered
  just because Fragment loaded. Identify the process actually sending requests.

Prefer an existing matching release for someone who only wants to run Fragment.
No compiler is needed for a release. Bun is needed only for the included proxy
or development scripts; an existing compatible proxy can be used instead.

### 2. Start the proxy first

From the checkout or a package containing `tools/proxy.ts`, run in one terminal:

```sh
bun tools/proxy.ts 19020
```

Leave it running and use a second terminal for the target. The example port
19020 must be free; use another port consistently if it is occupied. Do not stop
an existing service to take its port. Fragment's default is 9020; the launch
examples below explicitly select 19020.

The proxy must accept a request such as `GET /https://example.com/path`, forward
to that original URL, and relay the response. This is not a conventional HTTP
CONNECT/SOCKS proxy configuration. Fragment redirects traffic; its launcher does
not start a proxy or record response bodies. The included proxy forwards requests
and prints method, URL, and response status; use a recording proxy when payload
inspection is needed. Treat real request URLs and payloads as potentially sensitive.

Older release archives, including v1.2.0, omit the proxy script and this guide.
For those, obtain `tools/proxy.ts` from the matching repository tag (or use an
existing compatible proxy). Do not give a command for an absent file without
explaining how to obtain it. The script requires Bun but no `bun install`.

### 3. Launch the target

From an extracted Windows release directory, in PowerShell:

```powershell
.\fragment.exe --version
.\fragment.exe --help
.\fragment.exe --proxy http://127.0.0.1:19020 --log debug --log-file fragment.log -- "C:\Path\To\program.exe" arg1
```

From an extracted Linux release directory:

```sh
./fragment --version
./fragment --help
./fragment --proxy http://127.0.0.1:19020 --log debug --log-file fragment.log -- /path/to/program arg1
```

Replace the example target with the user's executable and arguments. Everything
after `--` belongs to the target. Use `curl.exe` explicitly in PowerShell if
testing curl, and verify that particular curl build is supported. Keep the
target's required working directory; invoke Fragment by absolute path if needed.
Use an absolute log path when the log's location would otherwise be unclear.

For a source checkout, build only the host platform first, from the repo root:

```powershell
# Windows: Visual Studio C++ tools and CMake required
cmd /c windows\build.bat
.\windows\build\fragment.exe --help
```

```sh
# Linux: C compiler required; build.sh uses CMake when available
bash linux/build.sh
./linux/build/fragment --help
```

With the Visual Studio multi-configuration generator, use the binaries in
`windows/build/Release/` (or `Debug/`) instead of the build root. Check the actual
output location. Then substitute that built launcher path in the launch example. Native test
fixtures and TypeScript dependencies are not prerequisites for an ordinary launch.

Prefer launch-time configuration. For an already-running process, the commands
are `.\fragment.exe --pid 1234` on Windows or `./fragment --pid 1234` on Linux.
Confirm the actual target PID first. Attachment uses the target's existing
environment: `--proxy`, `--log`, and other configuration flags cannot update it.
Configuration is read once when the library loads; changing the launching shell
after attachment does not reconfigure it. Restart with the desired configuration
when appropriate. Linux attachment may be restricted by ptrace policy; diagnose
the error rather than automatically changing system policy. WinHTTP connections
opened before attachment lack origin metadata and pass through.

### 4. Prove it works and troubleshoot

Have the target perform a known request, then check these separately:

1. **Library loaded:** launcher/module-list evidence. An attach success alone
   says nothing about requests.
2. **Hooks installed:** inspect `fragment.log` for `[hook]` entries and, for
   WinHTTP, `[winhttp] backend ready`. Release logging is off unless enabled.
3. **Traffic observed:** confirm the expected original URL at the proxy, the
   response received by the target, and its exit status where applicable.

For a controlled local fixture, verify method/body/path and that no request hits
the origin directly. Compare a bare run and a launch with `--off` before `--`;
these should bypass Fragment's rewrite. `--off` applies to a newly launched
target, not to a previously injected process. To stop using Fragment, restart
the target normally; stopping only the proxy leaves redirected requests failing.

If the proxy stays empty, check in order: proxy reachability and matching port;
library path/architecture and injection result; hook logs; whether that PID uses
a supported stack; and whether the request happened in a child process or on a
pre-existing connection. Children are not automatically injected. Report an
unsupported or unverified case honestly; do not substitute a permissive signature
or claim application compatibility from a successful fixture.

In a checkout, `bun windows/test/run_winhttp.ts` provides a self-contained Windows
WinHTTP check. `bun windows/test/run.ts` and `bun linux/test/run.ts` cover curl;
optional missing fixtures are SKIP. These suites use local ports 19020, 19021,
and 19999: stop the demo proxy you started on 19020, or resolve the conflict,
before running them. See README for configuration and the full test workflow.

## Map

- `common/arch/`: shared instruction decoders/relocation helpers; `curl_abi.h`
  holds curl option IDs. Changes here can affect several operating systems.
- `windows/main.c`: DLL lifecycle, module discovery, curl resolution and hook
  registration. `winhttp.h`: WinHTTP handle tracking and redirection.
- `windows/hook.h`, `linux/hook.h`: platform-specific hook engines.
- `windows/tools/fragment.c`, `linux/tools/fragment.c`: launch/attach tools.
- `linux/main.c`: interposition, audit, ELF resolution and inline hooking.
- Each platform's `test/` contains C fixtures and test orchestration.
- `BRIEF.md` is a roadmap, not a list of implemented capabilities. macOS is
  currently documentation only.

## Runtime and tooling

Use Bun for TypeScript scripts and tests; prefer `Bun.spawn`, `Bun.file`,
`Bun.write`, `Bun.Glob`, `Bun.serve`, and `bun:test` over Node APIs. Do not add
Node, npm, tsx or Python dependencies to new tooling. Existing Python scripts
are legacy comparison/reference tools until their coverage is ported.
Native libraries and fixtures remain C; Bun orchestrates them.

Windows builds require Visual Studio C++ tools, discovered by
`windows/find_vcvars.bat`. Run `windows/build.bat` and
`windows/test/build_test.bat`. If an old CMake cache names a removed compiler,
reconfigure a fresh build directory or clear only the generated cache.
Linux: `bash linux/build.sh` and `bash linux/test/build_test.sh`.

## Correctness boundaries

- Fail closed on unsupported instruction relocation or ambiguous symbols.
  Never weaken a decoder or signature gate just to make a target hook.
- Preserve URL rewrite idempotency, runtime configuration, disable switches,
  option neutralization, and the `/<original-url>` proxy contract.
- Handle hook publication, module loading and handle lifetimes carefully:
  detours may run concurrently. Do not call arbitrary loader APIs under loader
  notifications or free remote arguments while their thread is still running.
- Supported stacks are libcurl and (Windows) WinHTTP. Child processes, other
  TLS/HTTP stacks and QUIC are not automatically covered.
- Verify traffic at a local recording server, including path, method, body,
  child exit status and absence of unexpected origin hits. Include bare and
  disabled negative controls. A missing fixture is SKIP, never PASS.
- Test the engine and mock curl before real library/WinHTTP integration. Use
  CI for architectures unavailable locally; report untested platforms honestly.

## Change discipline

Read `git status` first; preserve unrelated and untracked user files. Keep
machine-specific binaries, downloaded corpora, logs, secrets and traffic out of
commits. Update README/CI when commands or coverage change. Review the diff and
run relevant checks before committing; merge only when the user requested it
and required checks pass. Do not claim third-party application compatibility
from a fixture test alone.
