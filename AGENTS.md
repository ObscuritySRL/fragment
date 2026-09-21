# Working on Fragment

Fragment is a C17 library and launcher that redirect supported HTTP APIs to an
operator-provided proxy. Loading the library is not proof that hooks installed
or that a request reached the proxy. Keep those claims separate.

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
