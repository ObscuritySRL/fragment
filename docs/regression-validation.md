# Redirection regression fixes

The regression fixtures exercise these previously failing cases:

- Windows curl DLLs loaded, unloaded, and reloaded eight times, including
  forced loader modes. Unload notifications retire hook identities so a reused
  image address can be hooked again. Retired trampolines remain allocated until
  process exit to avoid freeing code that another thread may still be using.
- `curl_off_t` option values with nonzero high words and negative values.
  i386 and ARMv7 stubs preserve the full original argument; interposition and
  audit forwarding recognize the 64-bit option type. `CURLcode` uses its actual
  `int` ABI on both platforms.
- URL components changed after `CURLOPT_CURLU`, relative full-URL updates,
  resets, and invalid mutations. Shared code unwraps the embedded origin before
  mutation and rewrites the resulting complete URL. Partial URL assembly stays
  in origin form until complete. Builds exposing only `curl_url_set`, without
  its matching getter/free functions, retain whole-URL-only coverage.
- Root-relative, parent-relative, and query-only redirects (302/307/308).
  The included proxy resolves each location against the upstream URL and
  returns a proxy URL. Real curl and WinHTTP clients must send both hops through
  the proxy; disabled controls must send neither hop through it.
- Empty Windows arguments, quotes, trailing backslashes, tabs, Unicode, and an
  argument longer than the old 8192-byte buffer. Launching uses `CreateProcessW`
  and Windows CRT escaping; oversized command lines fail rather than truncate.

## Local validation

Windows x64 and x86 were built with MSVC. Engine and mock-curl tests passed on
both; x64 real-curl, WinHTTP, launcher, and Bun tooling regressions passed.
Linux x64 was built and tested in a separate Ubuntu WSL distribution, with
i386 and ARMv7 engine and mock-curl tests executed under QEMU. CI installs the
32-bit cross toolchains on its Linux x64 runner to keep this coverage active.
ARM64 execution remains covered by the existing CI jobs, not this local run.

One check outside these fixes remains unresolved:

- Linux live PID attachment terminates the local fixture during injection.
  The same failure was reproduced with the unchanged HEAD baseline in the
  same WSL environment; the regression changes do not fix it.

Missing optional integration fixtures remain SKIP. Fixture tests establish
these specific behaviors, not compatibility with arbitrary applications.
