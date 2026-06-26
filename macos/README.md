# `macos/` — macOS port (TODO)

OS glue for macOS (`macos-x86_64` + `macos-arm64`). Both arches reuse the
existing `common/arch/x86_64` and `common/arch/aarch64` engine backends; only the
OS glue is new. Mirror `linux/` (POSIX: `mmap`/`mprotect`/`dlopen` carry over),
swapping:

- **interception**: `LD_PRELOAD` -> `DYLD_INSERT_LIBRARIES` (+ `__interpose`).
- **symbol resolution**: ELF `.dynsym`/`.symtab` -> **Mach-O** / dyld APIs.
- **injection**: `ptrace` -> `mach` `task_for_pid` + remote thread (needs
  entitlement / SIP off; launch-mode interposition first, inject best-effort).

Planned files mirror `linux/`: `main.c`, `hook.h`, `util.h`, `config.h`,
`log.h`, `curl.h`, `tools/fragment.c`, `test/`. See [TARGETS.md](../TARGETS.md).
