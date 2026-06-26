# `common/arch/i386` — 32-bit x86 engine backend (TODO)

Per-arch backend for IA-32. Unlocks **`windows-x86`** and **`linux-i386`** (one
backend, both OSes). Provide here, mirroring `../x86_64/decode.h`:

- `decode.h` — 32-bit length-decoder. Simpler than x86-64: **no REX prefixes**,
  **no RIP-relative** addressing (absolute `disp32` operands copy verbatim), and
  `0x40-0x4F` are `INC/DEC reg` (not REX). Relocation is mostly rel8/rel32 branch
  fixups; rel32 reaches the whole 4 GB, so there is no near-allocation limit.
- caller stub: `__cdecl` / `__stdcall` — arguments on the **stack**, not in
  registers (unlike the x86-64 register stub).

The OS glue (`windows/`, `linux/`) selects this backend by `#if defined(__i386__)`
/ `defined(_M_IX86)`. See [TARGETS.md](../../../TARGETS.md).
