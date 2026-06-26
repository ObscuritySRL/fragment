# `common/arch/armv7` — 32-bit ARM engine backend (TODO)

Per-arch backend for ARMv7 (`linux-armv7`). Provide here:

- `reloc.h` — ARM + Thumb-2 relocation (the prologue may be either state). Fail
  closed on any PC-relative operand that cannot be re-encoded in range, mirroring
  `../aarch64/reloc.h`.
- caller stub: AAPCS (r0-r3 + stack).

See [TARGETS.md](../../../TARGETS.md).
