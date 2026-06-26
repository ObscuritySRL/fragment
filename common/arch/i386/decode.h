#pragma once

/*
 * IA-32 prologue length-decoder: the 32-bit selection of the shared x86 core.
 * The decoder logic lives once in ../x86/decode.h; this header pins FR_X86_BITS
 * so 0x40-0x4F decode as INC/DEC reg (no REX prefix exists), a bare disp32 is an
 * absolute address that copies verbatim (no RIP-relative form in 32-bit), and a
 * mov-immediate is never REX.W-widened. The OS glue selects this path with
 * `#if defined(__i386__)` / `defined(_M_IX86)`.
 */

#define FR_X86_BITS 32
#include "../x86/decode.h"
