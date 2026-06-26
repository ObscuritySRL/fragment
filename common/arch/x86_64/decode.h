#pragma once

/*
 * x86-64 prologue length-decoder: the 64-bit selection of the shared x86 core.
 * The decoder logic lives once in ../x86/decode.h (a decode fix lands for every
 * x86 width and both ports at the same time); this header pins FR_X86_BITS so a
 * REX prefix is consumed, a bare disp32 is treated as RIP-relative, and a REX.W
 * mov-immediate is eight bytes wide. The OS glue includes this path unchanged.
 */

#define FR_X86_BITS 64
#include "../x86/decode.h"
