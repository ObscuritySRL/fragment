#pragma once
#include <stdint.h>

/* aarch64 engine backend (relocation) -- OS-independent, shared by every OS
 * glue that hooks on aarch64 (linux/, and windows-arm64/macos when added).
 *
 * Every instruction is a 4-byte word, so "length decoding" is trivial; the work
 * is classifying the FIRST instruction (the only one the single-B patch
 * overwrites) for PC-relative relocation. Any instruction without a PC-relative
 * operand is position-independent and copies verbatim -- the safe default --
 * while ADR/ADRP/LDR-literal/B/BL are relocated and conditional/test branches
 * leaving the window, or any relocation that will not fit, FAIL CLOSED.
 *
 * The patch is a single naturally-aligned 4-byte store (atomic, so no torn
 * window even without thread suspension). The jump back is a direct B (no
 * indirect branch, so BTI is a non-issue); the relay reaches an arbitrary
 * detour via LDR x16,#8 / BR x16, and Fragment is built with branch protection
 * so the detour entry is a valid BTI landing pad.
 */

#define FR_B_RANGE (128 * 1024 * 1024)        /* +/-128 MB for B/BL imm26 */

static uint32_t FrEncB(uintptr_t from, uintptr_t to) {     /* unconditional B */
    int64_t off = (int64_t)to - (int64_t)from;
    uint32_t imm26 = (uint32_t)((off >> 2) & 0x03FFFFFF);
    return 0x14000000u | imm26;
}
static int FrInRangeB(uintptr_t from, uintptr_t to) {
    int64_t off = (int64_t)to - (int64_t)from;
    return off >= -FR_B_RANGE && off < FR_B_RANGE && (off & 3) == 0;
}

/* Relocate the single first instruction `insn` (originally at `src`) so that,
 * placed at `dst`, any PC-relative operand still resolves to the same absolute
 * address. Returns 1 and writes *out, or 0 to fail closed. */
static int FrRelocOne(uint32_t insn, uintptr_t src, uintptr_t dst, uint32_t* out) {
    /* ADR / ADRP: bits[28:24]=10000 */
    if ((insn & 0x1F000000u) == 0x10000000u) {
        int isAdrp = (insn >> 31) & 1;
        int64_t immhi = (int64_t)((insn >> 5) & 0x7FFFF);   /* 19 bits */
        int64_t immlo = (insn >> 29) & 0x3;
        int64_t imm = (immhi << 2) | immlo;                 /* 21 bits */
        imm = (imm << 43) >> 43;                            /* sign-extend */
        uintptr_t tgt;
        if (isAdrp) tgt = ((src & ~(uintptr_t)0xFFF)) + (uintptr_t)(imm << 12);
        else        tgt = src + (uintptr_t)imm;
        int64_t nd;
        if (isAdrp) nd = (int64_t)(tgt) - (int64_t)(dst & ~(uintptr_t)0xFFF), nd >>= 12;
        else        nd = (int64_t)tgt - (int64_t)dst;
        if (nd < -(1 << 20) || nd >= (1 << 20)) return 0;   /* 21-bit signed */
        uint32_t nimm = (uint32_t)(nd & 0x1FFFFF);
        uint32_t base = insn & ~((0x3u << 29) | (0x7FFFFu << 5));
        *out = base | ((nimm & 0x3u) << 29) | (((nimm >> 2) & 0x7FFFFu) << 5);
        return 1;
    }
    /* LDR (literal) Wt/Xt/SIMD: top byte 0x18/0x58/0x98/0x1C/0x5C/0x9C */
    {
        uint32_t t = insn & 0xBF000000u;
        if (t == 0x18000000u || t == 0x98000000u || t == 0x1C000000u || t == 0x9C000000u) {
            int64_t imm19 = (int64_t)((insn >> 5) & 0x7FFFF);
            imm19 = (imm19 << 45) >> 45;                    /* sign-extend */
            uintptr_t tgt = src + (uintptr_t)(imm19 << 2);
            int64_t nd = ((int64_t)tgt - (int64_t)dst) >> 2;
            if (((int64_t)tgt - (int64_t)dst) & 3) return 0;
            if (nd < -(1 << 18) || nd >= (1 << 18)) return 0; /* 19-bit signed */
            *out = (insn & ~(0x7FFFFu << 5)) | (((uint32_t)nd & 0x7FFFFu) << 5);
            return 1;
        }
    }
    /* B / BL: bits[30:26]=00101 */
    if ((insn & 0x7C000000u) == 0x14000000u) {
        int64_t imm26 = (int64_t)(insn & 0x03FFFFFF);
        imm26 = (imm26 << 38) >> 38;                        /* sign-extend */
        uintptr_t tgt = src + (uintptr_t)(imm26 << 2);
        if (!FrInRangeB(dst, tgt)) return 0;
        uint32_t link = insn & 0x80000000u;                 /* keep BL bit */
        *out = (0x14000000u | link) | (uint32_t)(((int64_t)tgt - (int64_t)dst) >> 2 & 0x03FFFFFF);
        return 1;
    }
    /* Conditional / compare-and-branch / test-and-branch all embed a short
     * PC-relative target; relocating them from a far trampoline cannot be
     * guaranteed to reach, so refuse (matches the x86 "short branch leaving
     * the window" refusal). Real curl prologues never start with one. */
    if ((insn & 0xFF000010u) == 0x54000000u ||              /* B.cond        */
        (insn & 0x7E000000u) == 0x34000000u ||              /* CBZ/CBNZ      */
        (insn & 0x7E000000u) == 0x36000000u)                /* TBZ/TBNZ      */
        return 0;
    /* Anything else has no PC-relative operand: copy verbatim. */
    *out = insn;
    return 1;
}
