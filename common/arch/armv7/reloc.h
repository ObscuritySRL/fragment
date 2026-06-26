#pragma once
#include <stdint.h>
#include <string.h>

/* armv7 engine backend (relocation) -- OS-independent, shared by every OS glue
 * that hooks on 32-bit ARM (linux/, and any later ARM port).
 *
 * ARM has two instruction states and a function's prologue may be in either:
 * A32 (every instruction a 4-byte word) or T32 / Thumb-2 (2- or 4-byte halfword
 * instructions, the toolchain default). The state is carried in bit 0 of the
 * function pointer (1 = Thumb), so the glue masks it off to read the bytes and
 * patches in the matching state. Like the aarch64 backend, the work is
 * classifying the prologue instructions the patch overwrites for PC-relative
 * relocation: B/BL reach far enough to be re-encoded toward the original target;
 * a position-independent instruction copies verbatim (the safe default); and a
 * PC-relative literal/ADR or a short Thumb branch leaving the window FAILS
 * CLOSED. Real compiler prologues (push/sub-sp/mov/str) are position-independent.
 *
 * The patch is a single branch to a near relay (an A32 `B`, +/-32 MB; or a T32
 * `B.W`, +/-16 MB -- the near-block allocator keeps the relay in range). The
 * relay's absolute jump is a PC literal load (`ldr pc,[pc,#-4]` in A32,
 * `ldr.w pc,[pc]` in T32) followed by the detour word, which reaches the whole
 * address space and interworks to the detour's own state via bit 0 of the word.
 */

#define FR_ARM_B_RANGE   (32 * 1024 * 1024)   /* A32 B: signed imm24 << 2     */
#define FR_THUMB_B_RANGE (16 * 1024 * 1024)   /* T32 B.W: signed 24-bit << 1  */

/* ---- A32 unconditional/conditional B (keeps the condition field) --------- */
static uint32_t FrEncArmB(uintptr_t from, uintptr_t to, uint32_t cond) {
    int32_t off = (int32_t)((int64_t)to - (int64_t)(from + 8));  /* A32 PC = insn + 8 */
    uint32_t imm24 = (uint32_t)(off >> 2) & 0x00FFFFFF;
    return (cond << 28) | 0x0A000000u | imm24;
}
static int FrInRangeArmB(uintptr_t from, uintptr_t to) {
    int64_t off = (int64_t)to - (int64_t)(from + 8);
    return off >= -FR_ARM_B_RANGE && off < FR_ARM_B_RANGE && (off & 3) == 0;
}

/* ---- T32 B.W (unconditional, T4 encoding) -------------------------------- */
static void FrEncThumbBW(uintptr_t from, uintptr_t to, uint8_t* out) {
    int32_t off = (int32_t)((int64_t)to - (int64_t)(from + 4));  /* T32 PC = insn + 4 */
    uint32_t u = (uint32_t)off;
    uint32_t S = (u >> 24) & 1, I1 = (u >> 23) & 1, I2 = (u >> 22) & 1;
    uint32_t imm10 = (u >> 12) & 0x3FF, imm11 = (u >> 1) & 0x7FF;
    uint32_t J1 = (~I1 & 1) ^ S, J2 = (~I2 & 1) ^ S;
    uint16_t hw1 = (uint16_t)(0xF000u | (S << 10) | imm10);
    uint16_t hw2 = (uint16_t)(0x9000u | (J1 << 13) | (J2 << 11) | imm11);
    memcpy(out + 0, &hw1, 2);
    memcpy(out + 2, &hw2, 2);
}
static int FrInRangeThumbBW(uintptr_t from, uintptr_t to) {
    int64_t off = (int64_t)to - (int64_t)(from + 4);
    return off >= -FR_THUMB_B_RANGE && off < FR_THUMB_B_RANGE && (off & 1) == 0;
}

/* ---- Thumb instruction length: 2 or 4 bytes ------------------------------ */
static int FrThumbLen(const uint8_t* p) {
    uint16_t hw; memcpy(&hw, p, 2);
    uint16_t top = hw & 0xF800;
    return (top == 0xE800 || top == 0xF000 || top == 0xF800) ? 4 : 2;
}

/* A small literal pool appended after the relocated prologue. When an
 * instruction loads a word PC-relatively (the PIC `ldr rN,[pc,#imm]` a Thumb
 * prologue opens with), the loaded VALUE is a position-independent constant, so
 * we copy it into this pool -- within the short LDR-literal reach of the moved
 * instruction -- and re-point the load there. The dependent `add rN,pc` that
 * forms the absolute address is left in the original function (it runs after the
 * jump back, with the original PC), so only the load itself must be relocated. */
typedef struct { uint8_t* base; uintptr_t baseVa; int used; int cap; } FrPool;

static int FrPoolPut(FrPool* p, uint32_t word, uintptr_t* slotVa) {
    if (p->used + 4 > p->cap) return 0;
    memcpy(p->base + p->used, &word, 4);
    *slotVa = p->baseVa + (uintptr_t)p->used;
    p->used += 4;
    return 1;
}

/* Relocate one A32 instruction `insn` (at `src`) to run at `dst`. Returns 1 and
 * writes *out, or 0 to fail closed. */
static int FrRelocArm(uint32_t insn, uintptr_t src, uintptr_t dst, uint32_t* out, FrPool* pool) {
    uint32_t cond = insn >> 28;
    /* B / BL (and conditional B): bits[27:25] = 101. Re-target so it still
     * reaches the original absolute destination from the trampoline. */
    if ((insn & 0x0E000000u) == 0x0A000000u) {
        int32_t imm24 = (int32_t)(insn << 8) >> 8;          /* sign-extend 24 */
        uintptr_t tgt = src + 8 + ((uintptr_t)imm24 << 2);
        if (!FrInRangeArmB(dst, tgt)) return 0;
        if (insn & 0x01000000u) {                           /* BL: keep link bit (H) */
            int32_t noff = (int32_t)((int64_t)tgt - (int64_t)(dst + 8)) >> 2;
            *out = (cond << 28) | 0x0B000000u | ((uint32_t)noff & 0x00FFFFFF);
        } else {
            *out = FrEncArmB(dst, tgt, cond);
        }
        return 1;
    }
    /* LDR rt,[pc,#imm] word literal (Rn=15, immediate offset): copy the loaded
     * word into the pool and re-point the load there. */
    if ((insn & 0x0E500000u) == 0x04100000u && ((insn >> 16) & 0xF) == 15) {
        uint32_t imm12 = insn & 0xFFF;
        int U = (insn >> 23) & 1;
        uintptr_t litVa = src + 8 + (U ? imm12 : (uintptr_t)0 - imm12);
        uint32_t W; memcpy(&W, (const void*)litVa, 4);
        uintptr_t slot;
        if (!FrPoolPut(pool, W, &slot)) return 0;
        int64_t no = (int64_t)slot - (int64_t)(dst + 8);
        int nu = no >= 0;
        uint32_t na = (uint32_t)(no < 0 ? -no : no);
        if (na > 0xFFF) return 0;
        *out = (insn & ~0x00800FFFu) | ((uint32_t)nu << 23) | na;
        return 1;
    }
    /* Any remaining instruction that uses PC (r15) -- an ADR (data-proc Rn=15),
     * a register-offset or block/coprocessor literal -- cannot be relocated this
     * simply, so refuse (matches the aarch64 short-branch refusal). Compilers
     * never start a prologue with one. */
    if (((insn & 0x0C000000u) == 0x00000000u && ((insn >> 16) & 0xF) == 15) ||  /* data-proc with Rn=PC (ADR)   */
        ((insn & 0x0C000000u) == 0x04000000u && ((insn >> 16) & 0xF) == 15) ||  /* other single transfer literal */
        ((insn & 0x0E000000u) == 0x08000000u && ((insn >> 16) & 0xF) == 15) ||  /* block transfer, PC base       */
        ((insn & 0x0C000000u) == 0x0C000000u && ((insn >> 16) & 0xF) == 15))    /* coprocessor literal           */
        return 0;
    /* Position-independent: copy verbatim. */
    *out = insn;
    return 1;
}

/* Relocate one T32 instruction of `len` bytes (at `src`) to run at `dst`. */
static int FrRelocThumb(const uint8_t* p, int len, uintptr_t src, uintptr_t dst, uint8_t* out, FrPool* pool) {
    uint16_t hw1; memcpy(&hw1, p, 2);
    if (len == 2) {
        /* LDR Rt,[PC,#imm8*4] word literal: pool the loaded word and re-point. */
        if ((hw1 & 0xF800) == 0x4800) {
            int rt = (hw1 >> 8) & 7;
            uintptr_t litVa = ((src + 4) & ~(uintptr_t)3) + ((uintptr_t)(hw1 & 0xFF) << 2);
            uint32_t W; memcpy(&W, (const void*)litVa, 4);
            uintptr_t slot;
            if (!FrPoolPut(pool, W, &slot)) return 0;
            int64_t no = (int64_t)slot - (int64_t)((dst + 4) & ~(uintptr_t)3);
            if (no < 0 || (no & 3) || no > 0x3FC) return 0;
            uint16_t o = (uint16_t)(0x4800 | (rt << 8) | ((uint32_t)no >> 2));
            memcpy(out, &o, 2);
            return 1;
        }
        /* ADR (0xA000) and the short branches B<c> (0xD000) / B (0xE000) have
         * only kilobyte reach and `add rd,pc` (0x4478) re-bases on PC -- none
         * survive a far move, so fail closed. */
        if ((hw1 & 0xF800) == 0xA000 ||                     /* ADR Rd,PC,#imm   */
            (hw1 & 0xF000) == 0xD000 ||                     /* B<cond> / SVC    */
            (hw1 & 0xF800) == 0xE000 ||                     /* B (T2)           */
            (hw1 & 0xFF78) == 0x4478)                       /* add rd, pc       */
            return 0;
        memcpy(out, p, 2);                                  /* position-independent */
        return 1;
    }
    /* 32-bit Thumb. */
    uint16_t hw2; memcpy(&hw2, p + 2, 2);
    /* B.W / BL (T3/T4): hw1[15:11]=11110, hw2[15]=1 and hw2[14:12] selects a
     * branch. Re-target toward the original absolute destination. */
    if ((hw1 & 0xF800) == 0xF000 && (hw2 & 0x8000) == 0x8000 &&
        ((hw2 & 0x5000) == 0x5000 || (hw2 & 0x5000) == 0x1000)) {   /* B.W / BL */
        uint32_t S = (hw1 >> 10) & 1;
        uint32_t J1 = (hw2 >> 13) & 1, J2 = (hw2 >> 11) & 1;
        uint32_t imm10 = hw1 & 0x3FF, imm11 = hw2 & 0x7FF;
        uint32_t I1 = (~(J1 ^ S)) & 1, I2 = (~(J2 ^ S)) & 1;
        int32_t off = (int32_t)((S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1));
        off = (off << 7) >> 7;                              /* sign-extend 25 */
        uintptr_t tgt = src + 4 + (uintptr_t)off;
        int isBL = (hw2 & 0x4000) != 0;                     /* BL sets bit14 */
        if (!FrInRangeThumbBW(dst, tgt)) return 0;
        if (isBL) {
            /* re-encode BL with the new displacement, keeping the link bit. */
            int32_t no = (int32_t)((int64_t)tgt - (int64_t)(dst + 4));
            uint32_t u = (uint32_t)no;
            uint32_t nS = (u >> 24) & 1, nI1 = (u >> 23) & 1, nI2 = (u >> 22) & 1;
            uint32_t nimm10 = (u >> 12) & 0x3FF, nimm11 = (u >> 1) & 0x7FF;
            uint32_t nJ1 = (~nI1 & 1) ^ nS, nJ2 = (~nI2 & 1) ^ nS;
            uint16_t o1 = (uint16_t)(0xF000u | (nS << 10) | nimm10);
            uint16_t o2 = (uint16_t)(0xD000u | (nJ1 << 13) | (nJ2 << 11) | nimm11);
            memcpy(out + 0, &o1, 2); memcpy(out + 2, &o2, 2);
        } else {
            FrEncThumbBW(dst, tgt, out);
        }
        return 1;
    }
    /* LDR.W Rt,[PC,#imm12] word literal (Rn=1111): pool the loaded word and
     * re-point. Encoding hw1 = 1111 1000 U101 1111. */
    if ((hw1 & 0xFF7F) == 0xF85F) {
        int rt = (hw2 >> 12) & 0xF;
        int U = (hw1 >> 7) & 1;
        uint32_t imm12 = hw2 & 0xFFF;
        uintptr_t litVa = ((src + 4) & ~(uintptr_t)3) + (U ? imm12 : (uintptr_t)0 - imm12);
        uint32_t W; memcpy(&W, (const void*)litVa, 4);
        uintptr_t slot;
        if (!FrPoolPut(pool, W, &slot)) return 0;
        int64_t no = (int64_t)slot - (int64_t)((dst + 4) & ~(uintptr_t)3);
        int nu = no >= 0;
        uint32_t na = (uint32_t)(no < 0 ? -no : no);
        if (na > 0xFFF) return 0;
        uint16_t o1 = (uint16_t)((hw1 & ~0x0080u) | ((uint32_t)nu << 7));
        uint16_t o2 = (uint16_t)((rt << 12) | na);
        memcpy(out + 0, &o1, 2); memcpy(out + 2, &o2, 2);
        return 1;
    }
    /* ADR / ADDW / SUBW Rd,PC,#imm12 re-base on PC and cannot be pooled -> refuse. */
    if (((hw1 & 0xFBFF) == 0xF20F) ||                       /* ADR / ADDW (add) */
        ((hw1 & 0xFBFF) == 0xF2AF))                         /* ADR / SUBW (sub) */
        return 0;
    memcpy(out, p, 4);                                      /* position-independent */
    return 1;
}
