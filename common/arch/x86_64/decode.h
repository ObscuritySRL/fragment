#pragma once

#include <stdint.h>

/*
 * Shared x86-64 prologue length-decoder + relocation metadata -- the
 * OS-independent core of the inline-hook engine, used by both the Windows and
 * Linux builds. The instruction encoding does not change with the OS, so this
 * lives once and a decode fix lands for both ports at the same time.
 *
 * It recognises the instruction subset compilers emit in function prologues and
 * reports, per instruction, what must be relocated when the prologue is copied
 * into a trampoline (a RIP-relative disp32, or a rel8/rel32 branch operand).
 * Anything it cannot decode with certainty returns length 0, so the caller
 * FAILS CLOSED. x86-64 only.
 */

/* What a single decoded instruction needs relocated when it is copied. */
typedef struct {
    int ripDisp;   /* byte offset of a RIP-relative disp32 within the insn, else -1 */
    int relKind;   /* 0 = none, 1 = rel8 branch, 4 = rel32 branch */
    int relOff;    /* byte offset of the rel operand within the insn */
} FrInsn;

/* ModRM (+SIB +displacement) length. Sets *ripDisp to the disp32 offset
 * (relative to the ModRM byte) when the operand is RIP-relative, else -1. */
static int FrModRM(const uint8_t* m, int addr32, int* ripDisp) {
    *ripDisp = -1;
    uint8_t modrm = m[0];
    int mod = modrm >> 6, rm = modrm & 7;
    int len = 1;
    if (mod == 3) return len;                 /* register direct */
    if (rm == 4) {                            /* SIB present */
        uint8_t sib = m[1];
        len += 1;
        int base = sib & 7;
        if (mod == 0 && base == 5) len += 4;  /* disp32, no base */
        else if (mod == 1) len += 1;          /* disp8  */
        else if (mod == 2) len += 4;          /* disp32 */
    } else {
        if (mod == 0) {
            if (rm == 5) { if (!addr32) *ripDisp = len; len += 4; }  /* RIP-rel / abs disp32 */
        } else if (mod == 1) len += 1;        /* disp8  */
        else if (mod == 2) len += 4;          /* disp32 */
    }
    return len;
}

/* Decode one instruction; return its byte length, or 0 if not decodable. */
static int FrDecode(const uint8_t* p, FrInsn* in) {
    in->ripDisp = -1; in->relKind = 0; in->relOff = -1;
    int i = 0, osz = 0, asz = 0, rexW = 0;

    for (;;) {                                /* legacy prefixes */
        uint8_t b = p[i];
        if (b == 0x66) { osz = 1; i++; }
        else if (b == 0x67) { asz = 1; i++; }
        else if (b == 0xF0 || b == 0xF2 || b == 0xF3 ||
                 b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
                 b == 0x64 || b == 0x65) { i++; }
        else break;
    }
    if (p[i] >= 0x40 && p[i] <= 0x4F) { rexW = (p[i] & 8) != 0; i++; }  /* REX */

    uint8_t op = p[i++];
    int rip, e;

    if (op == 0x0F) {                         /* two/three-byte opcodes */
        uint8_t o2 = p[i++];
        if (o2 == 0x38) { i++; e = FrModRM(p + i, asz, &rip); if (rip >= 0) in->ripDisp = i + rip; i += e; return i; }
        if (o2 == 0x3A) { i++; e = FrModRM(p + i, asz, &rip); if (rip >= 0) in->ripDisp = i + rip; i += e; i += 1; return i; }
        if (o2 >= 0x80 && o2 <= 0x8F) { in->relKind = 4; in->relOff = i; i += 4; return i; }  /* Jcc rel32 */
        /* ModRM + imm8 forms (pshuf/shld/shrd/bt-imm/cmp-imm) */
        if (o2 == 0x70 || o2 == 0x71 || o2 == 0x72 || o2 == 0x73 ||
            o2 == 0xA4 || o2 == 0xAC || o2 == 0xBA ||
            o2 == 0xC2 || o2 == 0xC4 || o2 == 0xC5 || o2 == 0xC6) {
            e = FrModRM(p + i, asz, &rip); if (rip >= 0) in->ripDisp = i + rip; i += e; i += 1; return i;
        }
        /* no-operand two-byte (syscall, cpuid, rdtsc, ud2, fs/gs push/pop...) */
        if (o2 == 0x05 || o2 == 0x06 || o2 == 0x07 || o2 == 0x08 || o2 == 0x09 ||
            o2 == 0x0B || o2 == 0x0E || o2 == 0x30 || o2 == 0x31 || o2 == 0x32 ||
            o2 == 0x33 || o2 == 0x34 || o2 == 0x35 || o2 == 0x77 || o2 == 0xA0 ||
            o2 == 0xA1 || o2 == 0xA2 || o2 == 0xA8 || o2 == 0xA9 || o2 == 0xAA)
            return i;
        /* ModRM, no immediate: the broad SSE/MMX, cmovcc, setcc, movzx/movsx,
         * bt-reg, bsf/bsr, imul, cmpxchg/xadd, prefetch and group-15 space --
         * which covers every 0F form a compiler emits in a function prologue
         * (incl. endbr64 = 0F 1E). Anything OUTSIDE this enumerated set is
         * refused below, so an unrecognised 0F opcode fails closed rather than
         * being assigned a guessed length. */
        if ((o2 >= 0x00 && o2 <= 0x03) || o2 == 0x0D ||
            (o2 >= 0x10 && o2 <= 0x1F) || (o2 >= 0x28 && o2 <= 0x2F) ||
            (o2 >= 0x40 && o2 <= 0x6F) || (o2 >= 0x74 && o2 <= 0x76) ||
            (o2 >= 0x7C && o2 <= 0x7F) || (o2 >= 0x90 && o2 <= 0x9F) ||
            o2 == 0xA3 || o2 == 0xAB || o2 == 0xAE || o2 == 0xAF ||
            o2 == 0xB0 || o2 == 0xB1 || o2 == 0xB3 || (o2 >= 0xB6 && o2 <= 0xBF) ||
            o2 == 0xC0 || o2 == 0xC1 || o2 == 0xC3 || o2 == 0xC7 ||
            (o2 >= 0xD0 && o2 <= 0xFE)) {
            e = FrModRM(p + i, asz, &rip); if (rip >= 0) in->ripDisp = i + rip; i += e; return i;
        }
        return 0;                              /* unrecognised 0F -> fail closed */
    }

    if (op >= 0x50 && op <= 0x5F) return i;                    /* push/pop r64   */
    if (op >= 0x91 && op <= 0x97) return i;                    /* xchg eax, r    */
    if (op >= 0xB0 && op <= 0xB7) { i += 1; return i; }        /* mov r8, imm8   */
    if (op >= 0xB8 && op <= 0xBF) { i += rexW ? 8 : (osz ? 2 : 4); return i; } /* mov r, imm */
    if (op >= 0x70 && op <= 0x7F) { in->relKind = 1; in->relOff = i; i += 1; return i; }   /* Jcc rel8 */

    switch (op) {
        /* no operands */
        case 0x90: case 0xCC: case 0xC3: case 0xCB: case 0xC9: case 0xF4:
        case 0x98: case 0x99: case 0x9C: case 0x9D:
        case 0xF5: case 0xF8: case 0xF9: case 0xFA: case 0xFB: case 0xFC: case 0xFD:
            return i;
        /* ModRM, no immediate */
        case 0x00: case 0x01: case 0x02: case 0x03:
        case 0x08: case 0x09: case 0x0A: case 0x0B:
        case 0x10: case 0x11: case 0x12: case 0x13:
        case 0x18: case 0x19: case 0x1A: case 0x1B:
        case 0x20: case 0x21: case 0x22: case 0x23:
        case 0x28: case 0x29: case 0x2A: case 0x2B:
        case 0x30: case 0x31: case 0x32: case 0x33:
        case 0x38: case 0x39: case 0x3A: case 0x3B:
        case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8A: case 0x8B:
        case 0x8D: case 0x8F: case 0x63: case 0xFE:
            e = FrModRM(p + i, asz, &rip); if (rip >= 0) in->ripDisp = i + rip; i += e; return i;
        case 0x8C: case 0x8E:
            e = FrModRM(p + i, asz, &rip); if (rip >= 0) in->ripDisp = i + rip; i += e; return i;
        case 0xFF: /* inc/dec/call/jmp/push r/m -- indirect, no rel operand */
            e = FrModRM(p + i, asz, &rip); if (rip >= 0) in->ripDisp = i + rip; i += e; return i;
        /* ModRM + imm8 */
        case 0x80: case 0x82: case 0x83: case 0x6B:
        case 0xC0: case 0xC1: case 0xC6:
            e = FrModRM(p + i, asz, &rip); if (rip >= 0) in->ripDisp = i + rip; i += e; i += 1; return i;
        /* ModRM + imm16/32 */
        case 0x81: case 0x69: case 0xC7:
            e = FrModRM(p + i, asz, &rip); if (rip >= 0) in->ripDisp = i + rip; i += e; i += osz ? 2 : 4; return i;
        /* group 3: imm only for TEST (/0,/1) */
        case 0xF6: { uint8_t mm = p[i]; int reg = (mm >> 3) & 7; e = FrModRM(p + i, asz, &rip); if (rip >= 0) in->ripDisp = i + rip; i += e; if (reg <= 1) i += 1; return i; }
        case 0xF7: { uint8_t mm = p[i]; int reg = (mm >> 3) & 7; e = FrModRM(p + i, asz, &rip); if (rip >= 0) in->ripDisp = i + rip; i += e; if (reg <= 1) i += osz ? 2 : 4; return i; }
        /* accumulator + immediate */
        case 0x04: case 0x0C: case 0x14: case 0x1C: case 0x24: case 0x2C: case 0x34: case 0x3C: case 0xA8:
            i += 1; return i;
        case 0x05: case 0x0D: case 0x15: case 0x1D: case 0x25: case 0x2D: case 0x35: case 0x3D: case 0xA9:
            i += osz ? 2 : 4; return i;
        case 0x68: i += osz ? 2 : 4; return i;            /* push imm32 */
        case 0x6A: i += 1; return i;                      /* push imm8  */
        /* relative branches */
        case 0xE8: case 0xE9: in->relKind = 4; in->relOff = i; i += 4; return i;
        case 0xEB: case 0xE3: in->relKind = 1; in->relOff = i; i += 1; return i;
        default:
            return 0;                                     /* unknown -> fail closed */
    }
}
