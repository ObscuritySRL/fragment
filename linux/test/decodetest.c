/*
 * Unit tests for the shared x86 length-decoder (common/arch/x86/decode.h),
 * selected at 32 or 64 bits via -DFR_DT_BITS. Unlike hooktest -- which installs
 * a real hook and therefore only runs on the host's own architecture -- the
 * decoder is pure byte arithmetic, so this exercises BOTH widths natively on any
 * host (it never executes the bytes it decodes). That is what lets the x86-64
 * decoder be regression-checked on a box with no qemu-x86_64, and gives the i386
 * backend a non-vacuous reloc-metadata + fail-closed check of its own.
 *
 * Each case asserts the reported instruction length and the relocation metadata
 * (RIP-relative disp offset, rel8/rel32 branch kind + operand offset). The
 * 32-bit and 64-bit expectations diverge exactly where the encodings do: a bare
 * disp32 is RIP-relative at 64 bits but absolute at 32, 0x40-0x4F is a REX prefix
 * at 64 bits but INC/DEC reg at 32, and a REX.W mov-immediate is eight bytes.
 */
#include <stdio.h>
#include <stdint.h>

#if FR_DT_BITS == 64
#include "../../common/arch/x86_64/decode.h"
#define WIDTH "x86-64"
#else
#include "../../common/arch/i386/decode.h"
#define WIDTH "i386"
#endif

static int fails = 0;

#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
                              else { printf("  ok:   %s\n", msg); } } while (0)

/* Decode `bytes` and assert length + relocation metadata match expectations. */
static void expect(const char* name, const uint8_t* bytes,
                   int len, int ripDisp, int relKind, int relOff) {
    FrInsn in;
    int got = FrDecode(bytes, &in);
    int ok = got == len && in.ripDisp == ripDisp &&
             in.relKind == relKind && in.relOff == relOff;
    if (!ok)
        printf("  FAIL: %s -> len=%d rip=%d rel=%d off=%d (want %d/%d/%d/%d)\n",
               name, got, in.ripDisp, in.relKind, in.relOff, len, ripDisp, relKind, relOff);
    else
        printf("  ok:   %s\n", name);
    if (!ok) fails++;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("== decode unit test (%s) ==\n", WIDTH);

    /* --- common prologue instructions (identical at both widths) ---------- */
    expect("push reg (0x55)",          (uint8_t[]){0x55},                         1, -1, 0, -1);
    expect("pop reg (0x5D)",           (uint8_t[]){0x5D},                         1, -1, 0, -1);
    expect("mov ebp,esp (89 E5)",      (uint8_t[]){0x89,0xE5},                    2, -1, 0, -1);
    expect("sub esp,imm8 (83 EC 10)",  (uint8_t[]){0x83,0xEC,0x10},               3, -1, 0, -1);
    expect("mov reg,imm32 (B8 ..)",    (uint8_t[]){0xB8,0x44,0x33,0x22,0x11},     5, -1, 0, -1);
    expect("nop (0x90)",               (uint8_t[]){0x90},                         1, -1, 0, -1);
    expect("ret (0xC3)",               (uint8_t[]){0xC3},                         1, -1, 0, -1);
    expect("endbr (F3 0F 1E FA)",      (uint8_t[]){0xF3,0x0F,0x1E,0xFA},          4, -1, 0, -1);

    /* --- relative branches: relocated when copied out of the prologue ------ */
    expect("jmp rel32 (E9 ..)",        (uint8_t[]){0xE9,0,0,0,0},                 5, -1, 4,  1);
    expect("call rel32 (E8 ..)",       (uint8_t[]){0xE8,0,0,0,0},                 5, -1, 4,  1);
    expect("jmp rel8 (EB ..)",         (uint8_t[]){0xEB,0x10},                    2, -1, 1,  1);
    expect("jcc rel8 (74 ..)",         (uint8_t[]){0x74,0x10},                    2, -1, 1,  1);
    expect("jcc rel32 (0F 84 ..)",     (uint8_t[]){0x0F,0x84,0,0,0,0},            6, -1, 4,  2);

    /* --- the width-dependent cases ---------------------------------------- */
#if FR_DT_BITS == 64
    /* a bare disp32 is RIP-relative: the disp must be relocated. */
    expect("mov eax,[rip+d32]",        (uint8_t[]){0x8B,0x05,0,0,0,0},            6,  2, 0, -1);
    /* REX.W widens the mov-immediate to eight bytes and is consumed as a prefix. */
    expect("mov rbp,rsp (48 89 E5)",   (uint8_t[]){0x48,0x89,0xE5},               3, -1, 0, -1);
    expect("mov rax,imm64 (48 B8 ..)", (uint8_t[]){0x48,0xB8,1,2,3,4,5,6,7,8},   10, -1, 0, -1);
    /* a 0x66 on a near branch is ignored: it stays a rel32 (64-bit only). */
    expect("66 jmp rel32 (still 32)",  (uint8_t[]){0x66,0xE9,0,0,0,0},            6, -1, 4,  2);
#else
    /* a bare disp32 is an ABSOLUTE address: copied verbatim, never relocated. */
    expect("mov eax,[d32] (8B 05 ..)", (uint8_t[]){0x8B,0x05,0,0,0,0},            6, -1, 0, -1);
    /* 0x40-0x4F are INC/DEC reg, one byte -- not a prefix. */
    expect("inc eax (0x40)",           (uint8_t[]){0x40},                         1, -1, 0, -1);
    expect("dec eax (0x48)",           (uint8_t[]){0x48},                         1, -1, 0, -1);
    expect("inc edi (0x47)",           (uint8_t[]){0x47},                         1, -1, 0, -1);
    /* mov eax,gs:0x14 -- the stack-protector canary load (moffs32). */
    expect("mov eax,gs:0x14 (65 A1 ..)", (uint8_t[]){0x65,0xA1,0x14,0,0,0},       6, -1, 0, -1);
    /* 16-bit operand/address overrides are outside the subset -> fail closed. */
    expect("66 rel16 jmp refused",     (uint8_t[]){0x66,0xE9,0x11,0x22},          0, -1, 0, -1);
    expect("67 16-bit addr refused",   (uint8_t[]){0x67,0x8B,0x06,0,0},           0, -1, 0, -1);
#endif

    /* --- fail closed: an opcode outside the prologue subset returns 0 ------ */
    expect("undecodable 1-byte (0x06)",(uint8_t[]){0x06,0x90,0x90},               0, -1, 0, -1);
    expect("undecodable 0F (0F 04)",   (uint8_t[]){0x0F,0x04,0x90},               0, -1, 0, -1);

    printf(fails ? "\nDECODETEST FAILED (%d failures)\n" : "\nDECODETEST OK\n", fails);
    return fails ? 1 : 0;
}
