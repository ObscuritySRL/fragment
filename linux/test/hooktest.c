/*
 * Unit tests for Fragment's inline-hook engine (hook.h), exercising paths the
 * real-curl matrix structurally cannot reach: trampoline relocation of
 * position-relative prologues, and fail-closed refusal of undecodable /
 * out-of-window prologues. Architecture-specific synthetic targets are
 * hand-assembled machine code placed in executable memory; we hook each with a
 * detour that calls the trampoline and returns its result, then assert the
 * hooked function still behaves like the original. If relocation is wrong the
 * result is wrong or the test crashes.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "../hook.h"

static int g_called = 0;
static int fails    = 0;

#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
                              else { printf("  ok:   %s\n", msg); } } while (0)

/* Copy `code` into executable memory. If `nearRef` is non-NULL the buffer is
 * placed within reach of it (so a position-relative operand still fits). */
static uint8_t* make_fn(const void* code, size_t len, void* nearRef) {
    uint8_t* p = nearRef ? (uint8_t*)FrAllocNear(nearRef, 0x1000)
                         : (uint8_t*)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!p || p == (uint8_t*)MAP_FAILED) return NULL;
    memcpy(p, code, len);
    mprotect(p, 0x1000, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char*)p, (char*)p + 0x1000);
    return p;
}

typedef int (*fn0)(void);
static fn0 t1_tramp, t2_tramp, t3_tramp;
static int t1_detour(void) { g_called++; return t1_tramp(); }
static int t2_detour(void) { g_called++; return t2_tramp(); }
static int t3_detour(void) { g_called++; return t3_tramp(); }

#if defined(__x86_64__)
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    HookEngineInit();

    /* T1: push rbx; sub rsp,0x20; mov eax,0xAB; add rsp,0x20; pop rbx; ret */
    uint8_t t1[] = { 0x53, 0x48,0x83,0xEC,0x20, 0xB8,0xAB,0x00,0x00,0x00,
                     0x48,0x83,0xC4,0x20, 0x5B, 0xC3 };
    uint8_t* f1 = make_fn(t1, sizeof(t1), NULL);
    CHECK(f1 && ((fn0)f1)() == 0xAB, "T1 original returns 0xAB");
    g_called = 0;
    CHECK(InstallHook(f1, (void*)t1_detour, (void**)&t1_tramp), "T1 install (plain prologue)");
    CHECK(((fn0)f1)() == 0xAB, "T1 hooked still returns 0xAB via trampoline");
    CHECK(g_called == 1, "T1 detour ran exactly once");

    /* T2: mov eax,[rip+disp]; ret  (disp patched to point at *g_valp). The
     * read target lives in mmap'd memory so the near trampoline lands in the
     * same region -- which also keeps this runnable under qemu-user, whose
     * /proc/self/maps emulation cannot satisfy a near-allocation to a low
     * static address. */
    int* g_valp = (int*) mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint8_t t2[] = { 0x8B,0x05, 0,0,0,0, 0xC3 };
    uint8_t* f2 = make_fn(t2, sizeof(t2), g_valp);
    {
        mprotect(f2, 0x1000, PROT_READ | PROT_WRITE);
        int32_t disp = (int32_t)((intptr_t)g_valp - ((intptr_t)f2 + 6)); memcpy(f2 + 2, &disp, 4);
        mprotect(f2, 0x1000, PROT_READ | PROT_EXEC);
        __builtin___clear_cache((char*)f2, (char*)f2 + 16);
    }
    *g_valp = 0x1234;
    CHECK(((fn0)f2)() == 0x1234, "T2 original reads g_val=0x1234");
    g_called = 0;
    CHECK(InstallHook(f2, (void*)t2_detour, (void**)&t2_tramp), "T2 install (RIP-relative prologue)");
    *g_valp = 0x5678;
    CHECK(((fn0)f2)() == 0x5678, "T2 trampoline RIP-reloc reads updated g_val (=0x5678)");
    CHECK(g_called == 1, "T2 detour ran exactly once");

    /* T3: jmp +3; int3 x3; mov eax,0xCD; ret  (jmp leaves the copy window) */
    uint8_t t3[] = { 0xE9,0x03,0x00,0x00,0x00, 0xCC,0xCC,0xCC,
                     0xB8,0xCD,0x00,0x00,0x00, 0xC3 };
    uint8_t* f3 = make_fn(t3, sizeof(t3), NULL);
    CHECK(((fn0)f3)() == 0xCD, "T3 original returns 0xCD");
    g_called = 0;
    CHECK(InstallHook(f3, (void*)t3_detour, (void**)&t3_tramp), "T3 install (rel32 jmp prologue)");
    CHECK(((fn0)f3)() == 0xCD, "T3 trampoline rel32-reloc returns 0xCD");
    CHECK(g_called == 1, "T3 detour ran exactly once");

    /* T4: rel8 branch leaving the window MUST fail closed */
    uint8_t t4[] = { 0xEB,0x40, 0x90,0x90,0x90, 0xC3 };
    uint8_t* f4 = make_fn(t4, sizeof(t4), NULL);
    void* tr4 = NULL;
    CHECK(!InstallHook(f4, (void*)t1_detour, &tr4), "T4 rel8-leaving-window refused (fail closed)");
    CHECK(f4[0] == 0xEB, "T4 target left unmodified after refusal");

    /* T5/T6: undecodable opcodes MUST fail closed */
    uint8_t t5[] = { 0x06, 0x90,0x90,0x90,0x90, 0xC3 };   /* 0x06 invalid in x64 */
    uint8_t* f5 = make_fn(t5, sizeof(t5), NULL);
    void* tr5 = NULL;
    CHECK(!InstallHook(f5, (void*)t1_detour, &tr5), "T5 undecodable one-byte opcode refused");
    CHECK(f5[0] == 0x06, "T5 target left unmodified after refusal");

    uint8_t t6[] = { 0x0F,0x04, 0x90,0x90,0x90, 0xC3 };   /* 0F 04 reserved */
    uint8_t* f6 = make_fn(t6, sizeof(t6), NULL);
    void* tr6 = NULL;
    CHECK(!InstallHook(f6, (void*)t1_detour, &tr6), "T6 undecodable 0F opcode refused");

    printf(fails ? "\nHOOKTEST FAILED (%d failures)\n" : "\nHOOKTEST OK\n", fails);
    return fails ? 1 : 0;
}

#elif defined(__i386__)
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    HookEngineInit();

    /* T1: push ebx; sub esp,0x20; mov eax,0xAB; add esp,0x20; pop ebx; ret */
    uint8_t t1[] = { 0x53, 0x83,0xEC,0x20, 0xB8,0xAB,0x00,0x00,0x00,
                     0x83,0xC4,0x20, 0x5B, 0xC3 };
    uint8_t* f1 = make_fn(t1, sizeof(t1), NULL);
    CHECK(f1 && ((fn0)f1)() == 0xAB, "T1 original returns 0xAB");
    g_called = 0;
    CHECK(InstallHook(f1, (void*)t1_detour, (void**)&t1_tramp), "T1 install (plain prologue)");
    CHECK(((fn0)f1)() == 0xAB, "T1 hooked still returns 0xAB via trampoline");
    CHECK(g_called == 1, "T1 detour ran exactly once");

    /* T2: mov eax,[disp32]; ret  (disp32 is ABSOLUTE in 32-bit, so it copies
     * verbatim -- no relocation -- and the trampoline still reads *g_valp). The
     * value lives in mmap'd memory so the near trampoline lands in the same
     * region, which keeps this runnable under qemu-user. */
    int* g_valp = (int*) mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint8_t t2[] = { 0x8B,0x05, 0,0,0,0, 0xC3 };
    uint8_t* f2 = make_fn(t2, sizeof(t2), g_valp);
    {
        mprotect(f2, 0x1000, PROT_READ | PROT_WRITE);
        uint32_t abs = (uint32_t)(uintptr_t)g_valp; memcpy(f2 + 2, &abs, 4);
        mprotect(f2, 0x1000, PROT_READ | PROT_EXEC);
        __builtin___clear_cache((char*)f2, (char*)f2 + 16);
    }
    *g_valp = 0x1234;
    CHECK(((fn0)f2)() == 0x1234, "T2 original reads g_val=0x1234");
    g_called = 0;
    CHECK(InstallHook(f2, (void*)t2_detour, (void**)&t2_tramp), "T2 install (absolute-disp32 prologue)");
    *g_valp = 0x5678;
    CHECK(((fn0)f2)() == 0x5678, "T2 trampoline copies absolute disp32 verbatim (reads 0x5678)");
    CHECK(g_called == 1, "T2 detour ran exactly once");

    /* T3: jmp +3; int3 x3; mov eax,0xCD; ret  (jmp leaves the copy window) */
    uint8_t t3[] = { 0xE9,0x03,0x00,0x00,0x00, 0xCC,0xCC,0xCC,
                     0xB8,0xCD,0x00,0x00,0x00, 0xC3 };
    uint8_t* f3 = make_fn(t3, sizeof(t3), NULL);
    CHECK(((fn0)f3)() == 0xCD, "T3 original returns 0xCD");
    g_called = 0;
    CHECK(InstallHook(f3, (void*)t3_detour, (void**)&t3_tramp), "T3 install (rel32 jmp prologue)");
    CHECK(((fn0)f3)() == 0xCD, "T3 trampoline rel32-reloc returns 0xCD");
    CHECK(g_called == 1, "T3 detour ran exactly once");

    /* T4: rel8 branch leaving the window MUST fail closed */
    uint8_t t4[] = { 0xEB,0x40, 0x90,0x90,0x90, 0xC3 };
    uint8_t* f4 = make_fn(t4, sizeof(t4), NULL);
    void* tr4 = NULL;
    CHECK(!InstallHook(f4, (void*)t1_detour, &tr4), "T4 rel8-leaving-window refused (fail closed)");
    CHECK(f4[0] == 0xEB, "T4 target left unmodified after refusal");

    /* T5/T6: opcodes outside the prologue subset MUST fail closed */
    uint8_t t5[] = { 0x06, 0x90,0x90,0x90,0x90, 0xC3 };   /* 0x06 (push es) outside subset */
    uint8_t* f5 = make_fn(t5, sizeof(t5), NULL);
    void* tr5 = NULL;
    CHECK(!InstallHook(f5, (void*)t1_detour, &tr5), "T5 undecodable one-byte opcode refused");
    CHECK(f5[0] == 0x06, "T5 target left unmodified after refusal");

    uint8_t t6[] = { 0x0F,0x04, 0x90,0x90,0x90, 0xC3 };   /* 0F 04 reserved */
    uint8_t* f6 = make_fn(t6, sizeof(t6), NULL);
    void* tr6 = NULL;
    CHECK(!InstallHook(f6, (void*)t1_detour, &tr6), "T6 undecodable 0F opcode refused");

    printf(fails ? "\nHOOKTEST FAILED (%d failures)\n" : "\nHOOKTEST OK\n", fails);
    return fails ? 1 : 0;
}

#elif defined(__arm__)
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    HookEngineInit();

    /* T1: A32 plain prologue (push {r4,lr}; mov r0,#0xAB; pop {r4,pc}). */
    uint8_t t1[] = { 0x10,0x40,0x2D,0xE9, 0xAB,0x00,0xA0,0xE3, 0x10,0x80,0xBD,0xE8 };
    uint8_t* f1 = make_fn(t1, sizeof(t1), NULL);
    CHECK(f1 && ((fn0)f1)() == 0xAB, "T1 (A32) original returns 0xAB");
    g_called = 0;
    CHECK(InstallHook(f1, (void*)t1_detour, (void**)&t1_tramp), "T1 install (A32 plain prologue)");
    CHECK(((fn0)f1)() == 0xAB, "T1 hooked still returns 0xAB via trampoline");
    CHECK(g_called == 1, "T1 detour ran exactly once");

    /* T2: T32 plain prologue (push {r4,lr}; movs r0,#0xCD; pop {r4,pc}). The
     * Thumb bit (bit 0) is set in the callable pointer. */
    uint8_t t2[] = { 0x10,0xB5, 0xCD,0x20, 0x10,0xBD };
    uint8_t* f2b = make_fn(t2, sizeof(t2), NULL);
    fn0 f2 = (fn0)((uintptr_t)f2b | 1);
    CHECK(f2b && f2() == 0xCD, "T2 (T32) original returns 0xCD");
    g_called = 0;
    CHECK(InstallHook((void*)f2, (void*)t2_detour, (void**)&t2_tramp), "T2 install (T32 plain prologue)");
    CHECK(f2() == 0xCD, "T2 hooked still returns 0xCD via trampoline");
    CHECK(g_called == 1, "T2 detour ran exactly once");

    /* T3: A32, first instruction is a B leaving the window -> B relocation. */
    uint8_t t3[] = { 0x01,0x00,0x00,0xEA, 0xF0,0x00,0xF0,0xE7, 0xF0,0x00,0xF0,0xE7,
                     0xCD,0x00,0xA0,0xE3, 0x1E,0xFF,0x2F,0xE1 };
    uint8_t* f3 = make_fn(t3, sizeof(t3), NULL);
    CHECK(((fn0)f3)() == 0xCD, "T3 (A32) original returns 0xCD");
    g_called = 0;
    CHECK(InstallHook(f3, (void*)t3_detour, (void**)&t3_tramp), "T3 install (A32 B-relative prologue)");
    CHECK(((fn0)f3)() == 0xCD, "T3 trampoline B-reloc returns 0xCD");
    CHECK(g_called == 1, "T3 detour ran exactly once");

    /* T4: T32 LDR-literal prologue -- relocated through the trampoline literal
     * pool (the loaded constant is copied and the load re-pointed). */
    uint8_t t4[] = { 0x00,0x48, 0x70,0x47, 0xCD,0x00,0x00,0x00 };
    uint8_t* f4b = make_fn(t4, sizeof(t4), NULL);
    fn0 f4 = (fn0)((uintptr_t)f4b | 1);
    CHECK(f4() == 0xCD, "T4 (T32) original loads literal 0xCD");
    g_called = 0;
    CHECK(InstallHook((void*)f4, (void*)t2_detour, (void**)&t2_tramp), "T4 install (T32 LDR-literal, pooled)");
    CHECK(f4() == 0xCD, "T4 trampoline pooled-literal returns 0xCD");
    CHECK(g_called == 1, "T4 detour ran exactly once");

    /* T5: A32 LDR-literal prologue -- relocated through the literal pool too. */
    uint8_t t5[] = { 0x00,0x00,0x9F,0xE5, 0x1E,0xFF,0x2F,0xE1, 0xCD,0x00,0x00,0x00 };
    uint8_t* f5 = make_fn(t5, sizeof(t5), NULL);
    CHECK(((fn0)f5)() == 0xCD, "T5 (A32) original loads literal 0xCD");
    g_called = 0;
    CHECK(InstallHook(f5, (void*)t3_detour, (void**)&t3_tramp), "T5 install (A32 LDR-literal, pooled)");
    CHECK(((fn0)f5)() == 0xCD, "T5 trampoline pooled-literal returns 0xCD");
    CHECK(g_called == 1, "T5 detour ran exactly once");

    /* T6: T32 `add rd,pc` re-bases on PC and cannot be pooled -> fail closed. */
    uint8_t t6[] = { 0x78,0x44, 0x70,0x47 };
    uint8_t* f6 = make_fn(t6, sizeof(t6), NULL);
    void* tr6 = NULL;
    CHECK(!InstallHook((void*)((uintptr_t)f6 | 1), (void*)t1_detour, &tr6), "T6 (T32) add-pc refused (fail closed)");
    CHECK(f6[0] == 0x78 && f6[1] == 0x44, "T6 target left unmodified after refusal");

    /* T7: A32 ADR (add rd,pc,#imm) -> fail closed. */
    uint8_t t7[] = { 0x04,0x00,0x8F,0xE2, 0x1E,0xFF,0x2F,0xE1 };
    uint8_t* f7 = make_fn(t7, sizeof(t7), NULL);
    void* tr7 = NULL;
    CHECK(!InstallHook(f7, (void*)t1_detour, &tr7), "T7 (A32) ADR refused (fail closed)");
    CHECK(f7[0] == 0x04 && f7[3] == 0xE2, "T7 target left unmodified after refusal");

    /* T8: T32 `vldr d0,[pc,#imm]` -- a non-word PC-relative literal (the head of
     * a stock double-returning prologue). It is not the pooled word `ldr`, so it
     * MUST fail closed rather than be copied verbatim. */
    uint8_t t8[] = { 0x9F,0xED,0x01,0x0B, 0x70,0x47, 0x00,0xBF,
                     0x6E,0x86,0x1B,0xF0, 0xF9,0x21,0x09,0x40 };
    uint8_t* f8 = make_fn(t8, sizeof(t8), NULL);
    void* tr8 = NULL;
    CHECK(!InstallHook((void*)((uintptr_t)f8 | 1), (void*)t1_detour, &tr8), "T8 (T32) vldr-literal refused (fail closed)");
    CHECK(f8[0] == 0x9F && f8[1] == 0xED, "T8 target left unmodified after refusal");

    printf(fails ? "\nHOOKTEST FAILED (%d failures)\n" : "\nHOOKTEST OK\n", fails);
    return fails ? 1 : 0;
}

#else /* __aarch64__ */
static int g_val = 0x1234;   /* read via an ADRP+LDR in T2 */

/* Encode `adrp Rd, page(target)` for an instruction sitting at `pc`. */
static uint32_t enc_adrp(int rd, uintptr_t pc, uintptr_t target) {
    int64_t imm = (int64_t)((target & ~(uintptr_t)0xFFF)) - (int64_t)(pc & ~(uintptr_t)0xFFF);
    imm >>= 12;
    uint32_t immlo = (uint32_t)(imm & 3), immhi = (uint32_t)((imm >> 2) & 0x7FFFF);
    return 0x90000000u | (immlo << 29) | (immhi << 5) | (uint32_t)rd;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    HookEngineInit();

    /* T1: mov w0,#0xAB ; ret  (first insn position-independent -> copy as-is) */
    uint32_t t1[] = { 0x52801560u, 0xD65F03C0u };
    uint8_t* f1 = make_fn(t1, sizeof(t1), NULL);
    CHECK(f1 && ((fn0)f1)() == 0xAB, "T1 original returns 0xAB");
    g_called = 0;
    CHECK(InstallHook(f1, (void*)t1_detour, (void**)&t1_tramp), "T1 install (plain prologue)");
    CHECK(((fn0)f1)() == 0xAB, "T1 hooked still returns 0xAB via trampoline");
    CHECK(g_called == 1, "T1 detour ran exactly once");

    /* T2: adrp x1,page(&g_val) ; ldr w0,[x1,#off] ; ret  (ADRP relocation) */
    uint32_t t2[] = { 0x90000001u, 0xB9400020u, 0xD65F03C0u };
    uint8_t* f2 = make_fn(t2, sizeof(t2), &g_val);
    {
        mprotect(f2, 0x1000, PROT_READ | PROT_WRITE);
        uint32_t adrp = enc_adrp(1, (uintptr_t)f2, (uintptr_t)&g_val);
        uint32_t off  = (uint32_t)((uintptr_t)&g_val & 0xFFF);
        uint32_t ldr  = 0xB9400000u | (((off >> 2) & 0xFFF) << 10) | (1u << 5) | 0u; /* ldr w0,[x1,#off] */
        memcpy(f2 + 0, &adrp, 4);
        memcpy(f2 + 4, &ldr, 4);
        mprotect(f2, 0x1000, PROT_READ | PROT_EXEC);
        __builtin___clear_cache((char*)f2, (char*)f2 + 0x1000);
    }
    g_val = 0x1234;
    CHECK(((fn0)f2)() == 0x1234, "T2 original reads g_val=0x1234");
    g_called = 0;
    CHECK(InstallHook(f2, (void*)t2_detour, (void**)&t2_tramp), "T2 install (ADRP prologue)");
    g_val = 0x5678;
    CHECK(((fn0)f2)() == 0x5678, "T2 trampoline ADRP-reloc reads updated g_val (=0x5678)");
    CHECK(g_called == 1, "T2 detour ran exactly once");

    /* T3: b +12 ; udf ; udf ; mov w0,#0xCD ; ret  (B leaves the copy window) */
    uint32_t t3[] = { 0x14000003u, 0x00000000u, 0x00000000u, 0x528019A0u, 0xD65F03C0u };
    uint8_t* f3 = make_fn(t3, sizeof(t3), NULL);
    CHECK(((fn0)f3)() == 0xCD, "T3 original returns 0xCD");
    g_called = 0;
    CHECK(InstallHook(f3, (void*)t3_detour, (void**)&t3_tramp), "T3 install (B-relative prologue)");
    CHECK(((fn0)f3)() == 0xCD, "T3 trampoline B-reloc returns 0xCD");
    CHECK(g_called == 1, "T3 detour ran exactly once");

    /* T4: cbz x0,#8 as the first instruction MUST fail closed (a short
     * conditional branch leaving the window cannot be guaranteed to reach). */
    uint32_t t4[] = { 0xB4000040u, 0xD2800000u, 0xD65F03C0u };
    uint8_t* f4 = make_fn(t4, sizeof(t4), NULL);
    void* tr4 = NULL;
    uint32_t orig4; memcpy(&orig4, f4, 4);
    CHECK(!InstallHook(f4, (void*)t1_detour, &tr4), "T4 cbz-leaving-window refused (fail closed)");
    { uint32_t now; memcpy(&now, f4, 4); CHECK(now == orig4, "T4 target left unmodified after refusal"); }

    printf(fails ? "\nHOOKTEST FAILED (%d failures)\n" : "\nHOOKTEST OK\n", fails);
    return fails ? 1 : 0;
}
#endif
