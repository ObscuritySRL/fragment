/*
 * Unit tests for Fragment's inline-hook engine (hook.h), exercising paths the
 * real-curl matrix structurally cannot reach: trampoline relocation of
 * position-relative prologues, and fail-closed refusal of undecodable /
 * out-of-window prologues. Width-specific synthetic targets are hand-assembled
 * machine code placed in executable memory; we hook each with a detour that
 * calls the trampoline and returns its result, then assert the hooked function
 * still behaves like the original. If relocation is wrong the result is wrong
 * or the test crashes.
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../hook.h"

static int g_val    = 0x1234;   /* read via a disp32 memory load in T2 */
static int g_called = 0;
static int fails    = 0;

#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
                              else { printf("  ok:   %s\n", msg); } } while (0)

/* Copy `code` into executable memory. If `nearRef` is non-NULL the buffer is
 * placed within reach of it (so a position-relative operand still fits). */
static uint8_t* make_fn(const uint8_t* code, size_t len, void* nearRef) {
    uint8_t* p = nearRef ? (uint8_t*)FrAllocNear(nearRef, 0x1000)
                         : (uint8_t*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p) return NULL;
    memcpy(p, code, len);
    DWORD old;
    VirtualProtect(p, 0x1000, PAGE_EXECUTE_READ, &old);
    FlushInstructionCache(GetCurrentProcess(), p, 0x1000);
    return p;
}

typedef int (*fn0)(void);

static fn0 t1_tramp, t2_tramp, t3_tramp;
static int t1_detour(void) { g_called++; return t1_tramp(); }
static int t2_detour(void) { g_called++; return t2_tramp(); }
static int t3_detour(void) { g_called++; return t3_tramp(); }

#if defined(_M_X64) || defined(__x86_64__)
int main(void) {
    HookEngineInit();

    /* ---- T1: ordinary push/sub prologue ----------------------------------
     * push rbx; sub rsp,0x20; mov eax,0xAB; add rsp,0x20; pop rbx; ret */
    uint8_t t1[] = { 0x53, 0x48,0x83,0xEC,0x20, 0xB8,0xAB,0x00,0x00,0x00,
                     0x48,0x83,0xC4,0x20, 0x5B, 0xC3 };
    uint8_t* f1 = make_fn(t1, sizeof(t1), NULL);
    CHECK(f1 && ((fn0)f1)() == 0xAB, "T1 original returns 0xAB");
    g_called = 0;
    CHECK(InstallHook(f1, (void*)t1_detour, (void**)&t1_tramp), "T1 install (plain prologue)");
    CHECK(((fn0)f1)() == 0xAB, "T1 hooked still returns 0xAB via trampoline");
    CHECK(g_called == 1, "T1 detour ran exactly once");

    /* ---- T2: RIP-relative load prologue (exercises ripDisp relocation) ----
     * mov eax,[rip+disp]; ret   (disp patched at runtime to &g_val) */
    uint8_t t2[] = { 0x8B,0x05, 0,0,0,0, 0xC3 };
    uint8_t* f2 = make_fn(t2, sizeof(t2), &g_val);   /* near g_val so disp fits */
    {
        DWORD old;
        VirtualProtect(f2, 0x1000, PAGE_READWRITE, &old);
        int32_t disp = (int32_t)((intptr_t)&g_val - ((intptr_t)f2 + 6));
        memcpy(f2 + 2, &disp, 4);
        VirtualProtect(f2, 0x1000, PAGE_EXECUTE_READ, &old);
        FlushInstructionCache(GetCurrentProcess(), f2, 0x1000);
    }
    g_val = 0x1234;
    CHECK(((fn0)f2)() == 0x1234, "T2 original reads g_val=0x1234");
    g_called = 0;
    CHECK(InstallHook(f2, (void*)t2_detour, (void**)&t2_tramp), "T2 install (RIP-relative prologue)");
    g_val = 0x5678;
    CHECK(((fn0)f2)() == 0x5678, "T2 trampoline RIP-reloc reads updated g_val (=0x5678)");
    CHECK(g_called == 1, "T2 detour ran exactly once");

    /* ---- T3: rel32 jmp prologue (exercises rel32 branch relocation) -------
     * jmp +3; int3 x3; mov eax,0xCD; ret  -- the jmp leaves the copy window */
    uint8_t t3[] = { 0xE9,0x03,0x00,0x00,0x00, 0xCC,0xCC,0xCC,
                     0xB8,0xCD,0x00,0x00,0x00, 0xC3 };
    uint8_t* f3 = make_fn(t3, sizeof(t3), NULL);
    CHECK(((fn0)f3)() == 0xCD, "T3 original returns 0xCD");
    g_called = 0;
    CHECK(InstallHook(f3, (void*)t3_detour, (void**)&t3_tramp), "T3 install (rel32 jmp prologue)");
    CHECK(((fn0)f3)() == 0xCD, "T3 trampoline rel32-reloc returns 0xCD");
    CHECK(g_called == 1, "T3 detour ran exactly once");

    /* ---- T4: rel8 branch leaving the window MUST fail closed -------------- */
    uint8_t t4[] = { 0xEB,0x40, 0x90,0x90,0x90, 0xC3 };
    uint8_t* f4 = make_fn(t4, sizeof(t4), NULL);
    void* tr4 = NULL;
    CHECK(!InstallHook(f4, (void*)t1_detour, &tr4), "T4 rel8-leaving-window refused (fail closed)");
    CHECK(f4[0] == 0xEB, "T4 target left unmodified after refusal");

    /* ---- T5/T6: undecodable opcodes MUST fail closed --------------------- */
    uint8_t t5[] = { 0x06, 0x90,0x90,0x90,0x90, 0xC3 };   /* 0x06 invalid in x64 */
    uint8_t* f5 = make_fn(t5, sizeof(t5), NULL);
    void* tr5 = NULL;
    CHECK(!InstallHook(f5, (void*)t1_detour, &tr5), "T5 undecodable one-byte opcode refused");
    CHECK(f5[0] == 0x06, "T5 target left unmodified after refusal");

    uint8_t t6[] = { 0x0F,0x04, 0x90,0x90,0x90, 0xC3 };   /* 0F 04 reserved */
    uint8_t* f6 = make_fn(t6, sizeof(t6), NULL);
    void* tr6 = NULL;
    CHECK(!InstallHook(f6, (void*)t1_detour, &tr6), "T6 undecodable 0F opcode refused (M2)");

    printf(fails ? "\nHOOKTEST FAILED (%d failures)\n" : "\nHOOKTEST OK\n", fails);
    return fails ? 1 : 0;
}

#elif defined(_M_IX86) || defined(__i386__)
int main(void) {
    HookEngineInit();

    /* ---- T1: ordinary push/sub prologue ----------------------------------
     * push ebx; sub esp,0x20; mov eax,0xAB; add esp,0x20; pop ebx; ret. The
     * 64-bit form's 0x48 REX.W bytes are INC/DEC opcodes in IA-32, so each
     * width hand-assembles its own encoding. */
    uint8_t t1[] = { 0x53, 0x83,0xEC,0x20, 0xB8,0xAB,0x00,0x00,0x00,
                     0x83,0xC4,0x20, 0x5B, 0xC3 };
    uint8_t* f1 = make_fn(t1, sizeof(t1), NULL);
    CHECK(f1 && ((fn0)f1)() == 0xAB, "T1 original returns 0xAB");
    g_called = 0;
    CHECK(InstallHook(f1, (void*)t1_detour, (void**)&t1_tramp), "T1 install (plain prologue)");
    CHECK(((fn0)f1)() == 0xAB, "T1 hooked still returns 0xAB via trampoline");
    CHECK(g_called == 1, "T1 detour ran exactly once");

    /* ---- T2: absolute-disp32 memory-operand prologue ---------------------
     * mov eax,[disp32]; ret. In 32-bit a bare disp32 is an ABSOLUTE address
     * (IA-32 has no RIP-relative form), so the prologue copies verbatim -- no
     * relocation -- and the trampoline still reads g_val. */
    uint8_t t2[] = { 0x8B,0x05, 0,0,0,0, 0xC3 };
    uint8_t* f2 = make_fn(t2, sizeof(t2), &g_val);
    {
        DWORD old;
        VirtualProtect(f2, 0x1000, PAGE_READWRITE, &old);
        uint32_t abs = (uint32_t)(uintptr_t)&g_val;
        memcpy(f2 + 2, &abs, 4);
        VirtualProtect(f2, 0x1000, PAGE_EXECUTE_READ, &old);
        FlushInstructionCache(GetCurrentProcess(), f2, 0x1000);
    }
    g_val = 0x1234;
    CHECK(((fn0)f2)() == 0x1234, "T2 original reads g_val=0x1234");
    g_called = 0;
    CHECK(InstallHook(f2, (void*)t2_detour, (void**)&t2_tramp), "T2 install (absolute-disp32 prologue)");
    g_val = 0x5678;
    CHECK(((fn0)f2)() == 0x5678, "T2 trampoline copies absolute disp32 verbatim (reads 0x5678)");
    CHECK(g_called == 1, "T2 detour ran exactly once");

    /* ---- T3: rel32 jmp prologue (exercises rel32 branch relocation) -------
     * jmp +3; int3 x3; mov eax,0xCD; ret  -- the jmp leaves the copy window */
    uint8_t t3[] = { 0xE9,0x03,0x00,0x00,0x00, 0xCC,0xCC,0xCC,
                     0xB8,0xCD,0x00,0x00,0x00, 0xC3 };
    uint8_t* f3 = make_fn(t3, sizeof(t3), NULL);
    CHECK(((fn0)f3)() == 0xCD, "T3 original returns 0xCD");
    g_called = 0;
    CHECK(InstallHook(f3, (void*)t3_detour, (void**)&t3_tramp), "T3 install (rel32 jmp prologue)");
    CHECK(((fn0)f3)() == 0xCD, "T3 trampoline rel32-reloc returns 0xCD");
    CHECK(g_called == 1, "T3 detour ran exactly once");

    /* ---- T4: rel8 branch leaving the window MUST fail closed -------------- */
    uint8_t t4[] = { 0xEB,0x40, 0x90,0x90,0x90, 0xC3 };
    uint8_t* f4 = make_fn(t4, sizeof(t4), NULL);
    void* tr4 = NULL;
    CHECK(!InstallHook(f4, (void*)t1_detour, &tr4), "T4 rel8-leaving-window refused (fail closed)");
    CHECK(f4[0] == 0xEB, "T4 target left unmodified after refusal");

    /* ---- T5/T6: opcodes outside the prologue subset MUST fail closed ------ */
    uint8_t t5[] = { 0x06, 0x90,0x90,0x90,0x90, 0xC3 };   /* 0x06 (push es) outside subset */
    uint8_t* f5 = make_fn(t5, sizeof(t5), NULL);
    void* tr5 = NULL;
    CHECK(!InstallHook(f5, (void*)t1_detour, &tr5), "T5 undecodable one-byte opcode refused");
    CHECK(f5[0] == 0x06, "T5 target left unmodified after refusal");

    uint8_t t6[] = { 0x0F,0x04, 0x90,0x90,0x90, 0xC3 };   /* 0F 04 reserved */
    uint8_t* f6 = make_fn(t6, sizeof(t6), NULL);
    void* tr6 = NULL;
    CHECK(!InstallHook(f6, (void*)t1_detour, &tr6), "T6 undecodable 0F opcode refused (M2)");

    printf(fails ? "\nHOOKTEST FAILED (%d failures)\n" : "\nHOOKTEST OK\n", fails);
    return fails ? 1 : 0;
}

#endif
