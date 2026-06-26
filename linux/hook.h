#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>
#include "log.h"

#if !defined(__x86_64__) && !defined(__i386__) && !defined(__aarch64__)
#error "Fragment's hook engine (caller stubs, prologue decoder, patch) is x86-64 / i386 / aarch64 only."
#endif

/*
 * Fragment's own inline-hook engine (no third-party dependency).
 *
 * On Linux the broad, portable interception is symbol interposition (see
 * main.c); this engine is the best-effort fallback that reaches what
 * interposition structurally cannot -- a statically-linked curl, or a dlopen'd
 * curl an app calls through pointers it never asked the loader to resolve. To
 * hook a function we:
 *   1. length-decode its prologue until we have >= one whole jump's worth of
 *      bytes (5 on x86-64 for an E9 rel32; a single 4-byte instruction on
 *      aarch64, where the patch is one B);
 *   2. allocate a small executable block WITHIN reach of the target (+/-2 GB on
 *      x86-64 so a 5-byte E9 can reach it; +/-128 MB on aarch64 so a B can)
 *      holding a "trampoline" (the relocated prologue followed by a jump back
 *      into the function body) and a "relay" (an absolute jump to the detour);
 *   3. overwrite the target's first bytes with a jump to the relay, padding any
 *      leftover bytes with NOPs (x86-64 only; aarch64 patches exactly 4).
 *
 * Calling the returned trampoline therefore runs the original function. The
 * near jump only needs to reach the relay; the relay's absolute jump can reach
 * a detour anywhere in the address space, so the detour need not be near the
 * target.
 *
 * The decoder recognises the common instruction subset compilers emit in
 * function prologues. If it meets anything it cannot relocate with certainty
 * (an unknown opcode, a short branch leaving the copied window, or a
 * PC-relative operand whose relocated form will not fit), it FAILS CLOSED: it
 * refuses the hook and leaves the target untouched, so a mis-decode can never
 * corrupt the process.
 *
 * Residual hazards (documented for honesty):
 *   (1) the patch is not performed under thread suspension. On x86-64 a thread
 *       executing the target's first bytes at the instant of install could read
 *       a torn instruction (mitigated by an aligned 8-byte atomic publish where
 *       the prologue allows; aarch64 patches a single naturally-aligned 4-byte
 *       word, which is atomic, so it has no torn-write window). Safe in
 *       Fragment's flow regardless: hooks land before the curl module is
 *       exercised.
 *   (2) we NOP-fill the x86-64 prologue bytes in [jmpLen, copyLen); if some
 *       other instruction branches into that range, the landing site is
 *       destroyed. We copy the MINIMAL prologue to shrink this window but do not
 *       prove no internal target exists. (aarch64 copies exactly one
 *       instruction, so there is no fill range.)
 */

/* ---- near-block allocation ------------------------------------------------ */
#if defined(__x86_64__) || defined(__i386__)
#define FR_REACH 0x7FFF0000ULL     /* stay safely under 2 GB (E9 rel32)     */
#else
#define FR_REACH 0x07FF0000ULL     /* stay safely under 128 MB (B imm26)    */
#endif

/* ---- installed-hook registry (for clean teardown) ---------------------- */
typedef struct FrHook {
    void*          target;
    void*          block;
    size_t         blockSize;
    uint8_t        saved[24];
    size_t         savedLen;
    struct FrHook* next;
} FrHook;

static FrHook*         gFrHooks = NULL;
/* Recursive on purpose: InstallHook runs inside it, and via the dlopen
 * interposer HookCurl->InstallHook can re-enter on the SAME thread (a hooked
 * module's initializer triggers another dlopen). A non-recursive lock would
 * self-deadlock -- the exact reasoning behind the Windows build's recursive
 * critical section. */
static pthread_mutex_t gFrLock;
static volatile int    gFrReady = 0;

/* glibc's allocator is reentrant for our nested-but-not-interrupted usage
 * (the dlopen interposer calls the real dlopen, then allocates AFTER it
 * returns -- never mid-malloc), so unlike the Windows build there is no
 * loader-lock/CRT-heap deadlock to dodge and no private heap is needed. */
static void* FrHeapAlloc(size_t n) { return calloc(1, n); }
static void  FrHeapFree(void* p)   { free(p); }

/* First call is single-threaded (the .so constructor, before any detour or
 * interposer can fire). Publish gFrReady AFTER the lock is constructed. */
static void HookEngineInit(void) {
    static volatile int once = 0;
    int expected = 0;
    if (__atomic_compare_exchange_n(&once, &expected, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        pthread_mutexattr_t a;
        pthread_mutexattr_init(&a);
        pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&gFrLock, &a);
        pthread_mutexattr_destroy(&a);
        __atomic_store_n(&gFrReady, 1, __ATOMIC_RELEASE);
    }
}

/* True if `target` already has a hook installed. The teardown registry is the
 * single source of truth, so dedup needs no separate (fixed-size) table: it is
 * unbounded and can never silently stop deduping. Caller serializes resolve+
 * check+install (gHookLock) so there is no TOCTOU between this and InstallHook. */
static int FrIsHooked(void* target) {
    if (!gFrReady) return 0;
    int found = 0;
    pthread_mutex_lock(&gFrLock);
    for (FrHook* h = gFrHooks; h; h = h->next)
        if (h->target == target) { found = 1; break; }
    pthread_mutex_unlock(&gFrLock);
    return found;
}

/* Change protection on the page(s) spanning [addr, addr+len). */
static int FrProtect(void* addr, size_t len, int prot) {
    long pg = sysconf(_SC_PAGESIZE);
    uintptr_t m = (uintptr_t)(pg > 0 ? pg : 4096) - 1;
    uintptr_t s = (uintptr_t)addr & ~m;
    uintptr_t e = ((uintptr_t)addr + len + m) & ~m;
    return mprotect((void*)s, e - s, prot) == 0;
}

/* Try to map exactly `size` RW bytes at `addr` without clobbering an existing
 * mapping (MAP_FIXED_NOREPLACE). Returns the block or NULL. */
static void* FrMapAt(uintptr_t addr, size_t size) {
    void* p = mmap((void*)addr, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (p == MAP_FAILED) return NULL;
    if ((uintptr_t)p != addr) { munmap(p, size); return NULL; } /* pre-4.17 kernels */
    return p;
}

/* If `target` is hooked, return its trampoline (a callable that behaves as the
 * un-hooked original); else NULL. Lets an interposer that has already rewritten
 * forward to the original without re-entering an incidental inline hook. */
static void* FrTrampolineFor(void* target) {
    if (!gFrReady) return NULL;
    void* tramp = NULL;
    pthread_mutex_lock(&gFrLock);
    for (FrHook* h = gFrHooks; h; h = h->next)
        if (h->target == target) { tramp = h->block; break; }  /* block start == trampoline */
    pthread_mutex_unlock(&gFrLock);
    return tramp;
}

/* Reserve+commit `size` bytes whose address is within FR_REACH of `target`, so
 * a near jump from the target can reach it. First lets the kernel place it
 * (mappings cluster, so the freebie is usually already in range); otherwise
 * probes outward from the target with MAP_FIXED_NOREPLACE. Deliberately avoids
 * /proc/self/maps -- it is unnecessary here and some emulators cannot synthesise
 * it -- so a free slot is found by trying, not by parsing the map. Returns NULL
 * if nothing free is in range. */
static void* FrAllocNear(void* target, size_t size) {
    long pgl = sysconf(_SC_PAGESIZE);
    uintptr_t gran = (uintptr_t)(pgl > 0 ? pgl : 4096);
    uintptr_t t  = (uintptr_t)target;
    uintptr_t reach = FR_REACH;
    uintptr_t lo = (t > reach) ? (t - reach) : gran;
    uintptr_t hi = (t + reach < t) ? (uintptr_t)-1 : t + reach;

    /* 1. cheap: let the kernel place it; accept if within reach. */
    void* p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p != MAP_FAILED) {
        uintptr_t d = (uintptr_t)p > t ? (uintptr_t)p - t : t - (uintptr_t)p;
        if (d <= reach) return p;
        munmap(p, size);
    }

    /* 2. probe outward from the target. Page-granular for the first megabyte
     * (find a close slot fast), then in ~1 MB strides out to the reach limit. */
    uintptr_t talign = t & ~(gran - 1);
    for (uintptr_t off = gran; off <= reach; off += (off < 0x100000 ? gran : 0x100000)) {
        if (off <= talign && (talign - off) >= lo) {
            void* q = FrMapAt(talign - off, size);
            if (q) return q;
        }
        uintptr_t up = talign + off;
        if (up > talign && up + size <= hi) {
            void* q = FrMapAt(up, size);
            if (q) return q;
        }
    }
    return NULL;
}

/* ======================================================================== */
#if defined(__x86_64__)
/* ===== x86-64 backend (prologue decoder shared in common/) ============== */

#include "../common/arch/x86_64/decode.h"

/* Write a 14-byte absolute jump (jmp [rip+0]; .quad dest) at `p`. */
static void FrWriteAbsJmp(uint8_t* p, uint64_t dest) {
    p[0] = 0xFF; p[1] = 0x25; p[2] = p[3] = p[4] = p[5] = 0;
    memcpy(p + 6, &dest, 8);
}

static int InstallHook(void* target, void* detour, void** outTramp) {
    uint8_t* tgt = (uint8_t*)target;

    /* 1. measure whole instructions covering >= 5 bytes; remember offsets. */
    int    offs[16];
    FrInsn ins[16];
    int    n = 0, copyLen = 0;
    while (copyLen < 5) {
        if (n >= 16) { LogError("[hook] prologue too long @ %p\n", target); return 0; }
        FrInsn d;
        int l = FrDecode(tgt + copyLen, &d);
        if (l <= 0) { LogError("[hook] undecodable byte 0x%02x @ %p+%d\n", tgt[copyLen], target, copyLen); return 0; }
        offs[n] = copyLen; ins[n] = d; n++; copyLen += l;
    }
    if (copyLen > 20) { LogError("[hook] prologue copy too large (%d) @ %p\n", copyLen, target); return 0; }

    /* 2. allocate the near block: [trampoline][relay]. */
    size_t trampLen  = (size_t)copyLen + 14;
    size_t blockSize = trampLen + 14;
    uint8_t* block = (uint8_t*)FrAllocNear(target, blockSize);
    if (!block) { LogError("[hook] no free memory within 2GB of %p\n", target); return 0; }
    uint8_t* tramp = block;
    uint8_t* relay = block + trampLen;

    /* 3. copy + relocate the prologue into the trampoline. */
    memcpy(tramp, tgt, (size_t)copyLen);
    for (int k = 0; k < n; k++) {
        int o = offs[k];
        FrInsn* d = &ins[k];
        int ilen = (k + 1 < n ? offs[k + 1] : copyLen) - o;

        if (d->ripDisp >= 0) {
            int32_t disp;
            memcpy(&disp, tgt + o + d->ripDisp, 4);
            int64_t nd = (int64_t)disp + (int64_t)((intptr_t)tgt - (intptr_t)tramp);
            if (nd < INT32_MIN || nd > INT32_MAX) { munmap(block, blockSize); LogError("[hook] RIP reloc out of range @ %p\n", target); return 0; }
            int32_t nd32 = (int32_t)nd;
            memcpy(tramp + o + d->ripDisp, &nd32, 4);
        }
        if (d->relKind) {
            int64_t rel;
            if (d->relKind == 1) { int8_t r; memcpy(&r, tgt + o + d->relOff, 1); rel = r; }
            else                 { int32_t r; memcpy(&r, tgt + o + d->relOff, 4); rel = r; }
            uint8_t* absTarget = tgt + o + ilen + rel;
            if (absTarget >= tgt && absTarget < tgt + copyLen) {
                /* branch stays inside the copied block: distance preserved. */
            } else if (d->relKind == 4) {
                int64_t nr = (int64_t)((intptr_t)absTarget - (intptr_t)(tramp + o + ilen));
                if (nr < INT32_MIN || nr > INT32_MAX) { munmap(block, blockSize); LogError("[hook] rel32 reloc out of range @ %p\n", target); return 0; }
                int32_t nr32 = (int32_t)nr;
                memcpy(tramp + o + d->relOff, &nr32, 4);
            } else {
                /* short branch leaving the window: cannot keep length. */
                munmap(block, blockSize);
                LogError("[hook] short branch in prologue @ %p; refusing\n", target);
                return 0;
            }
        }
    }
    FrWriteAbsJmp(tramp + copyLen, (uint64_t)(uintptr_t)(tgt + copyLen));  /* jump back */
    FrWriteAbsJmp(relay, (uint64_t)(uintptr_t)detour);                    /* to detour */

    /* 4. make the block executable. */
    if (!FrProtect(block, blockSize, PROT_READ | PROT_EXEC)) { munmap(block, blockSize); LogError("[hook] mprotect(block) failed\n"); return 0; }
    __builtin___clear_cache((char*)block, (char*)block + blockSize);

    /* 5. patch the target: E9 rel32 -> relay, NOP-fill any remainder. Prefer an
     * aligned 8-byte atomic publish (torn-write safe without thread suspension)
     * when the prologue fits in 8 bytes and the target is 8-aligned; otherwise a
     * byte-wise write that touches only the decoded prologue. */
    int64_t jrel = (int64_t)((intptr_t)relay - (intptr_t)(tgt + 5));
    if (jrel < INT32_MIN || jrel > INT32_MAX) { munmap(block, blockSize); LogError("[hook] relay out of jump range @ %p\n", target); return 0; }

    int atomicPatch = (((uintptr_t)tgt & 7) == 0) && (copyLen <= 8);
    size_t patchSpan = atomicPatch ? (size_t)8 : (size_t)copyLen;

    if (!FrProtect(tgt, patchSpan, PROT_READ | PROT_WRITE)) { munmap(block, blockSize); LogError("[hook] mprotect(target) failed\n"); return 0; }

    /* Record the hook (capturing the ORIGINAL bytes) BEFORE patching. If we
     * cannot record it, fail closed -- never patch a target we can't restore. */
    FrHook* h = (FrHook*)FrHeapAlloc(sizeof(FrHook));
    if (!h) {
        FrProtect(tgt, patchSpan, PROT_READ | PROT_EXEC);
        munmap(block, blockSize);
        LogError("[hook] out of memory recording hook @ %p\n", target);
        return 0;
    }
    h->target = target; h->block = block; h->blockSize = blockSize;
    h->savedLen = (size_t)copyLen;
    memcpy(h->saved, tgt, (size_t)copyLen);

    int32_t r32 = (int32_t)jrel;
    if (atomicPatch) {
        uint64_t nv;
        memcpy(&nv, tgt, 8);                 /* preserve bytes [copyLen, 8) */
        uint8_t* nb = (uint8_t*)&nv;
        nb[0] = 0xE9;
        memcpy(nb + 1, &r32, 4);
        for (int b = 5; b < copyLen; b++) nb[b] = 0x90;
        __atomic_store_n((volatile uint64_t*)tgt, nv, __ATOMIC_RELEASE);  /* one atomic store */
    } else {
        tgt[0] = 0xE9;
        memcpy(tgt + 1, &r32, 4);
        for (int b = 5; b < copyLen; b++) tgt[b] = 0x90;
    }

    FrProtect(tgt, patchSpan, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char*)tgt, (char*)tgt + patchSpan);

    HookEngineInit();
    pthread_mutex_lock(&gFrLock);
    h->next = gFrHooks; gFrHooks = h;
    pthread_mutex_unlock(&gFrLock);

    *outTramp = tramp;
    LogDebug("[hook] installed @ %p copyLen=%d block=%p tramp=%p relay=%p\n",
             target, copyLen, (void*)block, (void*)tramp, (void*)relay);
    return 1;
}

#elif defined(__i386__)
/* ===== i386 backend (prologue decoder shared in common/) ================ */

#include "../common/arch/i386/decode.h"

/* Write a 6-byte absolute jump (push imm32; ret) at `p`. IA-32 has no
 * RIP-relative form, so the destination is pushed as an absolute immediate and
 * `ret` consumes it -- reaching anywhere in the address space without a scratch
 * register or a memory slot (the 32-bit analogue of the x86-64 jmp [rip+0]). */
static void FrWriteAbsJmp(uint8_t* p, uint32_t dest) {
    p[0] = 0x68;                          /* push imm32 */
    memcpy(p + 1, &dest, 4);
    p[5] = 0xC3;                          /* ret        */
}

static int InstallHook(void* target, void* detour, void** outTramp) {
    uint8_t* tgt = (uint8_t*)target;

    /* 1. measure whole instructions covering >= 5 bytes; remember offsets. */
    int    offs[16];
    FrInsn ins[16];
    int    n = 0, copyLen = 0;
    while (copyLen < 5) {
        if (n >= 16) { LogError("[hook] prologue too long @ %p\n", target); return 0; }
        FrInsn d;
        int l = FrDecode(tgt + copyLen, &d);
        if (l <= 0) { LogError("[hook] undecodable byte 0x%02x @ %p+%d\n", tgt[copyLen], target, copyLen); return 0; }
        offs[n] = copyLen; ins[n] = d; n++; copyLen += l;
    }
    if (copyLen > 20) { LogError("[hook] prologue copy too large (%d) @ %p\n", copyLen, target); return 0; }

    /* 2. allocate the near block: [trampoline][relay]. */
    size_t trampLen  = (size_t)copyLen + 6;
    size_t blockSize = trampLen + 6;
    uint8_t* block = (uint8_t*)FrAllocNear(target, blockSize);
    if (!block) { LogError("[hook] no free memory within 2GB of %p\n", target); return 0; }
    uint8_t* tramp = block;
    uint8_t* relay = block + trampLen;

    /* 3. copy + relocate the prologue into the trampoline. A 32-bit disp32 is an
     * absolute address (IA-32 has no RIP-relative form), so memory operands copy
     * verbatim; the only relocations are rel8/rel32 branch operands, and rel32
     * spans the whole 4 GB so it never falls out of range. */
    memcpy(tramp, tgt, (size_t)copyLen);
    for (int k = 0; k < n; k++) {
        int o = offs[k];
        FrInsn* d = &ins[k];
        int ilen = (k + 1 < n ? offs[k + 1] : copyLen) - o;

        if (d->relKind) {
            int32_t rel;
            if (d->relKind == 1) { int8_t r; memcpy(&r, tgt + o + d->relOff, 1); rel = r; }
            else                 { memcpy(&rel, tgt + o + d->relOff, 4); }
            uint8_t* absTarget = tgt + o + ilen + rel;
            if (absTarget >= tgt && absTarget < tgt + copyLen) {
                /* branch stays inside the copied block: distance preserved. */
            } else if (d->relKind == 4) {
                int32_t nr = (int32_t)(absTarget - (tramp + o + ilen));
                memcpy(tramp + o + d->relOff, &nr, 4);
            } else {
                /* short branch leaving the window: cannot keep length. */
                munmap(block, blockSize);
                LogError("[hook] short branch in prologue @ %p; refusing\n", target);
                return 0;
            }
        }
    }
    FrWriteAbsJmp(tramp + copyLen, (uint32_t)(uintptr_t)(tgt + copyLen));  /* jump back */
    FrWriteAbsJmp(relay, (uint32_t)(uintptr_t)detour);                    /* to detour */

    /* 4. make the block executable. */
    if (!FrProtect(block, blockSize, PROT_READ | PROT_EXEC)) { munmap(block, blockSize); LogError("[hook] mprotect(block) failed\n"); return 0; }
    __builtin___clear_cache((char*)block, (char*)block + blockSize);

    /* 5. patch the target: E9 rel32 -> relay, NOP-fill any remainder. rel32
     * spans the whole 32-bit address space, so the relay is always reachable and
     * the displacement needs no range check. The write is byte-wise over exactly
     * the decoded prologue; as on x86-64 the torn window is benign in Fragment's
     * flow (hooks land before the curl module is exercised), and 32-bit has no
     * lock-free aligned 8-byte store without a libatomic dependency, so the
     * atomic publish the 64-bit path can take is not used here. */
    int32_t jrel = (int32_t)(relay - (tgt + 5));

    if (!FrProtect(tgt, (size_t)copyLen, PROT_READ | PROT_WRITE)) { munmap(block, blockSize); LogError("[hook] mprotect(target) failed\n"); return 0; }

    /* Record the hook (capturing the ORIGINAL bytes) BEFORE patching. If we
     * cannot record it, fail closed -- never patch a target we can't restore. */
    FrHook* h = (FrHook*)FrHeapAlloc(sizeof(FrHook));
    if (!h) {
        FrProtect(tgt, (size_t)copyLen, PROT_READ | PROT_EXEC);
        munmap(block, blockSize);
        LogError("[hook] out of memory recording hook @ %p\n", target);
        return 0;
    }
    h->target = target; h->block = block; h->blockSize = blockSize;
    h->savedLen = (size_t)copyLen;
    memcpy(h->saved, tgt, (size_t)copyLen);

    tgt[0] = 0xE9;
    memcpy(tgt + 1, &jrel, 4);
    for (int b = 5; b < copyLen; b++) tgt[b] = 0x90;

    FrProtect(tgt, (size_t)copyLen, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char*)tgt, (char*)tgt + copyLen);

    HookEngineInit();
    pthread_mutex_lock(&gFrLock);
    h->next = gFrHooks; gFrHooks = h;
    pthread_mutex_unlock(&gFrLock);

    *outTramp = tramp;
    LogDebug("[hook] installed @ %p copyLen=%d block=%p tramp=%p relay=%p\n",
             target, copyLen, (void*)block, (void*)tramp, (void*)relay);
    return 1;
}

#else
/* ===== aarch64 backend: relocation shared in common/arch/aarch64 ======= */
#include "../common/arch/aarch64/reloc.h"

static int InstallHook(void* target, void* detour, void** outTramp) {
    uint8_t* tgt = (uint8_t*)target;
    if (((uintptr_t)tgt & 3) != 0) { LogError("[hook] target not 4-aligned @ %p\n", target); return 0; }

    uint32_t first;
    memcpy(&first, tgt, 4);

    /* block: [trampoline: reloc'd insn (4) + B-back (4)][relay: LDR/BR/.quad (16)] */
    const size_t trampLen = 8, blockSize = 24;
    uint8_t* block = (uint8_t*)FrAllocNear(target, blockSize);
    if (!block) { LogError("[hook] no free memory within 128MB of %p\n", target); return 0; }
    uint8_t* tramp = block;
    uint8_t* relay = block + trampLen;

    uint32_t reloc;
    if (!FrRelocOne(first, (uintptr_t)tgt, (uintptr_t)tramp, &reloc)) {
        munmap(block, blockSize);
        LogError("[hook] un-relocatable prologue insn 0x%08x @ %p; refusing\n", first, target);
        return 0;
    }
    if (!FrInRangeB((uintptr_t)(tramp + 4), (uintptr_t)(tgt + 4))) {
        munmap(block, blockSize);
        LogError("[hook] trampoline out of B range to %p; refusing\n", (void*)(tgt + 4));
        return 0;
    }
    if (!FrInRangeB((uintptr_t)tgt, (uintptr_t)relay)) {
        munmap(block, blockSize);
        LogError("[hook] relay out of B range from %p; refusing\n", target);
        return 0;
    }

    memcpy(tramp, &reloc, 4);
    uint32_t bback = FrEncB((uintptr_t)(tramp + 4), (uintptr_t)(tgt + 4));
    memcpy(tramp + 4, &bback, 4);

    uint32_t ldr = 0x58000050u;   /* LDR x16, #8     */
    uint32_t br  = 0xD61F0200u;   /* BR  x16         */
    uint64_t det = (uint64_t)(uintptr_t)detour;
    memcpy(relay + 0, &ldr, 4);
    memcpy(relay + 4, &br, 4);
    memcpy(relay + 8, &det, 8);

    if (!FrProtect(block, blockSize, PROT_READ | PROT_EXEC)) { munmap(block, blockSize); LogError("[hook] mprotect(block) failed\n"); return 0; }
    __builtin___clear_cache((char*)block, (char*)block + blockSize);

    /* patch: a single naturally-aligned, atomic 4-byte B to the relay. */
    if (!FrProtect(tgt, 4, PROT_READ | PROT_WRITE)) { munmap(block, blockSize); LogError("[hook] mprotect(target) failed\n"); return 0; }

    FrHook* h = (FrHook*)FrHeapAlloc(sizeof(FrHook));
    if (!h) {
        FrProtect(tgt, 4, PROT_READ | PROT_EXEC);
        munmap(block, blockSize);
        LogError("[hook] out of memory recording hook @ %p\n", target);
        return 0;
    }
    h->target = target; h->block = block; h->blockSize = blockSize;
    h->savedLen = 4;
    memcpy(h->saved, tgt, 4);

    uint32_t patch = FrEncB((uintptr_t)tgt, (uintptr_t)relay);
    __atomic_store_n((volatile uint32_t*)tgt, patch, __ATOMIC_RELEASE);

    FrProtect(tgt, 4, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char*)tgt, (char*)tgt + 4);

    HookEngineInit();
    pthread_mutex_lock(&gFrLock);
    h->next = gFrHooks; gFrHooks = h;
    pthread_mutex_unlock(&gFrLock);

    *outTramp = tramp;
    LogDebug("[hook] installed @ %p insn=0x%08x block=%p tramp=%p relay=%p\n",
             target, first, (void*)block, (void*)tramp, (void*)relay);
    return 1;
}
#endif

/* Restore every installed hook and release its block. Call only when no other
 * thread can be inside a detour/trampoline (e.g. process teardown).
 *
 * Intentionally NOT wired into the destructor: Fragment pins its own module, so
 * it is never unloaded -- there is no unload teardown to run, and at process
 * exit the OS reclaims everything. Kept for completeness and for embedders who
 * host the engine in an unloadable module. */
static void HookEngineShutdown(void) {
    if (!gFrReady) return;
    pthread_mutex_lock(&gFrLock);
    FrHook* h = gFrHooks;
    while (h) {
        if (FrProtect(h->target, h->savedLen, PROT_READ | PROT_WRITE)) {
            memcpy(h->target, h->saved, h->savedLen);
            FrProtect(h->target, h->savedLen, PROT_READ | PROT_EXEC);
            __builtin___clear_cache((char*)h->target, (char*)h->target + h->savedLen);
        }
        if (h->block) munmap(h->block, h->blockSize);
        FrHook* nx = h->next;
        FrHeapFree(h);
        h = nx;
    }
    gFrHooks = NULL;
    pthread_mutex_unlock(&gFrLock);
}
