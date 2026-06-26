#pragma once

#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"

#if !defined(_M_X64) && !defined(__x86_64__) && !defined(_M_IX86) && !defined(__i386__) && \
    !defined(_M_ARM64) && !defined(__aarch64__)
#error "Fragment's hook engine (caller stubs, prologue decoder, patch) is x86-64 / i386 / aarch64 only."
#endif

/*
 * Fragment's own x86-64 inline-hook engine (no third-party dependency).
 *
 * To hook a function we:
 *   1. length-decode its prologue until we have >= 5 whole instructions'
 *      worth of bytes (the size of a relative JMP);
 *   2. allocate a small executable block WITHIN +/-2 GB of the target (so a
 *      5-byte E9 can reach it) holding a "trampoline" (the relocated prologue
 *      followed by an absolute jump back into the function body) and a
 *      "relay" (an absolute jump to the detour);
 *   3. overwrite the target's first 5 bytes with `E9 rel32` -> relay, padding
 *      any leftover bytes with NOPs.
 *
 * Calling the returned trampoline therefore runs the original function. The
 * 5-byte jump only needs to reach the near relay; the relay's absolute jump
 * can reach a detour anywhere in the address space, so the detour need not be
 * near the target.
 *
 * The decoder recognises the common instruction subset compilers emit in
 * function prologues. If it meets anything it cannot decode with certainty
 * (or a short branch leaving the copied window, or a relocation that will not
 * fit in 32 bits), it FAILS CLOSED: it refuses the hook and leaves the target
 * untouched, so a mis-decode can never corrupt the process. x86-64 only.
 *
 * Residual hazards (addressed by the hardening pass; documented here for
 * honesty):
 *   (1) the 5-byte patch is not yet performed under thread suspension, so a
 *       thread executing the target's first bytes at the instant of install
 *       could read a torn instruction. Safe in Fragment's flow because hooks
 *       land before the curl module is exercised, but the load-notification
 *       path could in principle race another thread that calls curl the moment
 *       the module appears.
 *   (2) we NOP-fill the prologue bytes in [5, copyLen); if some other
 *       instruction in the function branches into that range, the landing site
 *       is destroyed. We copy the MINIMAL prologue (smallest copyLen >= 5) to
 *       shrink this window, but do not prove no such internal target exists.
 */

#if defined(_M_ARM64) || defined(__aarch64__)
#include "../common/arch/aarch64/reloc.h"
#elif defined(_M_IX86) || defined(__i386__)
#include "../common/arch/i386/decode.h"
#else
#include "../common/arch/x86_64/decode.h"
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

static FrHook*          gFrHooks = NULL;
// MUST remain a CRITICAL_SECTION (recursive): InstallHook runs inside it, and
// via the LdrLoadDll detour HookCurl->InstallHook can re-enter on the SAME
// thread under the loader lock. A non-recursive lock (SRWLOCK) would deadlock.
static CRITICAL_SECTION gFrLock;
static volatile LONG    gFrReady = 0;
static HANDLE           gFrHeap  = NULL;

/* Allocate from a PRIVATE heap. Because no other thread ever holds this heap's
 * lock, allocating from it under the Windows loader lock (e.g. from a
 * load-notification callback) cannot deadlock against another thread's CRT
 * heap operation. Falls back to the CRT heap only if heap creation failed. */
static void* FrHeapAlloc(size_t n) {
    return gFrHeap ? HeapAlloc(gFrHeap, HEAP_ZERO_MEMORY, n) : calloc(1, n);
}
static void FrHeapFree(void* p) {
    if (!p) return;
    if (gFrHeap) HeapFree(gFrHeap, 0, p);
    else free(p);
}

// First call is single-threaded (DllMain, before any detour/notification can
// fire). Publish gFrReady AFTER the section + heap are constructed.
static void HookEngineInit(void) {
    static volatile LONG once = 0;
    if (InterlockedCompareExchange(&once, 1, 0) == 0) {
        InitializeCriticalSection(&gFrLock);
        gFrHeap = HeapCreate(0, 0, 0);
        InterlockedExchange(&gFrReady, 1);
    }
}

/* True if `target` already has a hook installed. The teardown registry is the
 * single source of truth, so dedup needs no separate (fixed-size) table: it is
 * unbounded and can never silently stop deduping. Caller serializes resolve+
 * check+install (gHookLock) so there is no TOCTOU between this and InstallHook. */
static BOOL FrIsHooked(void* target) {
    if (!gFrReady) return FALSE;
    BOOL found = FALSE;
    EnterCriticalSection(&gFrLock);
    for (FrHook* h = gFrHooks; h; h = h->next)
        if (h->target == target) { found = TRUE; break; }
    LeaveCriticalSection(&gFrLock);
    return found;
}

/* Reserve+commit `size` bytes whose address is within +/-2 GB of `target`, so
 * a 5-byte relative jump from the target can reach it. Returns NULL if no slot
 * is free in range. */
static void* FrAllocNear(void* target, size_t size) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    uintptr_t gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;
    uintptr_t t  = (uintptr_t)target;
    uintptr_t lo = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t hi = (uintptr_t)si.lpMaximumApplicationAddress;
#if defined(_M_ARM64) || defined(__aarch64__)
    uintptr_t reach = 0x07FF0000ULL;          /* stay safely under 128 MB (B imm26) */
#else
    uintptr_t reach = 0x7FFF0000ULL;          /* stay safely under 2 GB (E9 rel32)  */
#endif
    if (t > reach && t - reach > lo) lo = t - reach;
    if (hi > t + reach) hi = t + reach;

    MEMORY_BASIC_INFORMATION mbi;

    /* upward from target */
    uintptr_t a = (t + gran - 1) & ~(gran - 1);
    while (a < hi && VirtualQuery((void*)a, &mbi, sizeof(mbi))) {
        uintptr_t regionEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (mbi.State == MEM_FREE) {
            uintptr_t base = ((uintptr_t)mbi.BaseAddress + gran - 1) & ~(gran - 1);
            if (base >= a && base + size <= regionEnd && base + size <= hi) {
                void* p = VirtualAlloc((void*)base, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (p) return p;
            }
        }
        a = (regionEnd + gran - 1) & ~(gran - 1);
        if (a <= (uintptr_t)mbi.BaseAddress) break;
    }

    /* downward from target */
    a = t & ~(gran - 1);
    for (;;) {
        if (!VirtualQuery((void*)a, &mbi, sizeof(mbi))) break;
        if (mbi.State == MEM_FREE) {
            uintptr_t regionEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
            if (regionEnd >= size) {
                uintptr_t cand = (regionEnd - size) & ~(gran - 1);
                if (cand >= (uintptr_t)mbi.BaseAddress && cand >= lo && cand <= t) {
                    void* p = VirtualAlloc((void*)cand, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    if (p) return p;
                }
            }
        }
        if ((uintptr_t)mbi.BaseAddress <= gran || (uintptr_t)mbi.BaseAddress <= lo) break;
        a = ((uintptr_t)mbi.BaseAddress - 1) & ~(gran - 1);
    }
    return NULL;
}

#if defined(_M_X64) || defined(__x86_64__)
/* ===== x86-64 backend (prologue decoder shared in common/) ============== */

/* Write a 14-byte absolute jump (jmp [rip+0]; .quad dest) at `p`. */
static void FrWriteAbsJmp(uint8_t* p, uint64_t dest) {
    p[0] = 0xFF; p[1] = 0x25; p[2] = p[3] = p[4] = p[5] = 0;
    memcpy(p + 6, &dest, 8);
}

/*
 * Install an inline hook on `target` jumping to `detour`. On success writes a
 * callable trampoline (which behaves as the original `target`) to *outTramp
 * and returns TRUE. On any uncertainty it returns FALSE without modifying the
 * target.
 */
static BOOL InstallHook(void* target, void* detour, void** outTramp) {
    uint8_t* tgt = (uint8_t*)target;

    /* 1. measure whole instructions covering >= 5 bytes; remember offsets. */
    int    offs[16];
    FrInsn ins[16];
    int    n = 0, copyLen = 0;
    while (copyLen < 5) {
        if (n >= 16) { LogError("[hook] prologue too long @ %p\n", target); return FALSE; }
        FrInsn d;
        int l = FrDecode(tgt + copyLen, &d);
        if (l <= 0) { LogError("[hook] undecodable byte 0x%02x @ %p+%d\n", tgt[copyLen], target, copyLen); return FALSE; }
        offs[n] = copyLen; ins[n] = d; n++; copyLen += l;
    }
    if (copyLen > 20) { LogError("[hook] prologue copy too large (%d) @ %p\n", copyLen, target); return FALSE; }

    /* 2. allocate the near block: [trampoline][relay]. */
    size_t trampLen  = (size_t)copyLen + 14;
    size_t blockSize = trampLen + 14;
    uint8_t* block = (uint8_t*)FrAllocNear(target, blockSize);
    if (!block) { LogError("[hook] no free memory within 2GB of %p\n", target); return FALSE; }
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
            if (nd < INT32_MIN || nd > INT32_MAX) { VirtualFree(block, 0, MEM_RELEASE); LogError("[hook] RIP reloc out of range @ %p\n", target); return FALSE; }
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
                if (nr < INT32_MIN || nr > INT32_MAX) { VirtualFree(block, 0, MEM_RELEASE); LogError("[hook] rel32 reloc out of range @ %p\n", target); return FALSE; }
                int32_t nr32 = (int32_t)nr;
                memcpy(tramp + o + d->relOff, &nr32, 4);
            } else {
                /* short branch leaving the window: cannot keep length. */
                VirtualFree(block, 0, MEM_RELEASE);
                LogError("[hook] short branch in prologue @ %p; refusing\n", target);
                return FALSE;
            }
        }
    }
    FrWriteAbsJmp(tramp + copyLen, (uint64_t)(uintptr_t)(tgt + copyLen));  /* jump back */
    FrWriteAbsJmp(relay, (uint64_t)(uintptr_t)detour);                    /* to detour */

    /* 4. make the block executable. */
    DWORD old;
    if (!VirtualProtect(block, blockSize, PAGE_EXECUTE_READ, &old)) { VirtualFree(block, 0, MEM_RELEASE); LogError("[hook] VirtualProtect(block) failed %lu\n", GetLastError()); return FALSE; }
    FlushInstructionCache(GetCurrentProcess(), block, blockSize);

    /* 5. patch the target: E9 rel32 -> relay, NOP-fill any remainder. */
    int64_t jrel = (int64_t)((intptr_t)relay - (intptr_t)(tgt + 5));
    if (jrel < INT32_MIN || jrel > INT32_MAX) { VirtualFree(block, 0, MEM_RELEASE); LogError("[hook] relay out of jump range @ %p\n", target); return FALSE; }

    /* 5. patch the target. Prefer an aligned 8-byte atomic publish (torn-write
     * safe without thread suspension), but ONLY when the full 8 bytes lie in a
     * single committed region -- otherwise the wider store could fault or touch
     * a neighbouring page. Fall back to a byte-wise write (which touches only
     * the decoded prologue) for wide/unaligned/edge prologues. */
    MEMORY_BASIC_INFORMATION mbi;
    BOOL atomicPatch = (((uintptr_t)tgt & 7) == 0) && (copyLen <= 8) &&
                       VirtualQuery(tgt, &mbi, sizeof(mbi)) == sizeof(mbi) &&
                       (PBYTE)mbi.BaseAddress + mbi.RegionSize >= tgt + 8;
    size_t patchSpan = atomicPatch ? (size_t)8 : (size_t)copyLen;

    DWORD oldp;
    if (!VirtualProtect(tgt, patchSpan, PAGE_EXECUTE_READWRITE, &oldp)) {
        VirtualFree(block, 0, MEM_RELEASE);
        LogError("[hook] VirtualProtect(target) failed %lu\n", GetLastError());
        return FALSE;
    }

    /* Record the hook (capturing the ORIGINAL bytes) BEFORE patching. If we
     * cannot record it, fail closed -- never patch a target we can't restore. */
    FrHook* h = (FrHook*)FrHeapAlloc(sizeof(FrHook));
    if (!h) {
        VirtualProtect(tgt, patchSpan, oldp, &oldp);
        VirtualFree(block, 0, MEM_RELEASE);
        LogError("[hook] out of memory recording hook @ %p\n", target);
        return FALSE;
    }
    h->target = target; h->block = block; h->blockSize = blockSize;
    h->savedLen = (size_t)copyLen;
    memcpy(h->saved, tgt, (size_t)copyLen);

    int32_t r32 = (int32_t)jrel;
    if (atomicPatch) {
        uint64_t nv;
        memcpy(&nv, tgt, 8);                 // preserve bytes [copyLen, 8)
        uint8_t* nb = (uint8_t*)&nv;
        nb[0] = 0xE9;
        memcpy(nb + 1, &r32, 4);
        for (int b = 5; b < copyLen; b++) nb[b] = 0x90;
        InterlockedExchange64((volatile LONG64*)tgt, (LONG64)nv);  // one atomic store
    } else {
        tgt[0] = 0xE9;
        memcpy(tgt + 1, &r32, 4);
        for (int b = 5; b < copyLen; b++) tgt[b] = 0x90;
    }

    VirtualProtect(tgt, patchSpan, oldp, &oldp);
    FlushInstructionCache(GetCurrentProcess(), tgt, patchSpan);

    /* 6. register for teardown (h is non-NULL here). */
    HookEngineInit();
    EnterCriticalSection(&gFrLock);
    h->next = gFrHooks; gFrHooks = h;
    LeaveCriticalSection(&gFrLock);

    *outTramp = tramp;
    LogDebug("[hook] installed @ %p copyLen=%d block=%p tramp=%p relay=%p\n",
             target, copyLen, (void*)block, (void*)tramp, (void*)relay);
    return TRUE;
}

#elif defined(_M_IX86) || defined(__i386__)
/* ===== i386 backend (prologue decoder shared in common/) ================ */

/* Write a 6-byte absolute jump (push imm32; ret) at `p`. IA-32 has no
 * RIP-relative form, so the destination is pushed as an absolute immediate and
 * `ret` consumes it -- reaching anywhere in the address space without a scratch
 * register or a memory slot (the 32-bit analogue of the x86-64 jmp [rip+0]). */
static void FrWriteAbsJmp(uint8_t* p, uint32_t dest) {
    p[0] = 0x68;                          /* push imm32 */
    memcpy(p + 1, &dest, 4);
    p[5] = 0xC3;                          /* ret        */
}

static BOOL InstallHook(void* target, void* detour, void** outTramp) {
    uint8_t* tgt = (uint8_t*)target;

    /* 1. measure whole instructions covering >= 5 bytes; remember offsets. */
    int    offs[16];
    FrInsn ins[16];
    int    n = 0, copyLen = 0;
    while (copyLen < 5) {
        if (n >= 16) { LogError("[hook] prologue too long @ %p\n", target); return FALSE; }
        FrInsn d;
        int l = FrDecode(tgt + copyLen, &d);
        if (l <= 0) { LogError("[hook] undecodable byte 0x%02x @ %p+%d\n", tgt[copyLen], target, copyLen); return FALSE; }
        offs[n] = copyLen; ins[n] = d; n++; copyLen += l;
    }
    if (copyLen > 20) { LogError("[hook] prologue copy too large (%d) @ %p\n", copyLen, target); return FALSE; }

    /* 2. allocate the near block: [trampoline][relay]. */
    size_t trampLen  = (size_t)copyLen + 6;
    size_t blockSize = trampLen + 6;
    uint8_t* block = (uint8_t*)FrAllocNear(target, blockSize);
    if (!block) { LogError("[hook] no free memory within 2GB of %p\n", target); return FALSE; }
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
                VirtualFree(block, 0, MEM_RELEASE);
                LogError("[hook] short branch in prologue @ %p; refusing\n", target);
                return FALSE;
            }
        }
    }
    FrWriteAbsJmp(tramp + copyLen, (uint32_t)(uintptr_t)(tgt + copyLen));  /* jump back */
    FrWriteAbsJmp(relay, (uint32_t)(uintptr_t)detour);                    /* to detour */

    /* 4. make the block executable. */
    DWORD old;
    if (!VirtualProtect(block, blockSize, PAGE_EXECUTE_READ, &old)) { VirtualFree(block, 0, MEM_RELEASE); LogError("[hook] VirtualProtect(block) failed %lu\n", GetLastError()); return FALSE; }
    FlushInstructionCache(GetCurrentProcess(), block, blockSize);

    /* 5. patch the target: E9 rel32 -> relay, NOP-fill any remainder. rel32
     * spans the whole 32-bit address space, so the relay is always reachable and
     * the displacement needs no range check. The write is byte-wise over exactly
     * the decoded prologue; as on x86-64 the torn window is benign in Fragment's
     * flow (hooks land before the curl module is exercised), and there is no
     * lock-free aligned 8-byte store on IA-32 to take the 64-bit atomic path. */
    int32_t jrel = (int32_t)(relay - (tgt + 5));

    DWORD oldp;
    if (!VirtualProtect(tgt, (size_t)copyLen, PAGE_EXECUTE_READWRITE, &oldp)) {
        VirtualFree(block, 0, MEM_RELEASE);
        LogError("[hook] VirtualProtect(target) failed %lu\n", GetLastError());
        return FALSE;
    }

    /* Record the hook (capturing the ORIGINAL bytes) BEFORE patching. If we
     * cannot record it, fail closed -- never patch a target we can't restore. */
    FrHook* h = (FrHook*)FrHeapAlloc(sizeof(FrHook));
    if (!h) {
        VirtualProtect(tgt, (size_t)copyLen, oldp, &oldp);
        VirtualFree(block, 0, MEM_RELEASE);
        LogError("[hook] out of memory recording hook @ %p\n", target);
        return FALSE;
    }
    h->target = target; h->block = block; h->blockSize = blockSize;
    h->savedLen = (size_t)copyLen;
    memcpy(h->saved, tgt, (size_t)copyLen);

    tgt[0] = 0xE9;
    memcpy(tgt + 1, &jrel, 4);
    for (int b = 5; b < copyLen; b++) tgt[b] = 0x90;

    VirtualProtect(tgt, (size_t)copyLen, oldp, &oldp);
    FlushInstructionCache(GetCurrentProcess(), tgt, (size_t)copyLen);

    /* 6. register for teardown (h is non-NULL here). */
    HookEngineInit();
    EnterCriticalSection(&gFrLock);
    h->next = gFrHooks; gFrHooks = h;
    LeaveCriticalSection(&gFrLock);

    *outTramp = tramp;
    LogDebug("[hook] installed @ %p copyLen=%d block=%p tramp=%p relay=%p\n",
             target, copyLen, (void*)block, (void*)tramp, (void*)relay);
    return TRUE;
}

#elif defined(_M_ARM64) || defined(__aarch64__)
/* ===== aarch64 backend: relocation shared in common/arch/aarch64 ======= */

/* Every instruction is one 4-byte word, so there is no length decoding: the
 * patch is a single B over the first instruction, and only that instruction is
 * relocated (FrRelocOne). The jump back is a direct B; the relay reaches an
 * arbitrary detour via LDR x16,#8 / BR x16. The 4-byte patch is a naturally-
 * aligned atomic store, so the install is torn-write safe without suspending
 * threads. Anything FrRelocOne cannot relocate (or a B out of +/-128 MB range)
 * FAILS CLOSED, leaving the target untouched. */
static BOOL InstallHook(void* target, void* detour, void** outTramp) {
    uint8_t* tgt = (uint8_t*)target;
    if (((uintptr_t)tgt & 3) != 0) { LogError("[hook] target not 4-aligned @ %p\n", target); return FALSE; }

    uint32_t first;
    memcpy(&first, tgt, 4);

    /* block: [trampoline: reloc'd insn (4) + B-back (4)][relay: LDR/BR/.quad (16)] */
    const size_t trampLen = 8, blockSize = 24;
    uint8_t* block = (uint8_t*)FrAllocNear(target, blockSize);
    if (!block) { LogError("[hook] no free memory within 128MB of %p\n", target); return FALSE; }
    uint8_t* tramp = block;
    uint8_t* relay = block + trampLen;

    uint32_t reloc;
    if (!FrRelocOne(first, (uintptr_t)tgt, (uintptr_t)tramp, &reloc)) {
        VirtualFree(block, 0, MEM_RELEASE);
        LogError("[hook] un-relocatable prologue insn 0x%08x @ %p; refusing\n", first, target);
        return FALSE;
    }
    if (!FrInRangeB((uintptr_t)(tramp + 4), (uintptr_t)(tgt + 4))) {
        VirtualFree(block, 0, MEM_RELEASE);
        LogError("[hook] trampoline out of B range to %p; refusing\n", (void*)(tgt + 4));
        return FALSE;
    }
    if (!FrInRangeB((uintptr_t)tgt, (uintptr_t)relay)) {
        VirtualFree(block, 0, MEM_RELEASE);
        LogError("[hook] relay out of B range from %p; refusing\n", target);
        return FALSE;
    }

    memcpy(tramp, &reloc, 4);
    uint32_t bback = FrEncB((uintptr_t)(tramp + 4), (uintptr_t)(tgt + 4));
    memcpy(tramp + 4, &bback, 4);

    uint32_t ldr = 0x58000050u;   /* LDR x16, #8 */
    uint32_t br  = 0xD61F0200u;   /* BR  x16     */
    uint64_t det = (uint64_t)(uintptr_t)detour;
    memcpy(relay + 0, &ldr, 4);
    memcpy(relay + 4, &br, 4);
    memcpy(relay + 8, &det, 8);

    DWORD old;
    if (!VirtualProtect(block, blockSize, PAGE_EXECUTE_READ, &old)) { VirtualFree(block, 0, MEM_RELEASE); LogError("[hook] VirtualProtect(block) failed %lu\n", GetLastError()); return FALSE; }
    FlushInstructionCache(GetCurrentProcess(), block, blockSize);

    /* patch: a single naturally-aligned, atomic 4-byte B to the relay. */
    DWORD oldp;
    if (!VirtualProtect(tgt, 4, PAGE_EXECUTE_READWRITE, &oldp)) { VirtualFree(block, 0, MEM_RELEASE); LogError("[hook] VirtualProtect(target) failed %lu\n", GetLastError()); return FALSE; }

    /* Record the hook (capturing the ORIGINAL word) BEFORE patching. If we
     * cannot record it, fail closed -- never patch a target we can't restore. */
    FrHook* h = (FrHook*)FrHeapAlloc(sizeof(FrHook));
    if (!h) {
        VirtualProtect(tgt, 4, oldp, &oldp);
        VirtualFree(block, 0, MEM_RELEASE);
        LogError("[hook] out of memory recording hook @ %p\n", target);
        return FALSE;
    }
    h->target = target; h->block = block; h->blockSize = blockSize;
    h->savedLen = 4;
    memcpy(h->saved, tgt, 4);

    uint32_t patch = FrEncB((uintptr_t)tgt, (uintptr_t)relay);
    InterlockedExchange((volatile LONG*)tgt, (LONG)patch);   /* one atomic 4-byte store */

    VirtualProtect(tgt, 4, oldp, &oldp);
    FlushInstructionCache(GetCurrentProcess(), tgt, 4);

    /* 6. register for teardown (h is non-NULL here). */
    HookEngineInit();
    EnterCriticalSection(&gFrLock);
    h->next = gFrHooks; gFrHooks = h;
    LeaveCriticalSection(&gFrLock);

    *outTramp = tramp;
    LogDebug("[hook] installed @ %p insn=0x%08x block=%p tramp=%p relay=%p\n",
             target, first, (void*)block, (void*)tramp, (void*)relay);
    return TRUE;
}

#endif

/* Restore every installed hook and release its block. Call only when no other
 * thread can be inside a detour/trampoline (e.g. process teardown).
 *
 * Intentionally NOT wired into DllMain: Fragment pins its own module (see the
 * GET_MODULE_HANDLE_EX_FLAG_PIN in DllMain), so it is never unloaded -- there is
 * no DLL_PROCESS_DETACH teardown to run, and at process exit the OS reclaims
 * everything. Kept for completeness and for embedders who host the engine in an
 * unloadable module. */
static void HookEngineShutdown(void) {
    if (!gFrReady) return;
    EnterCriticalSection(&gFrLock);
    FrHook* h = gFrHooks;
    while (h) {
        DWORD old;
        if (VirtualProtect(h->target, h->savedLen, PAGE_EXECUTE_READWRITE, &old)) {
            memcpy(h->target, h->saved, h->savedLen);
            VirtualProtect(h->target, h->savedLen, old, &old);
            FlushInstructionCache(GetCurrentProcess(), h->target, h->savedLen);
        }
        if (h->block) VirtualFree(h->block, 0, MEM_RELEASE);
        FrHook* nx = h->next;
        FrHeapFree(h);
        h = nx;
    }
    gFrHooks = NULL;
    LeaveCriticalSection(&gFrLock);
}
