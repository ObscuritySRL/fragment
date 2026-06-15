#pragma once

#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"

#if !defined(_M_X64) && !defined(__x86_64__)
#error "Fragment's hook engine (caller stubs, prologue decoder, patch) is x86-64 only."
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
            e = FrModRM(p + i, asz, &rip); i += e; return i;
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
    uintptr_t reach = 0x7FFF0000ULL;          /* stay safely under 2 GB */
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
