#pragma once

#include <windows.h>
#include "log.h"
#include "curl.h"
#include "hook.h"

BOOL CreateAndEnableHook(const char* name, LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal) {
    if (!InstallHook(pTarget, pDetour, ppOriginal)) {
        LogError("[hook] install '%s' @ 0x%p failed\n", name, pTarget);
        return FALSE;
    }
    return TRUE;
}

inline BOOL MaskCompare(PVOID pBuffer, LPCSTR lpPattern, LPCSTR lpMask) {
    for (PBYTE value = pBuffer; *lpMask; ++lpPattern, ++lpMask, ++value) {
        if (*lpMask == 'x' && *((LPCBYTE) lpPattern)!= *value)
            return FALSE;
    }

    return TRUE;
}

// True if a committed memory region is executable (any of the EXECUTE_*
// protections), ignoring guard/no-access pages. The original code only
// accepted exactly PAGE_EXECUTE_READ, which itself caused "works on some
// builds only" because a module's code can map as WRITECOPY/READWRITE.
inline BOOL IsExecRegion(const MEMORY_BASIC_INFORMATION* mbi) {
    if (mbi->State != MEM_COMMIT) return FALSE;
    if (mbi->Protect & (PAGE_GUARD | PAGE_NOACCESS)) return FALSE;
    DWORD p = mbi->Protect & 0xFF;
    return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
           p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

inline BOOL IsReadableRegion(const MEMORY_BASIC_INFORMATION* mbi) {
    if (mbi->State != MEM_COMMIT) return FALSE;
    if (mbi->Protect & (PAGE_GUARD | PAGE_NOACCESS)) return FALSE;
    DWORD p = mbi->Protect & 0xFF;
    return p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
           p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE ||
           p == PAGE_EXECUTE_WRITECOPY;
}

// SizeOfImage straight from the module's PE headers (read from the mapped
// image -- no psapi, so this is safe to call from inside a loader
// notification, unlike GetModuleInformation which walks the loader list).
inline SIZE_T ModuleImageSize(HMODULE module) {
    PBYTE b = (PBYTE) module;
    if (!b) return 0;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*) b;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*) (b + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    return nt->OptionalHeader.SizeOfImage;
}

// Scan only the executable regions of an image for a masked byte pattern.
// Walks region-by-region so we never read guard/unmapped pages and never miss
// code that maps with a non-RX protection. Takes an explicit (base,size) so it
// touches no psapi.
inline LPVOID FindPattern(PBYTE base, SIZE_T imageSize, LPCSTR lpPattern, LPCSTR lpMask) {
    if (!base || !imageSize) return 0;
    PBYTE imageEnd = base + imageSize;
    size_t patternLength = strlen(lpMask);
    if (patternLength == 0) return 0;

    PBYTE region = base;
    MEMORY_BASIC_INFORMATION mbi;
    while (region < imageEnd && VirtualQuery(region, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        PBYTE regionBase = (PBYTE) mbi.BaseAddress;
        PBYTE regionEnd = regionBase + mbi.RegionSize;
        if (regionEnd > imageEnd) regionEnd = imageEnd;

        if (IsExecRegion(&mbi) && (size_t)(regionEnd - regionBase) >= patternLength) {
            PBYTE scanEnd = regionEnd - patternLength;
            for (PBYTE p = regionBase; p <= scanEnd; ++p) {
                if (MaskCompare(p, lpPattern, lpMask))
                    return p;
            }
        }

        region = regionEnd;
        if (mbi.RegionSize == 0) break;
    }

    return 0;
}

// Does the module's image contain this ASCII string anywhere in a
// readable region? Used to confirm a module is really libcurl before
// doing the (compiler-specific, best-effort) prologue scan, so the scan
// never false-matches an unrelated module.
inline BOOL ModuleContainsAscii(PBYTE base, SIZE_T imageSize, const char* needle) {
    if (!base || !imageSize) return FALSE;
    PBYTE imageEnd = base + imageSize;
    size_t needleLen = strlen(needle);
    if (needleLen == 0) return FALSE;

    PBYTE region = base;
    MEMORY_BASIC_INFORMATION mbi;
    while (region < imageEnd && VirtualQuery(region, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        PBYTE regionBase = (PBYTE) mbi.BaseAddress;
        PBYTE regionEnd = regionBase + mbi.RegionSize;
        if (regionEnd > imageEnd) regionEnd = imageEnd;

        if (IsReadableRegion(&mbi) && (size_t)(regionEnd - regionBase) >= needleLen) {
            for (PBYTE p = regionBase; p <= regionEnd - needleLen; ++p) {
                if (p[0] == (BYTE)needle[0] && memcmp(p, needle, needleLen) == 0)
                    return TRUE;
            }
        }

        region = regionEnd;
        if (mbi.RegionSize == 0) break;
    }

    return FALSE;
}

inline CurlSetoptFn GenerateCaller(LPVOID pFirstParam, LPVOID pCalled) {
    const byte code[] = {
            0x4C, 0x89, 0x44, 0x24, 0x18, // mov qword ptr [rsp + 0x18], r8
            0x89, 0x54, 0x24, 0x10, // mov dword ptr [rsp + 0x10], edx
            0x48, 0x89, 0x4C, 0x24, 0x08, // mov qword ptr [rsp + 8], rcx
            0x57, // push rdi
            0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
            0x4C, 0x8B, 0x4C, 0x24, 0x40, // mov r9, qword ptr [rsp + 0x40]
            0x44, 0x8B, 0x44, 0x24, 0x38, // mov r8d, dword ptr [rsp + 0x38]
            0x48, 0x8B, 0x54, 0x24, 0x30, // mov rdx, qword ptr [rsp + 0x30]
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rcx, 0x0000000000000000 [param1]
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, 0x0000000000000000 [called]
            0xFF, 0xD0, // call rax
            0x48, 0x83, 0xC4, 0x20, // add rsp, 0x20
            0x5F, // pop rdi
            0xC3 // ret
    };

    byte* allocatedCode = VirtualAlloc(NULL, sizeof(code), MEM_COMMIT, PAGE_READWRITE);
    if (!allocatedCode) return NULL;
    memcpy(allocatedCode, code, sizeof(code));
    memcpy(allocatedCode+36, &pFirstParam, sizeof(pFirstParam));
    memcpy(allocatedCode+46, &pCalled, sizeof(pCalled));

    DWORD dummy;
    VirtualProtect(allocatedCode, sizeof(code), PAGE_EXECUTE_READ, &dummy);

    return (CurlSetoptFn) allocatedCode;
}

// Caller stub for the 4-argument curl_url_set(handle, what, part, flags).
// Like GenerateCaller, it prepends a context pointer so a single shared
// detour can reach the right per-hook original. Incoming rcx/edx/r8/r9d
// are shifted right one slot; the 4th original arg (flags) is passed as
// the detour's 5th argument on the stack.
inline CurlUrlSetFn GenerateUrlSetCaller(LPVOID pContext, LPVOID pCalled) {
    const byte code[] = {
            0x48, 0x89, 0x4C, 0x24, 0x08, // mov [rsp+8], rcx   (handle)
            0x89, 0x54, 0x24, 0x10,       // mov [rsp+0x10], edx (what)
            0x4C, 0x89, 0x44, 0x24, 0x18, // mov [rsp+0x18], r8  (part)
            0x4C, 0x89, 0x4C, 0x24, 0x20, // mov [rsp+0x20], r9  (flags)
            0x48, 0x83, 0xEC, 0x38,       // sub rsp, 0x38
            0x48, 0x8B, 0x54, 0x24, 0x40, // mov rdx, [rsp+0x40] (handle)
            0x44, 0x8B, 0x44, 0x24, 0x48, // mov r8d, [rsp+0x48] (what)
            0x4C, 0x8B, 0x4C, 0x24, 0x50, // mov r9,  [rsp+0x50] (part)
            0x48, 0x8B, 0x44, 0x24, 0x58, // mov rax, [rsp+0x58] (flags)
            0x48, 0x89, 0x44, 0x24, 0x20, // mov [rsp+0x20], rax (5th arg)
            0x48, 0xB9, 0,0,0,0,0,0,0,0,  // movabs rcx, <context>
            0x48, 0xB8, 0,0,0,0,0,0,0,0,  // movabs rax, <called>
            0xFF, 0xD0,                   // call rax
            0x48, 0x83, 0xC4, 0x38,       // add rsp, 0x38
            0xC3                          // ret
    };

    byte* allocatedCode = VirtualAlloc(NULL, sizeof(code), MEM_COMMIT, PAGE_READWRITE);
    if (!allocatedCode) return NULL;
    memcpy(allocatedCode, code, sizeof(code));
    memcpy(allocatedCode+50, &pContext, sizeof(pContext));
    memcpy(allocatedCode+60, &pCalled, sizeof(pCalled));

    DWORD dummy;
    VirtualProtect(allocatedCode, sizeof(code), PAGE_EXECUTE_READ, &dummy);

    return (CurlUrlSetFn) allocatedCode;
}
