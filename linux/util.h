#pragma once

#include <stdint.h>
#include <string.h>
#include <link.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include "log.h"
#include "curl.h"
#include "hook.h"

/* The symbol-table walk serves whichever ELF class the build is: ElfW(...) picks
 * the Elf32_/Elf64_ structures by the native word size, so a 32-bit Fragment
 * reads a 32-bit module and a 64-bit one a 64-bit module (a process and its
 * modules are always the same class). The 64-bit ports are unaffected --
 * ElfW(Ehdr) is Elf64_Ehdr there, and ST_TYPE extraction is identical math. */
#if __ELF_NATIVE_CLASS == 32
#define FR_ELFCLASS  ELFCLASS32
#define FR_ST_TYPE(i) ELF32_ST_TYPE(i)
#else
#define FR_ELFCLASS  ELFCLASS64
#define FR_ST_TYPE(i) ELF64_ST_TYPE(i)
#endif

// Resolve `name` to a runtime address via an object's on-disk symbol table.
// Reads BOTH .symtab (a statically-linked function, no dynamic symbol) and
// .dynsym (a real shared libcurl) -- an exact name match, immune to symbol
// interposition and to RTLD_NEXT being blind in an injected process, where a
// plain dlsym would resolve back to our own shadow. Returns NULL if the file is
// unreadable, stripped of both tables, or lacks a DEFINED match. `loadBias` is
// dlpi_addr (0 for a non-PIE main executable).
static void* ElfFindSym(const char* path, uintptr_t loadBias, const char* name) {
    if (!path || !*path) return NULL;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    struct stat stt;
    if (fstat(fd, &stt) != 0 || (size_t) stt.st_size < sizeof(ElfW(Ehdr))) { close(fd); return NULL; }
    size_t fsize = (size_t) stt.st_size;
    const uint8_t* base = (const uint8_t*) mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == (const uint8_t*) MAP_FAILED) return NULL;

    void* result = NULL;
    size_t namelen = strlen(name);
    const ElfW(Ehdr)* eh = (const ElfW(Ehdr)*) base;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 || eh->e_ident[EI_CLASS] != FR_ELFCLASS) goto done;
    /* All bounds use subtraction-form comparisons so an oversized field can
     * never wrap past fsize and bypass the check. */
    if (eh->e_shoff == 0 || eh->e_shoff > fsize ||
        (size_t) eh->e_shnum * sizeof(ElfW(Shdr)) > fsize - eh->e_shoff) goto done;
    const ElfW(Shdr)* sh = (const ElfW(Shdr)*) (base + eh->e_shoff);
    for (int i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type != SHT_SYMTAB && sh[i].sh_type != SHT_DYNSYM) continue;
        if (sh[i].sh_link >= eh->e_shnum) continue;
        if (sh[i].sh_offset > fsize || sh[i].sh_size > fsize - sh[i].sh_offset) continue;
        const ElfW(Shdr)* strsh = &sh[sh[i].sh_link];   /* the linked string table */
        if (strsh->sh_offset > fsize || strsh->sh_size > fsize - strsh->sh_offset) continue;
        const ElfW(Sym)* sym = (const ElfW(Sym)*) (base + sh[i].sh_offset);
        size_t nsym = sh[i].sh_size / sizeof(ElfW(Sym));
        const char* str = (const char*) (base + strsh->sh_offset);
        size_t strsz = strsh->sh_size;
        for (size_t k = 0; k < nsym; k++) {
            if (sym[k].st_value == 0 || FR_ST_TYPE(sym[k].st_info) != STT_FUNC) continue;
            size_t no = sym[k].st_name;
            /* Bound the name within the string table before comparing, so a
             * bad st_name can never walk strcmp off the end of the mapping. */
            if (no >= strsz || strsz - no <= namelen) continue;
            const char* sn = str + no;
            if (sn[namelen] == '\0' && memcmp(sn, name, namelen) == 0) {
                result = (void*) (loadBias + sym[k].st_value);
                goto done;
            }
        }
    }
done:
    munmap((void*) base, fsize);
    return result;
}

int CreateAndEnableHook(const char* name, void* pTarget, void* pDetour, void** ppOriginal) {
    if (!InstallHook(pTarget, pDetour, ppOriginal)) {
        LogError("[hook] install '%s' @ %p failed\n", name, pTarget);
        return 0;
    }
    return 1;
}

static inline int MaskCompare(const void* pBuffer, const char* lpPattern, const char* lpMask) {
    const uint8_t* value = (const uint8_t*) pBuffer;
    for (; *lpMask; ++lpPattern, ++lpMask, ++value) {
        if (*lpMask == 'x' && (uint8_t)(*lpPattern) != *value)
            return 0;
    }
    return 1;
}

// Scan a readable+executable byte range [base, base+size) for a masked pattern.
// The caller passes a single PT_LOAD executable segment (from dl_iterate_phdr),
// so unlike the Windows build there is no per-region VirtualQuery walk -- the
// segment is mapped and the bounds are already known.
static inline void* FindPattern(const uint8_t* base, size_t size, const char* lpPattern, const char* lpMask) {
    if (!base || !size) return 0;
    size_t patternLength = strlen(lpMask);
    if (patternLength == 0 || size < patternLength) return 0;
    const uint8_t* scanEnd = base + size - patternLength;
    for (const uint8_t* p = base; p <= scanEnd; ++p) {
        if (MaskCompare(p, lpPattern, lpMask))
            return (void*) p;
    }
    return 0;
}

// Does the byte range contain this ASCII string anywhere? Used to confirm a
// module is really libcurl before doing the (compiler-specific, best-effort)
// prologue scan, so the scan never false-matches an unrelated module.
static inline int ModuleContainsAscii(const uint8_t* base, size_t size, const char* needle) {
    if (!base || !size) return 0;
    size_t needleLen = strlen(needle);
    if (needleLen == 0 || size < needleLen) return 0;
    const uint8_t* end = base + size - needleLen;
    for (const uint8_t* p = base; p <= end; ++p) {
        if (p[0] == (uint8_t)needle[0] && memcmp(p, needle, needleLen) == 0)
            return 1;
    }
    return 0;
}

// Copy hand-assembled machine code into a fresh executable page.
static void* EmitStub(const uint8_t* code, size_t len) {
    void* p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return NULL;
    memcpy(p, code, len);
    if (mprotect(p, len, PROT_READ | PROT_EXEC) != 0) { munmap(p, len); return NULL; }
    __builtin___clear_cache((char*)p, (char*)p + len);
    return p;
}

/*
 * Caller stubs. Like the Windows build, a single shared C detour serves every
 * hook by having the stub prepend a per-hook context pointer as the detour's
 * first argument (so the detour can reach the right trampoline + URL-API). The
 * incoming arguments are shifted right one slot; the calling convention is the
 * platform's (System V on x86-64, __cdecl on i386, AAPCS on armv7, AAPCS64 on
 * aarch64).
 *
 * curl_easy_setopt is variadic, but every real option value is a single
 * general-purpose word, so the stub forwards exactly one (curl, option, value)
 * triple -- the va_list never has to be reconstructed.
 */
#if defined(__x86_64__)
static CurlSetoptFn GenerateCaller(void* pFirstParam, void* pCalled) {
    uint8_t code[] = {
        0x48, 0x89, 0xD1,                               // mov rcx, rdx   (value)
        0x89, 0xF2,                                     // mov edx, esi   (option)
        0x48, 0x89, 0xFE,                               // mov rsi, rdi   (curl)
        0x48, 0xBF, 0,0,0,0,0,0,0,0,                    // movabs rdi, <ctx>
        0x48, 0xB8, 0,0,0,0,0,0,0,0,                    // movabs rax, <detour>
        0xFF, 0xE0,                                     // jmp rax
    };
    memcpy(code + 10, &pFirstParam, sizeof(pFirstParam));
    memcpy(code + 20, &pCalled, sizeof(pCalled));
    return (CurlSetoptFn) EmitStub(code, sizeof(code));
}

// Caller stub for the 4-argument curl_url_set(handle, what, part, flags); shifts
// the args right one slot and passes flags as the detour's 5th argument.
static CurlUrlSetFn GenerateUrlSetCaller(void* pContext, void* pCalled) {
    uint8_t code[] = {
        0x49, 0x89, 0xC8,                               // mov r8, rcx    (flags)
        0x48, 0x89, 0xD1,                               // mov rcx, rdx   (part)
        0x89, 0xF2,                                     // mov edx, esi   (what)
        0x48, 0x89, 0xFE,                               // mov rsi, rdi   (handle)
        0x48, 0xBF, 0,0,0,0,0,0,0,0,                    // movabs rdi, <ctx>
        0x48, 0xB8, 0,0,0,0,0,0,0,0,                    // movabs rax, <detour>
        0xFF, 0xE0,                                     // jmp rax
    };
    memcpy(code + 13, &pContext, sizeof(pContext));
    memcpy(code + 23, &pCalled, sizeof(pCalled));
    return (CurlUrlSetFn) EmitStub(code, sizeof(code));
}

#elif defined(__i386__)
static CurlSetoptFn GenerateCaller(void* pFirstParam, void* pCalled) {
    // __cdecl passes everything on the stack, so we cannot prepend the context
    // by a register shuffle as on x86-64; we build a fresh call frame instead.
    // Frame: save ebp, then `and esp,-16` realigns to the 16-byte boundary the
    // SysV i386 ABI requires (the gcc-built detour may use aligned SSE), re-push
    // (curl, option, value) from the saved frame, prepend the context, and call
    // the shared C detour. `leave; ret` tears the frame down and returns to the
    // original caller (cdecl: the caller pops the original args).
    uint8_t code[] = {
        0x55,                                           // push ebp
        0x89, 0xE5,                                     // mov ebp, esp
        0x83, 0xE4, 0xF0,                               // and esp, -16
        0xFF, 0x75, 0x10,                               // push [ebp+16]  (value)
        0xFF, 0x75, 0x0C,                               // push [ebp+12]  (option)
        0xFF, 0x75, 0x08,                               // push [ebp+8]   (curl)
        0x68, 0,0,0,0,                                  // push <ctx>
        0xB8, 0,0,0,0,                                  // mov eax, <detour>
        0xFF, 0xD0,                                     // call eax
        0xC9,                                           // leave
        0xC3,                                           // ret
    };
    memcpy(code + 16, &pFirstParam, sizeof(pFirstParam));
    memcpy(code + 21, &pCalled, sizeof(pCalled));
    return (CurlSetoptFn) EmitStub(code, sizeof(code));
}

// Caller stub for the 4-argument curl_url_set(handle, what, part, flags); shifts
// the args right one slot and passes flags as the detour's 5th argument. The
// extra `sub esp,12` keeps the five pushed dwords 16-byte aligned at the call.
static CurlUrlSetFn GenerateUrlSetCaller(void* pContext, void* pCalled) {
    uint8_t code[] = {
        0x55,                                           // push ebp
        0x89, 0xE5,                                     // mov ebp, esp
        0x83, 0xE4, 0xF0,                               // and esp, -16
        0x83, 0xEC, 0x0C,                               // sub esp, 12
        0xFF, 0x75, 0x14,                               // push [ebp+20]  (flags)
        0xFF, 0x75, 0x10,                               // push [ebp+16]  (part)
        0xFF, 0x75, 0x0C,                               // push [ebp+12]  (what)
        0xFF, 0x75, 0x08,                               // push [ebp+8]   (handle)
        0x68, 0,0,0,0,                                  // push <ctx>
        0xB8, 0,0,0,0,                                  // mov eax, <detour>
        0xFF, 0xD0,                                     // call eax
        0xC9,                                           // leave
        0xC3,                                           // ret
    };
    memcpy(code + 22, &pContext, sizeof(pContext));
    memcpy(code + 27, &pCalled, sizeof(pCalled));
    return (CurlUrlSetFn) EmitStub(code, sizeof(code));
}

#elif defined(__arm__)
static CurlSetoptFn GenerateCaller(void* pFirstParam, void* pCalled) {
    // AAPCS: r0-r3. Shift (curl, option, value) right one register, put the
    // context in r0, and branch to the detour. Emitted as A32 and entered with
    // bit 0 clear (the relay clears it), so it runs as ARM and interworks to the
    // detour via the loaded word regardless of the .so's own state.
    uint8_t code[] = {
        0x02, 0x30, 0xA0, 0xE1,                         // mov r3, r2   (value)
        0x01, 0x20, 0xA0, 0xE1,                         // mov r2, r1   (option)
        0x00, 0x10, 0xA0, 0xE1,                         // mov r1, r0   (curl)
        0x00, 0x00, 0x9F, 0xE5,                         // ldr r0, [pc]   -> ctx
        0x00, 0xF0, 0x9F, 0xE5,                         // ldr pc, [pc]   -> detour
        0,0,0,0,                                        // .word ctx
        0,0,0,0,                                        // .word detour
    };
    memcpy(code + 20, &pFirstParam, sizeof(pFirstParam));
    memcpy(code + 24, &pCalled, sizeof(pCalled));
    return (CurlSetoptFn) EmitStub(code, sizeof(code));
}

// Caller stub for the 4-argument curl_url_set(handle, what, part, flags); shifts
// the args right one slot and spills flags onto the stack as the detour's 5th
// (AAPCS passes the fifth integer argument on the stack). push/pop keep the
// 8-byte-aligned stack arg in place across the call.
static CurlUrlSetFn GenerateUrlSetCaller(void* pContext, void* pCalled) {
    uint8_t code[] = {
        0x08, 0x40, 0x2D, 0xE9,                         // push {r3, lr}   (flags -> stack arg)
        0x02, 0x30, 0xA0, 0xE1,                         // mov r3, r2   (part)
        0x01, 0x20, 0xA0, 0xE1,                         // mov r2, r1   (what)
        0x00, 0x10, 0xA0, 0xE1,                         // mov r1, r0   (handle)
        0x08, 0x00, 0x9F, 0xE5,                         // ldr r0, [pc, #8]  -> ctx
        0x08, 0xC0, 0x9F, 0xE5,                         // ldr ip, [pc, #8]  -> detour
        0x3C, 0xFF, 0x2F, 0xE1,                         // blx ip
        0x08, 0x80, 0xBD, 0xE8,                         // pop {r3, pc}
        0,0,0,0,                                        // .word ctx
        0,0,0,0,                                        // .word detour
    };
    memcpy(code + 32, &pContext, sizeof(pContext));
    memcpy(code + 36, &pCalled, sizeof(pCalled));
    return (CurlUrlSetFn) EmitStub(code, sizeof(code));
}

#else /* __aarch64__ */
static CurlSetoptFn GenerateCaller(void* pFirstParam, void* pCalled) {
    // mov x3,x2 ; mov w2,w1 ; mov x1,x0 ; ldr x0,#12 ; ldr x16,#16 ; br x16
    // ; .quad ctx ; .quad detour
    uint8_t code[] = {
        0xE3, 0x03, 0x02, 0xAA,   // mov x3, x2   (value)
        0xE2, 0x03, 0x01, 0x2A,   // mov w2, w1   (option)
        0xE1, 0x03, 0x00, 0xAA,   // mov x1, x0   (curl)
        0x60, 0x00, 0x00, 0x58,   // ldr x0, #12  -> ctx
        0x90, 0x00, 0x00, 0x58,   // ldr x16,#16  -> detour
        0x00, 0x02, 0x1F, 0xD6,   // br  x16
        0,0,0,0,0,0,0,0,          // .quad ctx
        0,0,0,0,0,0,0,0,          // .quad detour
    };
    memcpy(code + 24, &pFirstParam, sizeof(pFirstParam));
    memcpy(code + 32, &pCalled, sizeof(pCalled));
    return (CurlSetoptFn) EmitStub(code, sizeof(code));
}

static CurlUrlSetFn GenerateUrlSetCaller(void* pContext, void* pCalled) {
    // mov w4,w3 ; mov x3,x2 ; mov w2,w1 ; mov x1,x0 ; ldr x0,#12 ; ldr x16,#16
    // ; br x16 ; .quad ctx ; .quad detour
    uint8_t code[] = {
        0xE4, 0x03, 0x03, 0x2A,   // mov w4, w3   (flags)
        0xE3, 0x03, 0x02, 0xAA,   // mov x3, x2   (part)
        0xE2, 0x03, 0x01, 0x2A,   // mov w2, w1   (what)
        0xE1, 0x03, 0x00, 0xAA,   // mov x1, x0   (handle)
        0x60, 0x00, 0x00, 0x58,   // ldr x0, #12  -> ctx
        0x90, 0x00, 0x00, 0x58,   // ldr x16,#16  -> detour
        0x00, 0x02, 0x1F, 0xD6,   // br  x16
        0,0,0,0,0,0,0,0,          // .quad ctx
        0,0,0,0,0,0,0,0,          // .quad detour
    };
    memcpy(code + 28, &pContext, sizeof(pContext));
    memcpy(code + 36, &pCalled, sizeof(pCalled));
    return (CurlUrlSetFn) EmitStub(code, sizeof(code));
}
#endif
