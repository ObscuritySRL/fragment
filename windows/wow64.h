#pragma once

#include <windows.h>
#include <string.h>

// Cross-bitness injection support. A 64-bit fragment.exe injecting the 32-bit
// Fragment32.dll into a WOW64 target cannot reuse its OWN kernel32!LoadLibraryA
// as the remote thread's start address -- that is the 64-bit image, mapped at a
// different base. It must resolve LoadLibraryA out of the TARGET's 32-bit
// kernel32 instead. The export walk below works in RVA space over a reader
// callback, so the very same parser serves both the live ReadProcessMemory path
// (tools/fragment.c) and the in-memory unit test (test/pe32test.c) -- there is
// no second copy to drift out of sync.
//
// It FAILS CLOSED: any short read, wrong magic, truncated header, out-of-range
// ordinal, or forwarded export yields 0, and the caller then refuses to inject
// rather than spin up a remote thread at a guessed address.

// Read `n` bytes at image-relative `rva` into `dst`; nonzero on success. A short
// read (or any failure) must return 0 so the walk fails closed.
typedef int (*PeReader)(void* ctx, DWORD rva, void* dst, DWORD n);

// RVA of the named export in the PE32 image read through `rd`, or 0 if it is
// absent / malformed / forwarded. PE32 (32-bit) only: a PE32+ image is rejected,
// since this exists purely to read a WOW64 target's kernel32.
static DWORD Pe32ExportRva(PeReader rd, void* ctx, const char* name) {
    IMAGE_DOS_HEADER dos;
    if (!rd(ctx, 0, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;

    DWORD e = (DWORD) dos.e_lfanew, sig = 0;
    if (!rd(ctx, e, &sig, sizeof(sig)) || sig != IMAGE_NT_SIGNATURE) return 0;

    IMAGE_FILE_HEADER fh;
    if (!rd(ctx, e + 4, &fh, sizeof(fh))) return 0;
    if (fh.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32)) return 0;

    IMAGE_OPTIONAL_HEADER32 opt;
    if (!rd(ctx, e + 4 + (DWORD) sizeof(fh), &opt, sizeof(opt))) return 0;
    if (opt.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return 0;     // must be PE32
    if (opt.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) return 0;

    IMAGE_DATA_DIRECTORY dir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || dir.Size < sizeof(IMAGE_EXPORT_DIRECTORY)) return 0;

    IMAGE_EXPORT_DIRECTORY ex;
    if (!rd(ctx, dir.VirtualAddress, &ex, sizeof(ex))) return 0;

    for (DWORD i = 0; i < ex.NumberOfNames; i++) {
        DWORD nameRva = 0;
        if (!rd(ctx, ex.AddressOfNames + i * 4, &nameRva, 4)) return 0;

        // A fixed-size pull is enough for the names we resolve (LoadLibraryA);
        // it lands deep inside the export blob with slack after it, so the read
        // never runs off the mapping in practice -- and if it ever did, the
        // short read is a fail-closed 0, never a false match.
        char nm[96];
        if (!rd(ctx, nameRva, nm, sizeof(nm))) return 0;
        nm[sizeof(nm) - 1] = 0;
        if (strcmp(nm, name)) continue;

        WORD ord = 0;
        if (!rd(ctx, ex.AddressOfNameOrdinals + i * 2, &ord, 2)) return 0;
        if (ord >= ex.NumberOfFunctions) return 0;

        DWORD fn = 0;
        if (!rd(ctx, ex.AddressOfFunctions + (DWORD) ord * 4, &fn, 4)) return 0;

        // A forwarded export's "RVA" points back inside the export directory at
        // a "Dll.Symbol" string, not at callable code. Refuse it -- jumping a
        // remote thread there would crash the target.
        if (fn >= dir.VirtualAddress && fn < dir.VirtualAddress + dir.Size) return 0;
        return fn;
    }
    return 0;
}
