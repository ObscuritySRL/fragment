/* Unit test for the cross-bitness export resolver (windows/wow64.h).
 *
 * Pe32ExportRva is the parser the 64-bit fragment.exe runs over a WOW64
 * target's 32-bit kernel32 to find LoadLibraryA. Here we drive it over THIS
 * 32-bit process's own mapped kernel32 -- an in-memory PE32 image with the
 * exact RVA layout the live ReadProcessMemory path sees -- and check every
 * resolution against the loader's own GetProcAddress.
 *
 * Built as a 32-bit binary (a PE32 kernel32 is the point) and run under Wine
 * locally / MSVC x86 in CI, so it exercises the real parser on a real export
 * table with no special host needed.
 */
#include <windows.h>
#include <stdio.h>
#include "../wow64.h"

static SIZE_T image_size(const BYTE* base) {
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*) base;
    const IMAGE_NT_HEADERS32* nt = (const IMAGE_NT_HEADERS32*) (base + dos->e_lfanew);
    return nt->OptionalHeader.SizeOfImage;
}

/* Read from a mapped image, bounded to its SizeOfImage so a tail-of-image name
 * pull cannot fault -- the live ReadProcessMemory path fails that same read
 * closed, which is exactly the behaviour we mirror. */
struct SelfImage { const BYTE* base; SIZE_T size; };
static int read_self(void* ctx, DWORD rva, void* dst, DWORD n) {
    struct SelfImage* img = (struct SelfImage*) ctx;
    if ((SIZE_T) rva + n > img->size) return 0;
    memcpy(dst, img->base + rva, n);
    return 1;
}

/* A reader that always fails, to prove the walk fails closed on a bad source. */
static int read_fail(void* ctx, DWORD rva, void* dst, DWORD n) {
    (void) ctx; (void) rva; (void) dst; (void) n;
    return 0;
}

static int fails = 0;
static void check(const char* what, int ok) {
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) fails++;
}

int main(void) {
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32) { printf("kernel32 not mapped?!\n"); return 2; }
    struct SelfImage img = { (const BYTE*) k32, image_size((const BYTE*) k32) };
    const BYTE* lo = img.base, *hi = img.base + img.size;

    /* For each name, classify by where GetProcAddress lands: an export resident
     * in kernel32 (address inside the image) must resolve to the SAME byte; a
     * forwarded export (GetProcAddress points off into kernelbase) must be
     * REFUSED by the walk (0), never pointed at a wrong address. This keeps the
     * test correct across Windows/Wine versions that differ in what kernel32
     * forwards, and actively exercises the forwarder-refusal path. */
    const char* names[] = {
        "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "GetModuleHandleA",
        "VirtualAllocEx", "CreateRemoteThread", "VirtualFree", "Sleep",
    };
    int resident = 0;
    for (int i = 0; i < (int)(sizeof(names) / sizeof(names[0])); i++) {
        DWORD rva = Pe32ExportRva(read_self, &img, names[i]);
        const BYTE* walk = rva ? img.base + rva : NULL;
        const BYTE* api = (const BYTE*) GetProcAddress(k32, names[i]);
        char msg[160];
        if (api >= lo && api < hi) {            /* resident export */
            _snprintf(msg, sizeof(msg), "resident %-20s walk == GetProcAddress", names[i]);
            check(msg, walk == api);
            resident++;
        } else {                                /* forwarded / absent */
            _snprintf(msg, sizeof(msg), "forwarded %-19s refused (walk == 0)", names[i]);
            check(msg, walk == NULL);
        }
    }

    /* Non-vacuous: at least one resident export must have been validated, or the
     * positive path proved nothing. */
    check("validated at least one resident export", resident > 0);
    check("absent export -> 0", Pe32ExportRva(read_self, &img, "NoSuchExport_zzz") == 0);
    check("failed reader -> 0 (fail closed)", Pe32ExportRva(read_fail, &img, "LoadLibraryA") == 0);

    if (fails) { printf("\nFAILED (%d)\n", fails); return 1; }
    printf("\nOK (%d resident exports cross-checked)\n", resident);
    return 0;
}
