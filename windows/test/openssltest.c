/* Deterministic exported-OpenSSL observer semantics without network traffic. */
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "../capture.h"

static int available = 1, writes, gaps, readiness;
static unsigned long long next_connection, written_connection;
static unsigned char written_data[32];
static size_t written_size, original_size;
static const char* written_direction;
static BOOL testAvailable(void) { return available; }
static unsigned long long testNextConnection(void) { return ++next_connection; }
static void testBackend(const char* backend, BOOL ready) { (void)backend; if (ready) ++readiness; }
static void testWrite(const char* backend, unsigned long long connection,
    const char* direction, const void* data, size_t captured, size_t original) {
    (void)backend; ++writes; written_connection = connection; written_direction = direction;
    written_size = captured; original_size = original;
    memcpy(written_data, data, captured < sizeof(written_data) ? captured : sizeof(written_data));
    errno = ERANGE; SetLastError(0xdddd);
}
static void testGap(const char* backend, unsigned long long connection, const char* direction, const char* reason) {
    (void)backend; (void)connection; (void)direction; (void)reason;
    ++gaps; errno = ERANGE; SetLastError(0xdddd);
}
#define CaptureAvailable testAvailable
#define CaptureNextConnection testNextConnection
#define CaptureBackend testBackend
#define CaptureWrite testWrite
#define CaptureGap testGap
#include "../main.c"
#include "../openssl_capture.h"
#undef CaptureAvailable
#undef CaptureNextConnection
#undef CaptureBackend
#undef CaptureWrite
#undef CaptureGap

static int failures, calls, incoming_ok = 1, free_reuse;
static unsigned long long reused_connection;
static const unsigned char payload[] = {'a', 0, 255, 'z'};
typedef struct FakeSsl { int result; size_t accepted; int nested; int mutate; } FakeSsl;
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d: %s\n", __LINE__, #x); ++failures; } } while (0)
static void checkIncoming(void) { if (GetLastError() != 123 || errno != EDOM) incoming_ok = 0; ++calls; }
static void leaveOriginal(void) { errno = EINVAL; SetLastError(456); }
static void setIncoming(void) { errno = EDOM; SetLastError(123); }
static int __cdecl fakeWrite(void* pointer, const void* data, int length) {
    FakeSsl* ssl = (FakeSsl*)pointer; checkIncoming();
    if (ssl->nested == 1) {
        ssl->nested = 0; size_t actual = 0;
        int result = OsWriteEx0(pointer, data, length > 0 ? (size_t)length : 0, &actual);
        ssl->nested = 1; leaveOriginal(); return result == 1 ? (int)actual : -1;
    }
    if (ssl->mutate && length > 0) memset((void*)data, '!', (size_t)length);
    leaveOriginal(); return ssl->result;
}
static int __cdecl fakeRead(void* pointer, void* data, int length) {
    FakeSsl* ssl = (FakeSsl*)pointer; checkIncoming();
    if (ssl->result > 0 && length >= ssl->result && ssl->result <= sizeof(payload))
        memcpy(data, payload, (size_t)ssl->result);
    leaveOriginal(); return ssl->result;
}
static int __cdecl fakeWriteEx(void* pointer, const void* data, size_t length, size_t* actual) {
    FakeSsl* ssl = (FakeSsl*)pointer; checkIncoming();
    if (ssl->nested == 2) {
        ssl->nested = 0; int result = OsWrite0(pointer, data, (int)length);
        ssl->nested = 2; if (actual) *actual = result > 0 ? (size_t)result : 0;
        leaveOriginal(); return result > 0;
    }
    if (actual) *actual = ssl->accepted;
    if (ssl->mutate && length) memset((void*)data, '!', length);
    leaveOriginal(); return ssl->result;
}
static int __cdecl fakeReadEx(void* pointer, void* data, size_t length, size_t* actual) {
    FakeSsl* ssl = (FakeSsl*)pointer; checkIncoming();
    if (actual) *actual = ssl->accepted;
    if (ssl->result == 1 && ssl->accepted <= length && ssl->accepted <= sizeof(payload))
        memcpy(data, payload, ssl->accepted);
    leaveOriginal(); return ssl->result;
}
static void __cdecl fakeFree(void* pointer) {
    checkIncoming();
    if (free_reuse) {
        const char* reason = NULL;
        reused_connection = OsConnection(&gOsModules[0], pointer, &reason);
    }
    leaveOriginal();
}
static int __cdecl fakeClear(void* pointer) { checkIncoming(); leaveOriginal(); return ((FakeSsl*)pointer)->result; }

int main(void) {
    OpenSslInit();
    for (unsigned int i = 0; i < 2; ++i) {
        OsModule* owner = &gOsModules[i];
        owner->read = fakeRead; owner->write = fakeWrite; owner->readEx = fakeReadEx;
        owner->writeEx = fakeWriteEx; owner->free = fakeFree; owner->clear = fakeClear;
        owner->module = (HMODULE)(uintptr_t)(i + 1); owner->active = 1;
    }
    gOsModuleCount = 2;
    FakeSsl ssl = {4, 4, 0, 0};
    unsigned char bytes[4]; memcpy(bytes, payload, sizeof(bytes));
    setIncoming(); CHECK(OsWrite0(&ssl, bytes, 4) == 4 && GetLastError() == 456 && errno == EINVAL);
    CHECK(writes == 1 && written_size == 4 && original_size == 4 && !memcmp(written_data, payload, 4));
    CHECK(!strcmp(written_direction, "out") && readiness == 1 && incoming_ok);
    unsigned long long first = written_connection;
    setIncoming(); CHECK(OsRead0(&ssl, bytes, 4) == 4 && GetLastError() == 456 && errno == EINVAL);
    CHECK(writes == 2 && written_connection == first && !strcmp(written_direction, "in"));

    ssl.result = 2; ssl.mutate = 1; memcpy(bytes, payload, 4);
    setIncoming(); CHECK(OsWrite0(&ssl, bytes, 4) == 2 && GetLastError() == 456 && errno == EINVAL);
    CHECK(writes == 3 && written_size == 2 && original_size == 2 && !memcmp(written_data, payload, 2));
    CHECK(!memcmp(bytes, "!!!!", 4)); ssl.mutate = 0;
    int prior = writes;
    for (int failure = -1; failure <= 0; ++failure) {
        ssl.result = failure;
        setIncoming(); CHECK(OsWrite0(&ssl, bytes, 4) == failure && GetLastError() == 456 && errno == EINVAL);
        setIncoming(); CHECK(OsRead0(&ssl, bytes, 4) == failure && GetLastError() == 456 && errno == EINVAL);
    }
    CHECK(writes == prior && gaps == 0);

    size_t accepted = 999; ssl.result = 1; ssl.accepted = 2; memcpy(bytes, payload, 4);
    setIncoming(); CHECK(OsWriteEx0(&ssl, bytes, 4, &accepted) == 1 && accepted == 2 && GetLastError() == 456 && errno == EINVAL);
    CHECK(writes == prior + 1 && written_size == 2 && original_size == 2);
    setIncoming(); CHECK(OsReadEx0(&ssl, bytes, 4, &accepted) == 1 && accepted == 2 && GetLastError() == 456 && errno == EINVAL);
    CHECK(writes == prior + 2 && written_size == 2 && !memcmp(written_data, payload, 2));
    ssl.result = 0; ssl.accepted = 4;
    setIncoming(); CHECK(OsWriteEx0(&ssl, bytes, 4, &accepted) == 0 && GetLastError() == 456 && errno == EINVAL);
    CHECK(writes == prior + 2);
    ssl.result = 1; ssl.accepted = 5;
    setIncoming(); CHECK(OsReadEx0(&ssl, bytes, 4, &accepted) == 1 && GetLastError() == 456 && errno == EINVAL);
    CHECK(writes == prior + 2 && gaps == 1);
    ssl.accepted = 0;
    setIncoming(); CHECK(OsWriteEx0(&ssl, bytes, 0, &accepted) == 1);
    CHECK(writes == prior + 2 && gaps == 1);

    ssl.result = 1; ssl.accepted = 4; ssl.nested = 1;
    setIncoming(); CHECK(OsWrite0(&ssl, bytes, 4) == 4 && GetLastError() == 456 && errno == EINVAL);
    CHECK(writes == prior + 3);
    ssl.result = 4; ssl.nested = 2;
    setIncoming(); CHECK(OsWriteEx0(&ssl, bytes, 4, &accepted) == 1 && accepted == 4 && GetLastError() == 456 && errno == EINVAL);
    CHECK(writes == prior + 4 && incoming_ok); ssl.nested = 0;

    const char* reason = NULL;
    CHECK(OsConnection(&gOsModules[0], &ssl, &reason) == first);
    CHECK(OsConnection(&gOsModules[1], &ssl, &reason) != first);
    ssl.result = 0; setIncoming(); CHECK(OsClear0(&ssl) == 0 && GetLastError() == 456 && errno == EINVAL);
    CHECK(OsConnection(&gOsModules[0], &ssl, &reason) == first);
    ssl.result = 1; setIncoming(); CHECK(OsClear0(&ssl) == 1 && GetLastError() == 456 && errno == EINVAL);
    unsigned long long reset = OsConnection(&gOsModules[0], &ssl, &reason);
    CHECK(reset != first);
    free_reuse = 1; setIncoming(); OsFree0(&ssl); CHECK(GetLastError() == 456 && errno == EINVAL);
    CHECK(reused_connection != reset && OsConnection(&gOsModules[0], &ssl, &reason) == reused_connection);
    free_reuse = 0;

    prior = writes; gOsModules[0].active = 0; ssl.result = 4;
    setIncoming(); CHECK(OsWrite0(&ssl, bytes, 4) == 4 && GetLastError() == 456 && errno == EINVAL);
    CHECK(writes == prior); gOsModules[0].active = 1;
    available = 0; setIncoming(); CHECK(OsRead0(&ssl, bytes, 4) == 4 && GetLastError() == 456 && errno == EINVAL);
    CHECK(writes == prior); available = 1;

    unsigned char* big = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, OS_CAPTURE_LIMIT + 7);
    CHECK(big != NULL);
    if (big) {
        memset(big, 'Q', OS_CAPTURE_LIMIT + 7); ssl.result = OS_CAPTURE_LIMIT + 7;
        setIncoming(); CHECK(OsWrite0(&ssl, big, OS_CAPTURE_LIMIT + 7) == OS_CAPTURE_LIMIT + 7);
        CHECK(written_size == OS_CAPTURE_LIMIT && original_size == OS_CAPTURE_LIMIT + 7);
        HeapFree(GetProcessHeap(), 0, big);
    }
    ssl.result = 4; prior = gaps;
    setIncoming(); CHECK(OsWrite0(&ssl, (const void*)1, 4) == 4 && GetLastError() == 456 && errno == EINVAL);
    CHECK(gaps == prior + 1);
    unsigned long long old = OsConnection(&gOsModules[1], &ssl, &reason);
    OpenSslModuleUnloaded((HMODULE)(uintptr_t)2);
    CHECK(!gOsModules[1].active && gOsModules[1].write == fakeWrite);
    gOsModules[2] = gOsModules[0]; gOsModules[2].module = (HMODULE)(uintptr_t)2;
    CHECK(OsConnection(&gOsModules[2], &ssl, &reason) != old);
    CHECK(incoming_ok);
    /* Every module is probed during discovery; a protected or malformed PE
     * export directory must be skipped, never crash the instrumented process. */
    unsigned char* image = (unsigned char*)VirtualAlloc(NULL, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    CHECK(image != NULL);
    if (image) {
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)image;
        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(image + 256);
        dos->e_magic = IMAGE_DOS_SIGNATURE; dos->e_lfanew = 256;
        nt->Signature = IMAGE_NT_SIGNATURE;
        nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER);
        nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR_MAGIC;
        nt->OptionalHeader.SizeOfImage = 8192;
        nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 4096;
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 512;
        DWORD oldProtection;
        CHECK(VirtualProtect(image + 4096, 4096, PAGE_NOACCESS, &oldProtection));
        CHECK(OsLocalExport((HMODULE)image, "SSL_read") == NULL);
        nt->OptionalHeader.NumberOfRvaAndSizes = 0;
        CHECK(OsLocalExport((HMODULE)image, "SSL_read") == NULL);
        dos->e_lfanew = LONG_MAX;
        CHECK(OsLocalExport((HMODULE)image, "SSL_read") == NULL);
        CHECK(OsLocalExport((HMODULE)(uintptr_t)1, "SSL_read") == NULL);
        VirtualFree(image, 0, MEM_RELEASE);
    }
    printf("OpenSSL observer: %s (%d failures, %d original calls)\n", failures ? "FAIL" : "PASS", failures, calls);
    return failures ? 1 : 0;
}
