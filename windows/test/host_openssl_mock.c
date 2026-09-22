/* Actual inline-hook, multiple DLL and unload/reload fixture for mockssl.c. */
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef struct Api {
    void* (__cdecl *newSsl)(void*);
    void (__cdecl *set)(void*, int, int);
    int (__cdecl *write)(void*, const void*, int);
    int (__cdecl *read)(void*, void*, int);
    int (__cdecl *writeEx)(void*, const void*, size_t, size_t*);
    int (__cdecl *readEx)(void*, void*, size_t, size_t*);
    int (__cdecl *clear)(void*);
    void (__cdecl *free)(void*);
} Api;
static int failures;
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d: %s\n", __LINE__, #x); ++failures; } } while (0)
static HMODULE loadApi(const char* path, Api* api) {
    HMODULE module = LoadLibraryA(path);
    if (!module) return NULL;
#define GET(field, symbol) do { *(FARPROC*)&api->field = GetProcAddress(module, symbol); if (!api->field) return NULL; } while (0)
    GET(newSsl, "SSL_new"); GET(set, "SSL_mock_set"); GET(write, "SSL_write"); GET(read, "SSL_read");
    GET(writeEx, "SSL_write_ex"); GET(readEx, "SSL_read_ex"); GET(clear, "SSL_clear"); GET(free, "SSL_free");
#undef GET
    return module;
}
static void exercise(Api* api) {
    static const unsigned char outgoing[] = {'a', 0, 255, 'z'};
    static const unsigned char reply[] = {'r', 0, 255, 'x'};
    unsigned char bytes[32]; size_t actual = 0;
    void* ssl = api->newSsl(NULL); CHECK(ssl != NULL); if (!ssl) return;
    api->set(ssl, 0, 2); SetLastError(123); errno = EDOM;
    CHECK(api->write(ssl, outgoing, 4) == 2 && GetLastError() == 456 && errno == EINVAL);
    api->set(ssl, 0, 0); SetLastError(123); errno = EDOM;
    CHECK(api->writeEx(ssl, outgoing + 2, 2, &actual) == 1 && actual == 2 && GetLastError() == 456 && errno == EINVAL);
    SetLastError(123); errno = EDOM;
    CHECK(api->readEx(ssl, bytes, sizeof(bytes), &actual) == 1 && actual == 4 && GetLastError() == 456 && errno == EINVAL);
    CHECK(!memcmp(bytes, reply, 4));
    api->set(ssl, 1, 0); SetLastError(123); errno = EDOM;
    CHECK(api->write(ssl, "failed", 6) == -1 && GetLastError() == 456 && errno == EINVAL);
    SetLastError(123); errno = EDOM;
    CHECK(api->read(ssl, bytes, sizeof(bytes)) == -1 && GetLastError() == 456 && errno == EINVAL);
    SetLastError(123); errno = EDOM;
    CHECK(api->clear(ssl) == 1 && GetLastError() == 456 && errno == EINVAL);
    SetLastError(123); errno = EDOM;
    CHECK(api->write(ssl, "clear", 5) == 5 && GetLastError() == 456 && errno == EINVAL);
    api->free(ssl);
    ssl = api->newSsl(NULL); CHECK(ssl != NULL); if (!ssl) return;
    SetLastError(123); errno = EDOM;
    CHECK(api->write(ssl, "new", 3) == 3 && GetLastError() == 456 && errno == EINVAL);
    api->free(ssl);
}
int main(int argc, char** argv) {
    if (argc != 5) { fprintf(stderr, "host_openssl_mock <fragment> <mockA> <mockB> <bare|swept|delayed>\n"); return 2; }
    Api a, b; HMODULE ma = NULL, mb = NULL;
    if (!strcmp(argv[4], "swept")) { ma = loadApi(argv[2], &a); mb = loadApi(argv[3], &b); }
    if (strcmp(argv[4], "bare") && !LoadLibraryA(argv[1])) return 3;
    if (!ma) ma = loadApi(argv[2], &a);
    if (!mb) mb = loadApi(argv[3], &b);
    if (!ma || !mb || ma == mb) return 4;
    exercise(&a); exercise(&b);
    FreeLibrary(ma);
    /* Query by full path, without incrementing reference count. This fixture
     * proves an actual unload, not merely a balanced FreeLibrary call. */
    CHECK(GetModuleHandleA(argv[2]) == NULL);
    ma = loadApi(argv[2], &a); if (!ma) return 5;
    exercise(&a);
    FreeLibrary(ma); FreeLibrary(mb);
    printf("OpenSSL exported mock: %s (%d failures, two libraries and one actual reload)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
