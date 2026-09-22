/* Local TLS fixture using dynamically resolved public OpenSSL exports only.
 * host_openssl <fragment-dll> <libssl-dll> <port> <legacy|ex>
 *              <bare|swept|delayed> [iterations] [threads] [reuse|reload]
 * Certificate verification is disabled in THIS loopback test client only.
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

typedef struct Api {
    const void* (__cdecl *method)(void);
    void* (__cdecl *ctxNew)(const void*);
    void (__cdecl *ctxFree)(void*);
    void (__cdecl *verify)(void*, int, void*);
    void* (__cdecl *sslNew)(void*);
    void (__cdecl *sslFree)(void*);
    int (__cdecl *clear)(void*);
    int (__cdecl *setFd)(void*, int);
    int (__cdecl *connect)(void*);
    int (__cdecl *shutdown)(void*);
    int (__cdecl *getError)(const void*, int);
    int (__cdecl *write)(void*, const void*, int);
    int (__cdecl *read)(void*, void*, int);
    int (__cdecl *writeEx)(void*, const void*, size_t, size_t*);
    int (__cdecl *readEx)(void*, void*, size_t, size_t*);
} Api;
static Api api;
static int port, useEx, iterations = 1, reuse;
static const unsigned char requestBody[] = {'f','r','a','g',0,255,128,13,10};
static const unsigned char responseBody[] = {'o','k',0,254,129,13,10,'!'};

static HMODULE loadApi(const char* path) {
    char absolute[MAX_PATH];
    DWORD count = GetFullPathNameA(path, MAX_PATH, absolute, NULL);
    if (!count || count >= MAX_PATH) return NULL;
    HMODULE module = LoadLibraryExA(absolute, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!module) { fprintf(stderr, "libssl load failed %lu\n", GetLastError()); return NULL; }
#define RESOLVE(field, symbol) do { *(FARPROC*)&api.field = GetProcAddress(module, symbol); \
    if (!api.field) { fprintf(stderr, "Missing %s\n", symbol); FreeLibrary(module); return NULL; } } while (0)
    RESOLVE(method, "TLS_client_method"); RESOLVE(ctxNew, "SSL_CTX_new");
    RESOLVE(ctxFree, "SSL_CTX_free"); RESOLVE(verify, "SSL_CTX_set_verify");
    RESOLVE(sslNew, "SSL_new"); RESOLVE(sslFree, "SSL_free");
    RESOLVE(clear, "SSL_clear"); RESOLVE(setFd, "SSL_set_fd");
    RESOLVE(connect, "SSL_connect"); RESOLVE(shutdown, "SSL_shutdown");
    RESOLVE(getError, "SSL_get_error"); RESOLVE(write, "SSL_write"); RESOLVE(read, "SSL_read");
    if (useEx) { RESOLVE(writeEx, "SSL_write_ex"); RESOLVE(readEx, "SSL_read_ex"); }
#undef RESOLVE
    return module;
}

static int transaction(void* ssl) {
    SOCKET socketFd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socketFd == INVALID_SOCKET || socketFd > INT_MAX) return 0;
    DWORD timeout = 15000;
    setsockopt(socketFd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(socketFd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET; address.sin_port = htons((unsigned short)port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(socketFd, (const struct sockaddr*)&address, sizeof(address)) ||
        api.setFd(ssl, (int)socketFd) != 1 || api.connect(ssl) != 1) {
        fprintf(stderr, "TLS connect failed\n"); closesocket(socketFd); return 0;
    }

    /* A genuine retryable read must remain a retryable read with no captured
     * plaintext. SSL_get_error is called immediately by the application. */
    unsigned char response[32768];
    u_long nonblocking = 1; ioctlsocket(socketFd, FIONBIO, &nonblocking);
    size_t actual = 0;
    int probe = useEx ? api.readEx(ssl, response, sizeof(response), &actual)
                      : api.read(ssl, response, (int)sizeof(response));
    int why = api.getError(ssl, probe);
    nonblocking = 0; ioctlsocket(socketFd, FIONBIO, &nonblocking);
    if ((useEx ? probe != 0 : probe >= 0) || why != 2) {
        fprintf(stderr, "Retry probe changed: result=%d SSL_get_error=%d\n", probe, why);
        closesocket(socketFd); return 0;
    }

    unsigned char request[512];
    int header = sprintf_s((char*)request, sizeof(request),
        "POST /openssl/binary?source=exports HTTP/1.1\r\nHost: localhost\r\n"
        "Content-Length: %u\r\nConnection: close\r\n\r\n", (unsigned int)sizeof(requestBody));
    memcpy(request + header, requestBody, sizeof(requestBody));
    size_t total = (size_t)header + sizeof(requestBody), sent = 0;
    while (sent < total) {
        size_t wrote = 0;
        int result = useEx ? api.writeEx(ssl, request + sent, total - sent, &wrote)
                           : api.write(ssl, request + sent, (int)(total - sent));
        if (useEx ? result != 1 : result <= 0) {
            fprintf(stderr, "TLS write failed: %d\n", api.getError(ssl, result));
            closesocket(socketFd); return 0;
        }
        if (!useEx) wrote = (size_t)result;
        if (!wrote || wrote > total - sent) { closesocket(socketFd); return 0; }
        sent += wrote;
    }
    size_t received = 0;
    int valid = 0;
    while (received < sizeof(response) - 1) {
        size_t got = 0;
        int result = useEx ? api.readEx(ssl, response + received, sizeof(response) - 1 - received, &got)
                           : api.read(ssl, response + received, (int)(sizeof(response) - 1 - received));
        if (useEx ? result != 1 : result <= 0) break;
        if (!useEx) got = (size_t)result;
        if (!got || got > sizeof(response) - 1 - received) break;
        received += got; response[received] = 0;
        unsigned char* split = (unsigned char*)strstr((char*)response, "\r\n\r\n");
        if (split && received >= (size_t)(split + 4 - response) + sizeof(responseBody)) {
            valid = !memcmp(response, "HTTP/1.1 200", 12) &&
                    received == (size_t)(split + 4 - response) + sizeof(responseBody) &&
                    !memcmp(split + 4, responseBody, sizeof(responseBody));
            break;
        }
    }
    api.shutdown(ssl);
    closesocket(socketFd);
    if (!valid) fprintf(stderr, "Response mismatch (%zu bytes)\n", received);
    return valid;
}

static unsigned int __stdcall worker(void* unused) {
    (void)unused;
    void* ctx = api.ctxNew(api.method());
    if (!ctx) return 1;
    api.verify(ctx, 0, NULL); /* Only the committed self-signed loopback fixture. */
    void* ssl = NULL;
    unsigned int failed = 0;
    for (int i = 0; i < iterations; ++i) {
        if (!ssl) ssl = api.sslNew(ctx);
        if (!ssl || !transaction(ssl)) { failed = 1; break; }
        if (reuse && i + 1 < iterations) {
            if (api.clear(ssl) != 1) { failed = 1; break; }
        } else { api.sslFree(ssl); ssl = NULL; }
    }
    if (ssl) api.sslFree(ssl);
    api.ctxFree(ctx);
    return failed;
}

int main(int argc, char** argv) {
    if (argc < 6) { fprintf(stderr, "host_openssl <fragment> <libssl> <port> <legacy|ex> <bare|swept|delayed> [iterations] [threads] [reuse|reload]\n"); return 2; }
    port = atoi(argv[3]); useEx = !strcmp(argv[4], "ex");
    iterations = argc > 6 ? atoi(argv[6]) : 1;
    int threads = argc > 7 ? atoi(argv[7]) : 1;
    reuse = argc > 8 && !strcmp(argv[8], "reuse");
    int reload = argc > 8 && !strcmp(argv[8], "reload");
    if (port < 1 || port > 65535 || iterations < 1 || iterations > 32 || threads < 1 || threads > 8) return 2;
    WSADATA data; if (WSAStartup(MAKEWORD(2, 2), &data)) return 2;
    HMODULE module = NULL;
    if (!strcmp(argv[5], "swept") && !(module = loadApi(argv[2]))) return 3;
    if (strcmp(argv[5], "bare") && !LoadLibraryA(argv[1])) {
        fprintf(stderr, "Fragment load failed %lu\n", GetLastError()); return 4;
    }
    if (!module && !(module = loadApi(argv[2]))) return 3;
    int rounds = reload ? 2 : 1, result = 0;
    for (int round = 0; round < rounds; ++round) {
        HANDLE workers[8]; int started = 0;
        for (int i = 0; i < threads; ++i) {
            HANDLE handle = (HANDLE)_beginthreadex(NULL, 0, worker, NULL, 0, NULL);
            if (!handle) { result = 5; break; }
            workers[started++] = handle;
        }
        if (started) WaitForMultipleObjects(started, workers, TRUE, INFINITE);
        for (int i = 0; i < started; ++i) {
            DWORD code = 1; GetExitCodeThread(workers[i], &code); CloseHandle(workers[i]);
            if (code) result = 6;
        }
        if (result || round + 1 == rounds) break;
        FreeLibrary(module);
        if (!(module = loadApi(argv[2]))) { result = 3; break; }
    }
    if (module) FreeLibrary(module);
    WSACleanup();
    printf("OpenSSL fixture: %s (%d request(s), %s API, retry semantics preserved)\n",
           result ? "FAIL" : "PASS", iterations * threads * rounds, useEx ? "_ex" : "legacy");
    return result;
}
