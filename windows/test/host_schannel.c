/* Local-only Schannel TLS client. The test server uses an intentionally public
 * self-signed fixture certificate; certificate validation is disabled HERE ONLY.
 * No WinHTTP, libcurl, or other HTTP implementation is involved.
 * host_schannel.exe <fragment-dll> <port> <exports|table-a|table-w>
 *                   <bare|swept|delayed> [threads] [iterations] [probes]
 * Cached SSPI tables are resolved BEFORE Fragment in the swept case.
 */
#define SECURITY_WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <security.h>
#include <schannel.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WIRE_CAP 65536
#define CLEAR_CAP 65536
static SecurityFunctionTableA api;
static int probe_messages;
static const unsigned char request_body[] = { 'f', 'r', 'a', 'g', 0, 255, 128, '\r', '\n' };
static const unsigned char response_body[] = { 'o', 'k', 0, 254, 129, '\r', '\n', '!' };

typedef struct {
    SOCKET socket;
    CredHandle credential;
    CtxtHandle context;
    int have_credential, have_context;
    unsigned char wire[WIRE_CAP];
    unsigned int wire_len;
} Client;

static int send_all(SOCKET socket, const void* data, unsigned int length) {
    const char* p = (const char*)data;
    while (length) {
        int n = send(socket, p, (int)length, 0);
        if (n <= 0) return 0;
        p += n; length -= (unsigned int)n;
    }
    return 1;
}

static int receive_more(Client* client) {
    int n;
    if (client->wire_len == WIRE_CAP) return 0;
    n = recv(client->socket, (char*)client->wire + client->wire_len,
             WIRE_CAP - (int)client->wire_len, 0);
    if (n <= 0) return 0;
    client->wire_len += (unsigned int)n;
    return 1;
}

static int handshake(Client* client) {
    SCHANNEL_CRED options = {0};
    TimeStamp expiry;
    ULONG attributes = 0;
    const ULONG flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
        ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
    SECURITY_STATUS status;
    options.dwVersion = SCHANNEL_CRED_VERSION;
    options.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
    options.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
    status = api.AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND,
        NULL, &options, NULL, NULL, &client->credential, &expiry);
    if (status != SEC_E_OK) return 0;
    client->have_credential = 1;
    for (;;) {
        SecBuffer input[2] = {{client->wire_len, SECBUFFER_TOKEN, client->wire},
                              {0, SECBUFFER_EMPTY, NULL}};
        SecBuffer output = {0, SECBUFFER_TOKEN, NULL};
        SecBufferDesc in = {SECBUFFER_VERSION, 2, input};
        SecBufferDesc out = {SECBUFFER_VERSION, 1, &output};
        status = api.InitializeSecurityContextA(&client->credential,
            client->have_context ? &client->context : NULL, "localhost", flags,
            0, SECURITY_NATIVE_DREP, client->have_context ? &in : NULL, 0,
            &client->context, &out, &attributes, &expiry);
        if (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED ||
            status == SEC_E_INCOMPLETE_MESSAGE) client->have_context = 1;
        if (output.pvBuffer) {
            int sent = send_all(client->socket, output.pvBuffer, output.cbBuffer);
            api.FreeContextBuffer(output.pvBuffer);
            if (!sent) return 0;
        }
        if (status == SEC_E_INCOMPLETE_MESSAGE) {
            if (!receive_more(client)) return 0;
            continue;
        }
        if (status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED) {
            fprintf(stderr, "TLS handshake failed: 0x%08lx\n", (unsigned long)status);
            return 0;
        }
        if (input[1].BufferType == SECBUFFER_EXTRA) {
            memmove(client->wire, client->wire + client->wire_len - input[1].cbBuffer,
                    input[1].cbBuffer);
            client->wire_len = input[1].cbBuffer;
        } else client->wire_len = 0;
        if (status == SEC_E_OK) return 1;
        if (!client->wire_len && !receive_more(client)) return 0;
    }
}

static int transmit(Client* client) {
    SecPkgContext_StreamSizes sizes;
    unsigned char request[512];
    unsigned char* record;
    SecBuffer buffers[4];
    SecBufferDesc message = {SECBUFFER_VERSION, 4, buffers};
    int header, good = 0;
    unsigned int length;
    SECURITY_STATUS status = api.QueryContextAttributesA(&client->context,
        SECPKG_ATTR_STREAM_SIZES, &sizes);
    if (status != SEC_E_OK) return 0;
    header = sprintf_s((char*)request, sizeof(request),
        "POST /schannel/binary?source=sspi HTTP/1.1\r\nHost: localhost\r\n"
        "Content-Length: %u\r\nConnection: close\r\n\r\n", (unsigned int)sizeof(request_body));
    if (header <= 0) return 0;
    memcpy(request + header, request_body, sizeof(request_body));
    length = (unsigned int)header + (unsigned int)sizeof(request_body);
    record = (unsigned char*)malloc(sizes.cbHeader + length + sizes.cbTrailer);
    if (!record) return 0;
    memcpy(record + sizes.cbHeader, request, length);
    buffers[0] = (SecBuffer){sizes.cbHeader, SECBUFFER_STREAM_HEADER, record};
    buffers[1] = (SecBuffer){length, SECBUFFER_DATA, record + sizes.cbHeader};
    buffers[2] = (SecBuffer){sizes.cbTrailer, SECBUFFER_STREAM_TRAILER, record + sizes.cbHeader + length};
    buffers[3] = (SecBuffer){0, SECBUFFER_EMPTY, NULL};
    status = api.EncryptMessage(&client->context, 0, &message, 0);
    if (status == SEC_E_OK) {
        good = 1;
        for (int i = 0; i < 3; ++i)
            if (!send_all(client->socket, buffers[i].pvBuffer, buffers[i].cbBuffer)) good = 0;
    }
    free(record);
    return good;
}

/* Failed operations must not expose either unsent plaintext or ciphertext.
 * A deliberately incomplete TLS header tests SEC_E_INCOMPLETE_MESSAGE without
 * consuming a real record; omitting STREAM_HEADER/TRAILER rejects encryption.
 */
static int unsuccessful_messages(Client* client) {
    unsigned char unsent[] = "THIS-FAILED-ENCRYPTION-MUST-NOT-BE-CAPTURED";
    unsigned char partial_record[] = {23};
    SecBuffer incomplete[4] = {{1, SECBUFFER_DATA, partial_record},
        {0, SECBUFFER_EMPTY, NULL}, {0, SECBUFFER_EMPTY, NULL}, {0, SECBUFFER_EMPTY, NULL}};
    SecBufferDesc incoming = {SECBUFFER_VERSION, 4, incomplete};
    SecBuffer invalid = {sizeof(unsent) - 1, SECBUFFER_DATA, unsent};
    SecBufferDesc outgoing = {SECBUFFER_VERSION, 1, &invalid};
    ULONG qop = 0;
    SECURITY_STATUS encrypted = api.EncryptMessage(&client->context, 0, &outgoing, 0);
    SECURITY_STATUS decrypted = api.DecryptMessage(&client->context, &incoming, 0, &qop);
    if (encrypted == SEC_E_OK || decrypted != SEC_E_INCOMPLETE_MESSAGE) {
        fprintf(stderr, "Unexpected failure-probe statuses: encrypt=0x%08lx decrypt=0x%08lx\n",
            (unsigned long)encrypted, (unsigned long)decrypted);
        return 0;
    }
    return 1;
}

static int receive_response(Client* client) {
    unsigned char clear[CLEAR_CAP];
    unsigned int clear_len = 0;
    for (;;) {
        SecBuffer buffers[4] = {{client->wire_len, SECBUFFER_DATA, client->wire},
            {0, SECBUFFER_EMPTY, NULL}, {0, SECBUFFER_EMPTY, NULL}, {0, SECBUFFER_EMPTY, NULL}};
        SecBufferDesc message = {SECBUFFER_VERSION, 4, buffers};
        SECURITY_STATUS status;
        ULONG qop = 0, extra = 0;
        if (!client->wire_len) {
            if (!receive_more(client)) return 0;
            buffers[0].cbBuffer = client->wire_len;
        }
        status = api.DecryptMessage(&client->context, &message, 0, &qop);
        if (status == SEC_E_INCOMPLETE_MESSAGE) {
            if (!receive_more(client)) return 0;
            continue;
        }
        if (status != SEC_E_OK) return 0;
        for (int i = 0; i < 4; ++i) {
            if (buffers[i].BufferType == SECBUFFER_DATA) {
                if (buffers[i].cbBuffer > CLEAR_CAP - clear_len - 1) return 0;
                memcpy(clear + clear_len, buffers[i].pvBuffer, buffers[i].cbBuffer);
                clear_len += buffers[i].cbBuffer;
            }
            if (buffers[i].BufferType == SECBUFFER_EXTRA) extra = buffers[i].cbBuffer;
        }
        if (extra) memmove(client->wire, client->wire + client->wire_len - extra, extra);
        client->wire_len = extra;
        clear[clear_len] = 0;
        if (clear_len >= 12 && memcmp(clear, "HTTP/1.1 200", 12) != 0) return 0;
        {
            char* end = strstr((char*)clear, "\r\n\r\n");
            if (end) {
                unsigned int offset = (unsigned int)(end - (char*)clear) + 4;
                if (clear_len >= offset + sizeof(response_body))
                    return clear_len == offset + sizeof(response_body) &&
                        memcmp(clear + offset, response_body, sizeof(response_body)) == 0;
            }
        }
    }
}

static int request(int port) {
    Client client = {0};
    struct sockaddr_in address = {0};
    DWORD timeout = 10000;
    int good = 0;
    client.socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client.socket == INVALID_SOCKET) return 0;
    setsockopt(client.socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(client.socket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((unsigned short)port);
    if (connect(client.socket, (struct sockaddr*)&address, sizeof(address)) == 0 &&
        handshake(&client) && (!probe_messages || unsuccessful_messages(&client)) &&
        transmit(&client) && receive_response(&client)) good = 1;
    if (client.have_context) api.DeleteSecurityContext(&client.context);
    if (client.have_credential) api.FreeCredentialsHandle(&client.credential);
    closesocket(client.socket);
    return good;
}

typedef struct { int port, iterations, good; } Worker;
static unsigned __stdcall worker(void* argument) {
    Worker* job = (Worker*)argument;
    job->good = 1;
    for (int i = 0; i < job->iterations; ++i)
        if (!request(job->port)) { job->good = 0; break; }
    return 0;
}

static int resolve_api(const char* mode) {
    HMODULE library = LoadLibraryW(L"secur32.dll");
    INIT_SECURITY_INTERFACE_A initialize;
    if (!library) return 0;
    initialize = (INIT_SECURITY_INTERFACE_A)GetProcAddress(library, "InitSecurityInterfaceA");
    if (!initialize || !initialize()) return 0;
    api = *initialize();
    if (!strcmp(mode, "exports")) {
        api.EncryptMessage = (ENCRYPT_MESSAGE_FN)GetProcAddress(library, "EncryptMessage");
        api.DecryptMessage = (DECRYPT_MESSAGE_FN)GetProcAddress(library, "DecryptMessage");
        api.DeleteSecurityContext = (DELETE_SECURITY_CONTEXT_FN)GetProcAddress(library, "DeleteSecurityContext");
    } else if (!strcmp(mode, "table-w")) {
        INIT_SECURITY_INTERFACE_W initialize_w = (INIT_SECURITY_INTERFACE_W)
            GetProcAddress(library, "InitSecurityInterfaceW");
        PSecurityFunctionTableW wide;
        if (!initialize_w || !(wide = initialize_w())) return 0;
        api.EncryptMessage = wide->EncryptMessage;
        api.DecryptMessage = wide->DecryptMessage;
        api.DeleteSecurityContext = wide->DeleteSecurityContext;
    } else if (strcmp(mode, "table-a")) return 0;
    return api.EncryptMessage && api.DecryptMessage && api.DeleteSecurityContext;
}

int main(int argc, char** argv) {
    WSADATA winsock;
    Worker workers[16];
    HANDLE threads[16];
    int count, iterations, good = 1, created = 0;
    if (argc < 5) return 64;
    count = argc > 5 ? atoi(argv[5]) : 1;
    iterations = argc > 6 ? atoi(argv[6]) : 1;
    probe_messages = argc > 7 && !strcmp(argv[7], "probes");
    if (count < 1 || count > 16 || iterations < 1 || iterations > 100) return 64;
    if (!strcmp(argv[4], "swept") && !resolve_api(argv[3])) return 65;
    if (strcmp(argv[4], "bare") && !LoadLibraryA(argv[1])) {
        fprintf(stderr, "LoadLibrary(Fragment) failed: %lu\n", GetLastError()); return 66;
    }
    if (strcmp(argv[4], "swept") && !resolve_api(argv[3])) return 65;
    if (getenv("FRAGMENT_TEST_EXPECT_PROXY")) {
        const char* expected = getenv("FRAGMENT_TEST_EXPECT_PROXY");
        char actual[512];
        DWORD length = GetEnvironmentVariableA("HTTP_PROXY", actual, sizeof(actual));
        if (!length || length >= sizeof(actual) || strcmp(actual, expected)) {
            fprintf(stderr, "Observation changed the application's HTTP_PROXY\n"); return 68;
        }
    }
    if (WSAStartup(MAKEWORD(2, 2), &winsock)) return 67;
    for (int i = 0; i < count; ++i) {
        workers[i] = (Worker){atoi(argv[2]), iterations, 0};
        threads[i] = (HANDLE)_beginthreadex(NULL, 0, worker, &workers[i], 0, NULL);
        if (!threads[i]) { good = 0; break; }
        ++created;
    }
    for (int i = 0; i < created; ++i) {
        WaitForSingleObject(threads[i], INFINITE);
        CloseHandle(threads[i]);
        if (!workers[i].good) good = 0;
    }
    WSACleanup();
    if (good) printf("Verified %d binary Schannel round trips\n", count * iterations);
    return good ? 0 : 1;
}
