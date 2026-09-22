/* Deterministic SSPI failure/lifetime tests. No network or installed hooks. */
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "../capture.h"

static int available = 1, writes, readiness;
static unsigned long long next_connection, written_connection;
static unsigned char written_data[128];
static size_t written_size;
static const char* written_direction;
static BOOL testAvailable(void) { return available; }
static unsigned long long testNextConnection(void) { return ++next_connection; }
static void testBackend(const char* backend, BOOL ready) { if (ready) ++readiness; }
static void testWrite(const char* backend, unsigned long long connection,
    const char* direction, const void* data, size_t captured, size_t original) {
    ++writes; written_connection = connection; written_direction = direction;
    written_size = captured;
    if (captured <= sizeof(written_data)) memcpy(written_data, data, captured);
    SetLastError(0xdddd);
}
#define CaptureAvailable testAvailable
#define CaptureNextConnection testNextConnection
#define CaptureBackend testBackend
#define CaptureWrite testWrite
#include "../main.c"
#undef CaptureAvailable
#undef CaptureNextConnection
#undef CaptureBackend
#undef CaptureWrite

static int failures, original_calls, query_calls, incoming_error_ok = 1;
static SECURITY_STATUS encrypt_status = SEC_E_OK, decrypt_status = SEC_E_OK, delete_status = SEC_E_OK;
static int schannel_package = 1;
static int reuse_during_delete;
static unsigned long long reused_connection;
static const unsigned char plaintext[] = {'a', 0, 255, 'z'};
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d: %s\n", __LINE__, #x); ++failures; } } while (0)

static SECURITY_STATUS SEC_ENTRY queryMock(PCtxtHandle context, ULONG attribute, PVOID result) {
    static SecPkgInfoW info;
    ++query_calls;
    if (attribute != SECPKG_ATTR_PACKAGE_INFO) return SEC_E_UNSUPPORTED_FUNCTION;
    memset(&info, 0, sizeof(info));
    info.Name = schannel_package ? L"Microsoft Unified Security Protocol Provider" : L"NTLM";
    ((SecPkgContext_PackageInfoW*)result)->PackageInfo = &info;
    SetLastError(0xbbbb);
    return SEC_E_OK;
}
static SECURITY_STATUS SEC_ENTRY freeMock(PVOID data) { SetLastError(0xcccc); return SEC_E_OK; }
static SECURITY_STATUS SEC_ENTRY encryptMock(PCtxtHandle context, ULONG qop,
    PSecBufferDesc message, ULONG sequence) {
    ++original_calls;
    if (GetLastError() != 0x1234) incoming_error_ok = 0;
    if (encrypt_status == SEC_E_OK && message && message->pBuffers)
        for (ULONG i = 0; i < message->cBuffers; ++i)
            if (message->pBuffers[i].BufferType == SECBUFFER_DATA)
                memset(message->pBuffers[i].pvBuffer, 0xee, message->pBuffers[i].cbBuffer);
    SetLastError(0x5678);
    return encrypt_status;
}
static SECURITY_STATUS SEC_ENTRY decryptMock(PCtxtHandle context, PSecBufferDesc message,
    ULONG sequence, PULONG qop) {
    ++original_calls;
    if (GetLastError() != 0x1234) incoming_error_ok = 0;
    if (decrypt_status == SEC_E_OK) {
        message->pBuffers[0].BufferType = SECBUFFER_DATA;
        message->pBuffers[0].pvBuffer = (PVOID)plaintext;
        message->pBuffers[0].cbBuffer = sizeof(plaintext);
    }
    SetLastError(0x5678);
    return decrypt_status;
}
static SECURITY_STATUS SEC_ENTRY deleteMock(PCtxtHandle context) {
    ++original_calls;
    if (GetLastError() != 0x1234) incoming_error_ok = 0;
    if (delete_status == SEC_E_OK) {
        CtxtHandle reused = *context;
        memset(context, 0, sizeof(*context));
        /* Models a second thread allocating the just-released handle before
         * DeleteSecurityContext returns to Fragment's detour. */
        if (reuse_during_delete) {
            const char* omitted = NULL;
            reused_connection = ScConnection(&reused, &omitted);
        }
    }
    SetLastError(0x5678);
    return delete_status;
}
static void encrypt(CtxtHandle* context, ULONG qop, ULONG type) {
    unsigned char bytes[sizeof(plaintext)];
    memcpy(bytes, plaintext, sizeof(bytes));
    SecBuffer buffer = {sizeof(bytes), type, bytes};
    SecBufferDesc message = {SECBUFFER_VERSION, 1, &buffer};
    int before = original_calls;
    SetLastError(0x1234);
    CHECK(ScEncryptDetour(context, qop, &message, 0) == encrypt_status);
    CHECK(GetLastError() == 0x5678 && original_calls == before + 1);
    if (encrypt_status == SEC_E_OK && type == SECBUFFER_DATA)
        CHECK(bytes[0] == 0xee); /* Provider still receives/mutates caller storage. */
}
static void decrypt(CtxtHandle* context) {
    unsigned char ciphertext[] = {0x17, 3, 3, 0, 4, 0xee, 0xee, 0xee, 0xee};
    SecBuffer buffer = {sizeof(ciphertext), SECBUFFER_DATA, ciphertext};
    SecBufferDesc message = {SECBUFFER_VERSION, 1, &buffer};
    ULONG qop = 0;
    int before = original_calls;
    SetLastError(0x1234);
    CHECK(ScDecryptDetour(context, &message, 0, &qop) == decrypt_status);
    CHECK(GetLastError() == 0x5678 && original_calls == before + 1);
}

int main(void) {
    CtxtHandle first = {10, 20}, copy = first, other = {10, 21};
    SchannelInit();
    gScEncrypt = encryptMock; gScDecrypt = decryptMock; gScDelete = deleteMock;
    gScQuery = queryMock; gScFree = freeMock;
    gScActive = 0;
    encrypt(&first, 0, SECBUFFER_DATA);
    CHECK(writes == 0 && query_calls == 0); /* Partial activation is pass-through. */
    gScActive = 1;
    available = 0;
    encrypt(&first, 0, SECBUFFER_DATA);
    CHECK(writes == 0 && query_calls == 0);
    available = 1;
    encrypt(&first, 0, SECBUFFER_DATA);
    CHECK(writes == 1 && written_size == sizeof(plaintext) && !memcmp(written_data, plaintext, sizeof(plaintext)));
    CHECK(!strcmp(written_direction, "out") && readiness == 1);
    unsigned long long first_id = written_connection;
    encrypt(&copy, 0, SECBUFFER_DATA);
    CHECK(writes == 2 && written_connection == first_id && query_calls == 1);
    decrypt(&copy);
    CHECK(writes == 3 && written_connection == first_id && !strcmp(written_direction, "in"));
    CHECK(written_size == sizeof(plaintext) && !memcmp(written_data, plaintext, sizeof(plaintext)));
    encrypt(&other, 0, SECBUFFER_DATA);
    CHECK(writes == 4 && written_connection != first_id);

    int before = writes;
    encrypt_status = SEC_E_INVALID_TOKEN;
    encrypt(&first, 0, SECBUFFER_DATA);
    encrypt_status = SEC_E_OK;
    decrypt_status = SEC_E_INCOMPLETE_MESSAGE;
    decrypt(&first);
    decrypt_status = SEC_I_RENEGOTIATE;
    decrypt(&first);
    decrypt_status = SEC_I_CONTEXT_EXPIRED;
    decrypt(&first);
    decrypt_status = SEC_E_OK;
    encrypt(&first, 0, SECBUFFER_DATA | SECBUFFER_READONLY);
    encrypt(&first, 0, SECBUFFER_DATA | SECBUFFER_READONLY_WITH_CHECKSUM);
    encrypt(&first, SECQOP_WRAP_OOB_DATA, SECBUFFER_DATA);
    CHECK(writes == before);

    CtxtHandle authentication = {30, 40};
    schannel_package = 0;
    encrypt(&authentication, 0, SECBUFFER_DATA);
    decrypt(&authentication);
    CHECK(writes == before); /* SSPI authentication traffic is not TLS. */
    schannel_package = 1;

    delete_status = SEC_E_INVALID_HANDLE;
    SetLastError(0x1234);
    CHECK(ScDeleteDetour(&copy) == delete_status && GetLastError() == 0x5678);
    encrypt(&copy, 0, SECBUFFER_DATA);
    CHECK(written_connection != first_id); /* Failed deletion conservatively splits a stream. */
    first_id = written_connection;
    delete_status = SEC_E_OK;
    SetLastError(0x1234);
    CHECK(ScDeleteDetour(&copy) == SEC_E_OK && GetLastError() == 0x5678);
    CHECK(copy.dwLower == 0 && copy.dwUpper == 0);
    copy = first;
    encrypt(&copy, 0, SECBUFFER_DATA);
    CHECK(written_connection != first_id); /* Reused numeric handles start a new stream. */
    first_id = written_connection;
    reuse_during_delete = 1;
    SetLastError(0x1234);
    CHECK(ScDeleteDetour(&copy) == SEC_E_OK);
    CHECK(reused_connection != first_id);
    copy = first;
    encrypt(&copy, 0, SECBUFFER_DATA);
    CHECK(written_connection == reused_connection); /* No post-delete eviction of the new owner. */
    reuse_during_delete = 0;

    unsigned char bytes[] = {1, 2, 3, 4, 5};
    SecBuffer buffers[] = {{2, SECBUFFER_DATA, bytes}, {1, SECBUFFER_TOKEN, bytes + 2},
        {2, SECBUFFER_DATA, bytes + 3}, {1, SECBUFFER_DATA | SECBUFFER_READONLY, bytes + 2}};
    SecBufferDesc message = {SECBUFFER_VERSION, 4, buffers};
    ScSnapshot snapshot;
    const unsigned char expected[] = {1, 2, 4, 5};
    ScSnapshotMessage(&message, &snapshot);
    CHECK(snapshot.original == 4 && snapshot.captured == 4 && !memcmp(snapshot.data, expected, 4));
    ScSnapshotFree(&snapshot);
    message.cBuffers = SC_BUFFER_LIMIT + 1;
    ScSnapshotMessage(&message, &snapshot);
    CHECK(snapshot.data == NULL && snapshot.captured == 0);
    message.cBuffers = 1; buffers[0].pvBuffer = NULL;
    ScSnapshotMessage(&message, &snapshot);
    CHECK(snapshot.data == NULL && snapshot.captured == 0);
    ScSnapshotMessage(NULL, &snapshot);
    CHECK(snapshot.data == NULL);

    unsigned char* large = (unsigned char*)malloc(SC_CAPTURE_LIMIT + 1);
    CHECK(large != NULL);
    if (large) {
        memset(large, 0x42, SC_CAPTURE_LIMIT + 1);
        buffers[0].cbBuffer = SC_CAPTURE_LIMIT + 1; buffers[0].pvBuffer = large;
        ScSnapshotMessage(&message, &snapshot);
        CHECK(snapshot.original == SC_CAPTURE_LIMIT + 1 && snapshot.captured == SC_CAPTURE_LIMIT);
        CHECK(snapshot.data && snapshot.data[0] == 0x42 && snapshot.data[SC_CAPTURE_LIMIT - 1] == 0x42);
        ScSnapshotFree(&snapshot);
        free(large);
    }
    CHECK(incoming_error_ok);
    printf("Schannel state tests: %d failures\n", failures);
    return failures ? 1 : 0;
}
