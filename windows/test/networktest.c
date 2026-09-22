/* Deterministic Winsock observer semantics; no sockets or installed hooks. */
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "../capture.h"

static int failures, calls, writes, gaps, events, available = 1;
static unsigned long long next_id, payload_id, reused_id;
static unsigned char payload_bytes[128];
static size_t payload_size, payload_original;
static unsigned long long event_bytes;
static const char* event_status;
static const char* event_name;
static int event_error;
static BOOL testAvailable(void) { return available; }
static unsigned long long testNext(void) { return ++next_id; }
static void testBackend(const char* backend, BOOL ready) { (void)backend; (void)ready; }
static void testGap(const char* backend, unsigned long long id, const char* direction, const char* reason) {
    ++gaps; SetLastError(0xeeee);
}
static void testWrite(const char* backend, unsigned long long id, const char* direction,
                      const void* data, size_t captured, size_t original) {
    ++writes; payload_id = id; payload_size = captured; payload_original = original;
    if (captured <= sizeof(payload_bytes)) memcpy(payload_bytes, data, captured);
    SetLastError(0xeeee);
}
static void testNetwork(unsigned long long id, const char* event, const char* transport,
                        const char* local, const char* remote, unsigned long long bytes,
                        const char* status, int error) {
    ++events; event_name = event; event_bytes = bytes; event_status = status; event_error = error;
    SetLastError(0xeeee);
}
#define CaptureAvailable testAvailable
#define CaptureNextConnection testNext
#define CaptureBackend testBackend
#define CaptureGap testGap
#define CaptureWrite testWrite
#define CaptureNetwork testNetwork
#include "../main.c"
#undef CaptureAvailable
#undef CaptureNextConnection
#undef CaptureBackend
#undef CaptureGap
#undef CaptureWrite
#undef CaptureNetwork

#define CHECK(value) do { if (!(value)) { printf("FAIL line %d: %s\n", __LINE__, #value); ++failures; } } while (0)
static int result_count = 3, result_error = 0x5678, reuse_close;
static int WSAAPI errorMock(void) { return (int)GetLastError(); }
static void WSAAPI setErrorMock(int error) { SetLastError((DWORD)error); }
static int WSAAPI optionMock(SOCKET socket, int level, int option, char* value, int* length) {
    WSAPROTOCOL_INFOW info = {0}; info.iProtocol = IPPROTO_TCP;
    memcpy(value, &info, sizeof(info)); *length = sizeof(info);
    SetLastError(0xbbbb); return 0;
}
static int WSAAPI nameMock(SOCKET socket, struct sockaddr* output, int* length) {
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    unsigned char* ip = (unsigned char*)&address.sin_addr;
    ip[0] = 127; ip[3] = 1;
    ((unsigned char*)&address.sin_port)[0] = 0x23;
    ((unsigned char*)&address.sin_port)[1] = 0x45;
    memcpy(output, &address, sizeof(address)); *length = sizeof(address);
    SetLastError(0xcccc); return 0;
}
static int WSAAPI sendMock(SOCKET socket, const char* bytes, int length, int flags) {
    ++calls; CHECK(GetLastError() == 0x1234);
    if (result_count > 0) memset((char*)bytes, 0xee, length);
    SetLastError(result_error); return result_count;
}
static int WSAAPI recvMock(SOCKET socket, char* bytes, int length, int flags) {
    ++calls; CHECK(GetLastError() == 0x1234);
    if (result_count > 0) memcpy(bytes, "abc", result_count);
    SetLastError(result_error); return result_count;
}
static int WSAAPI wsaSendMock(SOCKET socket, LPWSABUF buffers, DWORD count, LPDWORD transferred,
                              DWORD flags, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    ++calls; CHECK(GetLastError() == 0x1234);
    if (result_count >= 0 && !overlapped) {
        *transferred = (DWORD)result_count;
        for (DWORD i = 0; i < count; ++i) memset(buffers[i].buf, 0xee, buffers[i].len);
    }
    SetLastError(result_error); return result_count < 0 ? SOCKET_ERROR : 0;
}
static int WSAAPI wsaRecvMock(SOCKET socket, LPWSABUF buffers, DWORD count, LPDWORD transferred,
                              LPDWORD flags, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    ++calls; CHECK(GetLastError() == 0x1234);
    if (result_count > 0 && !overlapped) {
        *transferred = (DWORD)result_count;
        memcpy(buffers[0].buf, "ab", 2); memcpy(buffers[1].buf, "c", 1);
        *flags = 0; /* Providers replace input flags with completion flags. */
    }
    SetLastError(result_error); return result_count < 0 ? SOCKET_ERROR : 0;
}
static int WSAAPI closeMock(SOCKET socket) {
    ++calls; CHECK(GetLastError() == 0x1234);
    if (reuse_close) reused_id = NwIdentity(socket, TRUE);
    SetLastError(result_error); return result_count < 0 ? SOCKET_ERROR : 0;
}

int main(void) {
    NetworkInit();
    gNwError = errorMock; gNwSetError = setErrorMock; gNwOption = optionMock;
    gNwLocal = nameMock; gNwPeer = nameMock; gNwSend = sendMock; gNwRecv = recvMock;
    gNwWsaSend = wsaSendMock; gNwWsaRecv = wsaRecvMock; gNwClose = closeMock;
    gNwActive = 1; gCfg.socketData = TRUE;
    char bytes[8] = "abcdefg";
    SetLastError(0x1234);
    CHECK(NwSendDetour(5, bytes, 7, 0) == 3 && GetLastError() == 0x5678);
    CHECK(writes == 1 && payload_size == 3 && payload_original == 3 && !memcmp(payload_bytes, "abc", 3));
    CHECK(bytes[0] == (char)0xee && event_bytes == 3 && !strcmp(event_status, "completed"));
    unsigned long long first = payload_id;
    SetLastError(0x1234);
    CHECK(NwRecvDetour(5, bytes, 8, 0) == 3 && GetLastError() == 0x5678);
    CHECK(writes == 2 && payload_id == first && !memcmp(payload_bytes, "abc", 3));

    char left[2] = {'a','b'}, right[2] = {'c','d'};
    WSABUF vectors[2] = {{2, left}, {2, right}};
    DWORD transferred = 0, flags = 0;
    SetLastError(0x1234);
    CHECK(NwWsaSendDetour(5, vectors, 2, &transferred, 0, NULL, NULL) == 0 && GetLastError() == 0x5678);
    CHECK(writes == 3 && transferred == 3 && payload_size == 3 && !memcmp(payload_bytes, "abc", 3));
    SetLastError(0x1234);
    CHECK(NwWsaRecvDetour(5, vectors, 2, &transferred, &flags, NULL, NULL) == 0 && GetLastError() == 0x5678);
    CHECK(writes == 4 && payload_size == 3 && !memcmp(payload_bytes, "abc", 3));

    int peekWrites = writes;
    SetLastError(0x1234);
    NwRecvDetour(5, bytes, 8, MSG_PEEK);
    CHECK(writes == peekWrites && !strcmp(event_name, "recv(MSG_PEEK)"));
    SetLastError(0x1234);
    NwRecvDetour(5, bytes, 8, 0);
    CHECK(writes == peekWrites + 1 && !memcmp(payload_bytes, "abc", 3));
    flags = MSG_PEEK;
    SetLastError(0x1234);
    NwWsaRecvDetour(5, vectors, 2, &transferred, &flags, NULL, NULL);
    CHECK(writes == peekWrites + 1 && !strcmp(event_name, "WSARecv(MSG_PEEK)"));
    flags = 0;
    SetLastError(0x1234);
    NwWsaRecvDetour(5, vectors, 2, &transferred, &flags, NULL, NULL);
    CHECK(writes == peekWrites + 2 && !memcmp(payload_bytes, "abc", 3));
    int specialWrites = writes;
    SetLastError(0x1234); NwSendDetour(5, bytes, 7, MSG_OOB);
    CHECK(writes == specialWrites && !strcmp(event_name, "send(MSG_OOB)"));
    SetLastError(0x1234); NwRecvDetour(5, bytes, 8, MSG_OOB);
    CHECK(writes == specialWrites && !strcmp(event_name, "recv(MSG_OOB)"));
    SetLastError(0x1234); NwWsaSendDetour(5, vectors, 2, &transferred, MSG_OOB, NULL, NULL);
    CHECK(writes == specialWrites && !strcmp(event_name, "WSASend(MSG_OOB)"));
    flags = MSG_OOB;
    SetLastError(0x1234); NwWsaRecvDetour(5, vectors, 2, &transferred, &flags, NULL, NULL);
    CHECK(writes == specialWrites && !strcmp(event_name, "WSARecv(MSG_OOB)"));
    flags = 0;

    int before = writes;
    result_count = SOCKET_ERROR; result_error = WSA_IO_PENDING;
    SetLastError(0x1234);
    CHECK(NwWsaRecvDetour(5, (LPWSABUF)1, 1, (LPDWORD)1, (LPDWORD)1, (LPWSAOVERLAPPED)1, NULL) == SOCKET_ERROR);
    CHECK(GetLastError() == WSA_IO_PENDING && writes == before && event_bytes == 0 && !strcmp(event_status, "pending"));
    CHECK(gaps > 0);
    result_count = 0; result_error = 0x5678;
    SetLastError(0x1234);
    CHECK(NwWsaSendDetour(5, (LPWSABUF)1, 1, (LPDWORD)1, 0, (LPWSAOVERLAPPED)1, NULL) == 0);
    CHECK(GetLastError() == 0x5678 && writes == before && event_bytes == 0 && !strcmp(event_status, "completed-unmeasured"));

    result_count = SOCKET_ERROR; result_error = WSAEWOULDBLOCK;
    SetLastError(0x1234);
    CHECK(NwRecvDetour(5, (char*)1, 20, 0) == SOCKET_ERROR && GetLastError() == WSAEWOULDBLOCK);
    CHECK(writes == before && !strcmp(event_status, "would-block") && event_error == WSAEWOULDBLOCK);
    result_count = 3; result_error = 0x5678;
    gCfg.socketData = FALSE;
    SetLastError(0x1234); NwSendDetour(5, bytes, 7, 0);
    CHECK(writes == before);
    gCfg.socketData = TRUE;

    NwPayload snapshot = {0};
    NwSnapshot((void*)1, 4, &snapshot);
    CHECK(snapshot.omitted && !snapshot.data);
    snapshot = (NwPayload){0};
    NwSnapshotVectors((LPWSABUF)1, NW_BUFFER_LIMIT + 1, SIZE_MAX, &snapshot);
    CHECK(snapshot.omitted && !snapshot.data);
    unsigned char* large = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, NW_PAYLOAD_LIMIT + 4);
    CHECK(large != NULL);
    if (large) {
        snapshot = (NwPayload){0}; NwSnapshot(large, NW_PAYLOAD_LIMIT + 4, &snapshot);
        CHECK(snapshot.captured == NW_PAYLOAD_LIMIT); NwPayloadFree(&snapshot);
        HeapFree(GetProcessHeap(), 0, large);
    }
    result_count = 0; reuse_close = 1;
    SetLastError(0x1234); CHECK(NwCloseDetour(5) == 0 && GetLastError() == 0x5678);
    CHECK(reused_id && reused_id != first && NwIdentity(5, TRUE) == reused_id);
    size_t count = gNwSocketCount;
    gNwSocketCount = NW_SOCKET_LIMIT;
    CHECK(NwIdentity(99, TRUE) == 0);
    gNwSocketCount = count;

    printf("%d failures; %d original calls, %d activity events, %d payload records, %d explicit gaps\n",
           failures, calls, events, writes, gaps);
    return failures ? 1 : 0;
}
