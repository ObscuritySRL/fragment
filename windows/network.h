#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "capture.h"

/* Winsock call activity, not packet capture or TLS decryption. Application
 * bytes are copied only with the separate socketData opt-in. Pending calls
 * are reported as pending; completion
 * through IOCP, callbacks or WSAGetOverlappedResult is deliberately not inferred.
 * A socket ID identifies one observed socket lifetime, including UDP sockets
 * which may communicate with several different peers.
 */
#define NW_SOCKET_LIMIT 16384u
#define NW_ENDPOINT_SIZE 96u
#define NW_PAYLOAD_LIMIT (1024u * 1024u)
#define NW_BUFFER_LIMIT 64u
typedef int (WSAAPI *NwConnectFn)(SOCKET, const struct sockaddr*, int);
typedef int (WSAAPI *NwWsaConnectFn)(SOCKET, const struct sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
typedef int (WSAAPI *NwSendFn)(SOCKET, const char*, int, int);
typedef int (WSAAPI *NwRecvFn)(SOCKET, char*, int, int);
typedef int (WSAAPI *NwSendToFn)(SOCKET, const char*, int, int, const struct sockaddr*, int);
typedef int (WSAAPI *NwRecvFromFn)(SOCKET, char*, int, int, struct sockaddr*, int*);
typedef int (WSAAPI *NwWsaSendFn)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *NwWsaRecvFn)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *NwWsaSendToFn)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *NwWsaRecvFromFn)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *NwCloseFn)(SOCKET);
typedef int (WSAAPI *NwNameFn)(SOCKET, struct sockaddr*, int*);
typedef int (WSAAPI *NwOptionFn)(SOCKET, int, int, char*, int*);
typedef int (WSAAPI *NwErrorFn)(void);
typedef void (WSAAPI *NwSetErrorFn)(int);

static NwConnectFn gNwConnect;
static NwWsaConnectFn gNwWsaConnect;
static NwSendFn gNwSend;
static NwRecvFn gNwRecv;
static NwSendToFn gNwSendTo;
static NwRecvFromFn gNwRecvFrom;
static NwWsaSendFn gNwWsaSend;
static NwWsaRecvFn gNwWsaRecv;
static NwWsaSendToFn gNwWsaSendTo;
static NwWsaRecvFromFn gNwWsaRecvFrom;
static NwCloseFn gNwClose;
static NwNameFn gNwLocal, gNwPeer;
static NwOptionFn gNwOption;
static NwErrorFn gNwError;
static NwSetErrorFn gNwSetError;
static HMODULE gNwModule;
static HANDLE gNwHeap;
static DWORD gNwTls = TLS_OUT_OF_INDEXES;
static CRITICAL_SECTION gNwLock;
static volatile LONG gNwActive, gNwReported, gNwEpoch = 1;
static LONG gNwMapEpoch = 1;

typedef struct NwSocket {
    SOCKET socket;
    unsigned long long id;
    struct NwSocket* next;
} NwSocket;
static NwSocket* gNwSockets;
static size_t gNwSocketCount;

typedef struct NwInfo {
    unsigned long long id;
    const char* transport;
    char local[NW_ENDPOINT_SIZE], remote[NW_ENDPOINT_SIZE];
} NwInfo;

typedef struct NwPayload {
    unsigned char* data;
    size_t captured;
    const char* omitted;
} NwPayload;

static void NwPayloadFree(NwPayload* payload) {
    if (payload->data) HeapFree(gNwHeap, 0, payload->data);
    payload->data = NULL;
    payload->captured = 0;
}

static void NwSnapshot(const void* source, size_t length, NwPayload* payload) {
    if (!length) return;
    size_t take = length < NW_PAYLOAD_LIMIT ? length : NW_PAYLOAD_LIMIT;
    payload->data = (unsigned char*)HeapAlloc(gNwHeap, 0, take);
    if (!payload->data) { payload->omitted = "socket-payload-allocation-failed"; return; }
    __try {
        memcpy(payload->data, source, take);
        payload->captured = take;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        NwPayloadFree(payload);
        payload->omitted = "unreadable-socket-buffer";
    }
}

/* On writes, copy before the provider can consume/reuse the buffers. On reads,
 * call only after synchronous success, and inspect only the returned count.
 * No completion output or WSABUF payload is read for overlapped operations. */
static void NwSnapshotVectors(LPWSABUF source, DWORD count, size_t accepted, NwPayload* payload) {
    WSABUF buffers[NW_BUFFER_LIMIT];
    __try {
        if (!count || count > NW_BUFFER_LIMIT) { payload->omitted = "socket-buffer-count-limit"; return; }
        memcpy(buffers, source, count * sizeof(*buffers));
        size_t total = 0;
        for (DWORD i = 0; i < count; ++i) {
            if (SIZE_MAX - total < buffers[i].len) { payload->omitted = "socket-buffer-size-overflow"; return; }
            total += buffers[i].len;
        }
        if (total > accepted) total = accepted;
        if (!total) return;
        if (total > NW_PAYLOAD_LIMIT) total = NW_PAYLOAD_LIMIT;
        payload->data = (unsigned char*)HeapAlloc(gNwHeap, 0, total);
        if (!payload->data) { payload->omitted = "socket-payload-allocation-failed"; return; }
        for (DWORD i = 0; i < count && payload->captured < total; ++i) {
            size_t take = buffers[i].len;
            if (take > total - payload->captured) take = total - payload->captured;
            if (take) memcpy(payload->data + payload->captured, buffers[i].buf, take);
            payload->captured += take;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        NwPayloadFree(payload);
        payload->omitted = "unreadable-socket-buffer";
    }
}

static void NwWritePayload(unsigned long long id, const char* direction, NwPayload* payload, size_t accepted) {
    if (!gCfg.socketData || !accepted) return;
    if (!id) { CaptureGap("winsock", 0, direction, "socket-identity-unavailable"); return; }
    if (payload->omitted) { CaptureGap("winsock", id, direction, payload->omitted); return; }
    size_t captured = payload->captured < accepted ? payload->captured : accepted;
    if (captured) CaptureWrite("winsock", id, direction, payload->data, captured, accepted);
    else CaptureGap("winsock", id, direction, "socket-byte-count-unavailable");
}

static void NetworkInit(void) {
    InitializeCriticalSection(&gNwLock);
    gNwHeap = HeapCreate(0, 0, 0);
    gNwTls = TlsAlloc();
}

/* No name service, address conversion exports, or loader calls are needed. */
static void NwAddress(const struct sockaddr* address, int length, char out[NW_ENDPOINT_SIZE]) {
    out[0] = 0;
    __try {
        if (!address || length < (int)sizeof(ADDRESS_FAMILY)) return;
        if (address->sa_family == AF_INET && length >= (int)sizeof(struct sockaddr_in)) {
            struct sockaddr_in value;
            memcpy(&value, address, sizeof(value));
            const unsigned char* a = (const unsigned char*)&value.sin_addr;
            const unsigned char* p = (const unsigned char*)&value.sin_port;
            _snprintf_s(out, NW_ENDPOINT_SIZE, _TRUNCATE, "%u.%u.%u.%u:%u",
                a[0], a[1], a[2], a[3], ((unsigned)p[0] << 8) | p[1]);
        } else if (address->sa_family == AF_INET6 && length >= (int)sizeof(struct sockaddr_in6)) {
            struct sockaddr_in6 value;
            memcpy(&value, address, sizeof(value));
            const unsigned char* a = (const unsigned char*)&value.sin6_addr;
            const unsigned char* p = (const unsigned char*)&value.sin6_port;
            char scope[24] = "";
            if (value.sin6_scope_id) _snprintf_s(scope, sizeof(scope), _TRUNCATE, "%%%lu", value.sin6_scope_id);
            _snprintf_s(out, NW_ENDPOINT_SIZE, _TRUNCATE,
                "[%x:%x:%x:%x:%x:%x:%x:%x%s]:%u",
                ((unsigned)a[0] << 8) | a[1], ((unsigned)a[2] << 8) | a[3],
                ((unsigned)a[4] << 8) | a[5], ((unsigned)a[6] << 8) | a[7],
                ((unsigned)a[8] << 8) | a[9], ((unsigned)a[10] << 8) | a[11],
                ((unsigned)a[12] << 8) | a[13], ((unsigned)a[14] << 8) | a[15],
                scope, ((unsigned)p[0] << 8) | p[1]);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { out[0] = 0; }
}

static void NwOutputAddress(struct sockaddr* address, int* length, char out[NW_ENDPOINT_SIZE]) {
    out[0] = 0;
    __try { if (length) NwAddress(address, *length, out); }
    __except (EXCEPTION_EXECUTE_HANDLER) { out[0] = 0; }
}

/* Only called for a completed synchronous API; never read pending outputs. */
static BOOL NwCount(LPDWORD source, DWORD* value) {
    __try { if (!source) return FALSE; *value = *source; return TRUE; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return FALSE; }
}

static void NwRefresh(void) {
    LONG epoch = InterlockedCompareExchange(&gNwEpoch, 0, 0);
    if (epoch == gNwMapEpoch) return;
    while (gNwSockets) {
        NwSocket* next = gNwSockets->next;
        HeapFree(gNwHeap, 0, gNwSockets);
        gNwSockets = next;
    }
    gNwSocketCount = 0;
    gNwMapEpoch = epoch;
}

static unsigned long long NwIdentity(SOCKET socket, BOOL valid) {
    EnterCriticalSection(&gNwLock);
    NwRefresh();
    for (NwSocket* item = gNwSockets; item; item = item->next) {
        if (item->socket == socket) {
            unsigned long long id = item->id;
            LeaveCriticalSection(&gNwLock);
            return id;
        }
    }
    LONG epoch = gNwMapEpoch;
    LeaveCriticalSection(&gNwLock);
    if (!valid || socket == INVALID_SOCKET) return 0;
    NwSocket* fresh = (NwSocket*)HeapAlloc(gNwHeap, 0, sizeof(*fresh));
    if (!fresh) { CaptureGap("winsock", 0, "out", "socket-map-allocation-failed"); return 0; }
    fresh->socket = socket;
    fresh->id = CaptureNextConnection();
    unsigned long long id = 0;
    BOOL limited = FALSE;
    EnterCriticalSection(&gNwLock);
    NwRefresh();
    if (gNwActive && epoch == gNwMapEpoch) {
        for (NwSocket* item = gNwSockets; item; item = item->next)
            if (item->socket == socket) { id = item->id; break; }
        if (!id && gNwSocketCount < NW_SOCKET_LIMIT) {
            fresh->next = gNwSockets;
            gNwSockets = fresh;
            ++gNwSocketCount;
            id = fresh->id;
            fresh = NULL;
        } else if (!id) limited = TRUE;
    }
    LeaveCriticalSection(&gNwLock);
    if (fresh) HeapFree(gNwHeap, 0, fresh);
    if (limited) CaptureGap("winsock", 0, "out", "socket-tracking-limit");
    return id;
}

static void NwForget(SOCKET socket) {
    EnterCriticalSection(&gNwLock);
    NwRefresh();
    NwSocket** link = &gNwSockets;
    while (*link) {
        NwSocket* entry = *link;
        if (entry->socket == socket) {
            *link = entry->next;
            --gNwSocketCount;
            HeapFree(gNwHeap, 0, entry);
            break;
        }
        link = &entry->next;
    }
    LeaveCriticalSection(&gNwLock);
}

static void NwDescribe(SOCKET socket, NwInfo* info) {
    memset(info, 0, sizeof(*info));
    info->transport = "unknown";
    WSAPROTOCOL_INFOW protocol;
    int length = sizeof(protocol);
    BOOL valid = gNwOption(socket, SOL_SOCKET, SO_PROTOCOL_INFOW, (char*)&protocol, &length) == 0;
    if (valid && protocol.iProtocol == IPPROTO_TCP) info->transport = "tcp";
    if (valid && protocol.iProtocol == IPPROTO_UDP) info->transport = "udp";
    struct sockaddr_storage address;
    length = sizeof(address);
    if (gNwLocal(socket, (struct sockaddr*)&address, &length) == 0)
        NwAddress((struct sockaddr*)&address, length, info->local);
    length = sizeof(address);
    if (gNwPeer(socket, (struct sockaddr*)&address, &length) == 0)
        NwAddress((struct sockaddr*)&address, length, info->remote);
    info->id = NwIdentity(socket, valid);
}

static BOOL NwEnter(void) {
    if (!gNwActive || !CaptureAvailable() || TlsGetValue(gNwTls)) return FALSE;
    if (!TlsSetValue(gNwTls, (void*)1)) return FALSE;
    if (InterlockedCompareExchange(&gNwReported, 1, 0) == 0) CaptureBackend("winsock", TRUE);
    return TRUE;
}

static void NwRestore(DWORD win, int net) { gNwSetError(net); SetLastError(win); }
static const char* NwStatus(int result, int error, BOOL connectCall) {
    if (result != SOCKET_ERROR) return "completed";
    if (error == WSA_IO_PENDING || (connectCall && error == WSAEWOULDBLOCK)) return "pending";
    if (error == WSAEWOULDBLOCK) return "would-block";
    return "failed";
}

/* Peek bytes are not consumed; urgent bytes are a separate channel. Keep their
 * call counts visible without appending either to the ordinary raw stream. */
static const char* NwEvent(const char* base, DWORD flags) {
    if (!(flags & (MSG_PEEK | MSG_OOB))) return base;
#define NW_FLAGGED(api) if (!strcmp(base, #api)) return flags & MSG_PEEK \
    ? (flags & MSG_OOB ? #api "(MSG_PEEK|MSG_OOB)" : #api "(MSG_PEEK)") : #api "(MSG_OOB)"
    NW_FLAGGED(send); NW_FLAGGED(recv); NW_FLAGGED(sendto); NW_FLAGGED(recvfrom);
    NW_FLAGGED(WSASend); NW_FLAGGED(WSARecv); NW_FLAGGED(WSASendTo); NW_FLAGGED(WSARecvFrom);
#undef NW_FLAGGED
    return base;
}

static unsigned long long NwReport(SOCKET socket, const char* event, const char* remote,
                     size_t bytes, const char* status, int error) {
    NwInfo info;
    NwDescribe(socket, &info);
    CaptureNetwork(info.id, event, info.transport, info.local,
                   remote && *remote ? remote : info.remote, bytes, status, error);
    return info.id;
}

#define NW_BEGIN() \
    DWORD nwBeforeWin = GetLastError(); int nwBeforeNet = gNwError(); \
    BOOL nwObserving = NwEnter(); NwPayload nwPayload = {0}; NwRestore(nwBeforeWin, nwBeforeNet)
#define NW_AFTER() DWORD nwAfterWin = GetLastError(); int nwAfterNet = gNwError()
#define NW_RETURN(value) do { \
    NwPayloadFree(&nwPayload); \
    if (nwObserving) TlsSetValue(gNwTls, NULL); \
    NwRestore(nwAfterWin, nwAfterNet); return (value); \
} while (0)

static int WSAAPI NwConnectDetour(SOCKET socket, const struct sockaddr* address, int length) {
    NW_BEGIN();
    char remote[NW_ENDPOINT_SIZE] = "";
    if (nwObserving) NwAddress(address, length, remote);
    NwRestore(nwBeforeWin, nwBeforeNet);
    int result = gNwConnect(socket, address, length);
    NW_AFTER();
    if (nwObserving) NwReport(socket, "connect", remote, 0, NwStatus(result, nwAfterNet, TRUE), result == SOCKET_ERROR ? nwAfterNet : 0);
    NW_RETURN(result);
}

static int WSAAPI NwWsaConnectDetour(SOCKET socket, const struct sockaddr* address, int length,
                                     LPWSABUF caller, LPWSABUF callee, LPQOS sendQos, LPQOS recvQos) {
    NW_BEGIN();
    char remote[NW_ENDPOINT_SIZE] = "";
    if (nwObserving) NwAddress(address, length, remote);
    NwRestore(nwBeforeWin, nwBeforeNet);
    int result = gNwWsaConnect(socket, address, length, caller, callee, sendQos, recvQos);
    NW_AFTER();
    if (nwObserving) NwReport(socket, "WSAConnect", remote, 0, NwStatus(result, nwAfterNet, TRUE), result == SOCKET_ERROR ? nwAfterNet : 0);
    NW_RETURN(result);
}

static int WSAAPI NwSendDetour(SOCKET socket, const char* data, int length, int flags) {
    NW_BEGIN();
    if (nwObserving && gCfg.socketData && length > 0 && !(flags & MSG_OOB)) NwSnapshot(data, (size_t)length, &nwPayload);
    NwRestore(nwBeforeWin, nwBeforeNet);
    int result = gNwSend(socket, data, length, flags);
    NW_AFTER();
    if (nwObserving) {
        unsigned long long id = NwReport(socket, NwEvent("send", flags), NULL, result > 0 ? (size_t)result : 0, NwStatus(result, nwAfterNet, FALSE), result == SOCKET_ERROR ? nwAfterNet : 0);
        if (result > 0 && !(flags & MSG_OOB)) NwWritePayload(id, "out", &nwPayload, (size_t)result);
    }
    NW_RETURN(result);
}
static int WSAAPI NwRecvDetour(SOCKET socket, char* data, int length, int flags) {
    NW_BEGIN();
    int result = gNwRecv(socket, data, length, flags);
    NW_AFTER();
    if (nwObserving) {
        unsigned long long id = NwReport(socket, NwEvent("recv", flags), NULL, result > 0 ? (size_t)result : 0, NwStatus(result, nwAfterNet, FALSE), result == SOCKET_ERROR ? nwAfterNet : 0);
        /* Peeking does not consume bytes: a later read should record them once. */
        if (gCfg.socketData && result > 0 && !(flags & (MSG_PEEK | MSG_OOB))) { NwSnapshot(data, (size_t)result, &nwPayload); NwWritePayload(id, "in", &nwPayload, (size_t)result); }
    }
    NW_RETURN(result);
}
static int WSAAPI NwSendToDetour(SOCKET socket, const char* data, int length, int flags,
                                 const struct sockaddr* address, int addressLength) {
    NW_BEGIN();
    char remote[NW_ENDPOINT_SIZE] = "";
    if (nwObserving) NwAddress(address, addressLength, remote);
    if (nwObserving && gCfg.socketData && length > 0 && !(flags & MSG_OOB)) NwSnapshot(data, (size_t)length, &nwPayload);
    NwRestore(nwBeforeWin, nwBeforeNet);
    int result = gNwSendTo(socket, data, length, flags, address, addressLength);
    NW_AFTER();
    if (nwObserving) {
        unsigned long long id = NwReport(socket, NwEvent("sendto", flags), remote, result > 0 ? (size_t)result : 0, NwStatus(result, nwAfterNet, FALSE), result == SOCKET_ERROR ? nwAfterNet : 0);
        if (result > 0 && !(flags & MSG_OOB)) NwWritePayload(id, "out", &nwPayload, (size_t)result);
    }
    NW_RETURN(result);
}
static int WSAAPI NwRecvFromDetour(SOCKET socket, char* data, int length, int flags,
                                   struct sockaddr* address, int* addressLength) {
    NW_BEGIN();
    int result = gNwRecvFrom(socket, data, length, flags, address, addressLength);
    NW_AFTER();
    if (nwObserving) {
        char remote[NW_ENDPOINT_SIZE] = "";
        if (result != SOCKET_ERROR) NwOutputAddress(address, addressLength, remote);
        unsigned long long id = NwReport(socket, NwEvent("recvfrom", flags), remote, result > 0 ? (size_t)result : 0, NwStatus(result, nwAfterNet, FALSE), result == SOCKET_ERROR ? nwAfterNet : 0);
        if (gCfg.socketData && result > 0 && !(flags & (MSG_PEEK | MSG_OOB))) { NwSnapshot(data, (size_t)result, &nwPayload); NwWritePayload(id, "in", &nwPayload, (size_t)result); }
    }
    NW_RETURN(result);
}

static unsigned long long NwReportWsa(SOCKET socket, const char* event, const char* remote, int result,
                        int error, LPDWORD transferred, BOOL asynchronous, DWORD* count) {
    DWORD bytes = 0;
    const char* status = NwStatus(result, error, FALSE);
    if (result == 0 && (asynchronous || !NwCount(transferred, &bytes))) status = "completed-unmeasured";
    *count = bytes;
    unsigned long long id = NwReport(socket, event, remote, bytes, status, result == SOCKET_ERROR ? error : 0);
    if (gCfg.socketData && asynchronous && !strstr(event, "MSG_") && (result == 0 || error == WSA_IO_PENDING))
        CaptureGap("winsock", id, !strncmp(event, "WSARecv", 7) ? "in" : "out", "asynchronous-socket-payload-not-observed");
    return id;
}
static int WSAAPI NwWsaSendDetour(SOCKET socket, LPWSABUF buffers, DWORD count, LPDWORD transferred,
                                  DWORD flags, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    NW_BEGIN();
    if (nwObserving && gCfg.socketData && !overlapped && !completion && !(flags & MSG_OOB)) NwSnapshotVectors(buffers, count, SIZE_MAX, &nwPayload);
    NwRestore(nwBeforeWin, nwBeforeNet);
    int result = gNwWsaSend(socket, buffers, count, transferred, flags, overlapped, completion);
    NW_AFTER();
    if (nwObserving) {
        DWORD accepted;
        unsigned long long id = NwReportWsa(socket, NwEvent("WSASend", flags), NULL, result, nwAfterNet, transferred, overlapped || completion, &accepted);
        if (!(flags & MSG_OOB)) NwWritePayload(id, "out", &nwPayload, accepted);
    }
    NW_RETURN(result);
}
static int WSAAPI NwWsaRecvDetour(SOCKET socket, LPWSABUF buffers, DWORD count, LPDWORD transferred,
                                  LPDWORD flags, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    NW_BEGIN();
    DWORD inputFlags = 0;
    if (nwObserving) NwCount(flags, &inputFlags);
    NwRestore(nwBeforeWin, nwBeforeNet);
    int result = gNwWsaRecv(socket, buffers, count, transferred, flags, overlapped, completion);
    NW_AFTER();
    if (nwObserving) {
        DWORD accepted;
        unsigned long long id = NwReportWsa(socket, NwEvent("WSARecv", inputFlags), NULL, result, nwAfterNet, transferred, overlapped || completion, &accepted);
        if (gCfg.socketData && accepted && !(inputFlags & (MSG_PEEK | MSG_OOB))) { NwSnapshotVectors(buffers, count, accepted, &nwPayload); NwWritePayload(id, "in", &nwPayload, accepted); }
    }
    NW_RETURN(result);
}
static int WSAAPI NwWsaSendToDetour(SOCKET socket, LPWSABUF buffers, DWORD count, LPDWORD transferred,
                                    DWORD flags, const struct sockaddr* address, int addressLength,
                                    LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    NW_BEGIN();
    char remote[NW_ENDPOINT_SIZE] = "";
    if (nwObserving) NwAddress(address, addressLength, remote);
    if (nwObserving && gCfg.socketData && !overlapped && !completion && !(flags & MSG_OOB)) NwSnapshotVectors(buffers, count, SIZE_MAX, &nwPayload);
    NwRestore(nwBeforeWin, nwBeforeNet);
    int result = gNwWsaSendTo(socket, buffers, count, transferred, flags, address, addressLength, overlapped, completion);
    NW_AFTER();
    if (nwObserving) {
        DWORD accepted;
        unsigned long long id = NwReportWsa(socket, NwEvent("WSASendTo", flags), remote, result, nwAfterNet, transferred, overlapped || completion, &accepted);
        if (!(flags & MSG_OOB)) NwWritePayload(id, "out", &nwPayload, accepted);
    }
    NW_RETURN(result);
}
static int WSAAPI NwWsaRecvFromDetour(SOCKET socket, LPWSABUF buffers, DWORD count, LPDWORD transferred,
                                      LPDWORD flags, struct sockaddr* address, LPINT addressLength,
                                      LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    NW_BEGIN();
    DWORD inputFlags = 0;
    if (nwObserving) NwCount(flags, &inputFlags);
    NwRestore(nwBeforeWin, nwBeforeNet);
    int result = gNwWsaRecvFrom(socket, buffers, count, transferred, flags, address, addressLength, overlapped, completion);
    NW_AFTER();
    if (nwObserving) {
        char remote[NW_ENDPOINT_SIZE] = "";
        if (result == 0 && !overlapped && !completion) NwOutputAddress(address, addressLength, remote);
        DWORD accepted;
        unsigned long long id = NwReportWsa(socket, NwEvent("WSARecvFrom", inputFlags), remote, result, nwAfterNet, transferred, overlapped || completion, &accepted);
        if (gCfg.socketData && accepted && !(inputFlags & (MSG_PEEK | MSG_OOB))) { NwSnapshotVectors(buffers, count, accepted, &nwPayload); NwWritePayload(id, "in", &nwPayload, accepted); }
    }
    NW_RETURN(result);
}
static int WSAAPI NwCloseDetour(SOCKET socket) {
    NW_BEGIN();
    NwInfo info;
    if (nwObserving) {
        NwDescribe(socket, &info);
        /* The provider can recycle a socket value before closesocket returns.
         * Retire first, accepting an explicit identity split on close failure. */
        NwForget(socket);
    }
    NwRestore(nwBeforeWin, nwBeforeNet);
    int result = gNwClose(socket);
    NW_AFTER();
    if (nwObserving) {
        CaptureNetwork(info.id, "closesocket", info.transport, info.local, info.remote,
                       0, NwStatus(result, nwAfterNet, FALSE), result == SOCKET_ERROR ? nwAfterNet : 0);
        if (result == SOCKET_ERROR && info.id)
            CaptureGap("winsock", info.id, "out", "socket-close-failed-identity-reset");
    }
    NW_RETURN(result);
}
#undef NW_BEGIN
#undef NW_AFTER
#undef NW_RETURN

/* Loader notifications publish only state; never take a runtime map/capture
 * lock or call a Winsock provider while its image is loading or unloading. */
static void NetworkModuleUnloaded(HMODULE module) {
    if (module != gNwModule) return;
    InterlockedExchange(&gNwActive, 0);
    InterlockedExchange(&gNwReported, 0);
    InterlockedIncrement(&gNwEpoch);
    gNwModule = NULL;
    gNwConnect = NULL; gNwWsaConnect = NULL; gNwSend = NULL; gNwRecv = NULL;
    gNwSendTo = NULL; gNwRecvFrom = NULL; gNwWsaSend = NULL; gNwWsaRecv = NULL;
    gNwWsaSendTo = NULL; gNwWsaRecvFrom = NULL; gNwClose = NULL;
    gNwLocal = NULL; gNwPeer = NULL; gNwOption = NULL; gNwError = NULL; gNwSetError = NULL;
}
static void NwInstall(HMODULE module, const char* name, LPVOID detour, LPVOID* original) {
    if (*original) return;
    LPVOID target = (LPVOID)GetProcAddress(module, name);
    if (target && !FrIsHooked(target) && CreateAndEnableHook(name, target, detour, original))
        LogInfo("[hook] %s @ 0x%p\n", name, target);
}
static void HookNetwork(HMODULE module) {
    if (!module || !gCfg.observe || !gNwHeap || gNwTls == TLS_OUT_OF_INDEXES) return;
    char path[MAX_PATH] = {0};
    GetModuleFileNameA(module, path, MAX_PATH);
    const char* name = path;
    for (const char* p = path; *p; ++p) if (*p == '\\' || *p == '/') name = p + 1;
    if (_stricmp(name, "ws2_32.dll")) return;
    if (gHookLockReady) EnterCriticalSection(&gHookLock);
    if ((!gNwModule || gNwModule == module) && !gNwActive) {
        gNwModule = module;
        gNwLocal = (NwNameFn)(void*)GetProcAddress(module, "getsockname");
        gNwPeer = (NwNameFn)(void*)GetProcAddress(module, "getpeername");
        gNwOption = (NwOptionFn)(void*)GetProcAddress(module, "getsockopt");
        gNwError = (NwErrorFn)(void*)GetProcAddress(module, "WSAGetLastError");
        gNwSetError = (NwSetErrorFn)(void*)GetProcAddress(module, "WSASetLastError");
        if (gNwLocal && gNwPeer && gNwOption && gNwError && gNwSetError) {
            NwInstall(module, "connect", (LPVOID)&NwConnectDetour, (LPVOID*)&gNwConnect);
            NwInstall(module, "WSAConnect", (LPVOID)&NwWsaConnectDetour, (LPVOID*)&gNwWsaConnect);
            NwInstall(module, "send", (LPVOID)&NwSendDetour, (LPVOID*)&gNwSend);
            NwInstall(module, "recv", (LPVOID)&NwRecvDetour, (LPVOID*)&gNwRecv);
            NwInstall(module, "sendto", (LPVOID)&NwSendToDetour, (LPVOID*)&gNwSendTo);
            NwInstall(module, "recvfrom", (LPVOID)&NwRecvFromDetour, (LPVOID*)&gNwRecvFrom);
            NwInstall(module, "WSASend", (LPVOID)&NwWsaSendDetour, (LPVOID*)&gNwWsaSend);
            NwInstall(module, "WSARecv", (LPVOID)&NwWsaRecvDetour, (LPVOID*)&gNwWsaRecv);
            NwInstall(module, "WSASendTo", (LPVOID)&NwWsaSendToDetour, (LPVOID*)&gNwWsaSendTo);
            NwInstall(module, "WSARecvFrom", (LPVOID)&NwWsaRecvFromDetour, (LPVOID*)&gNwWsaRecvFrom);
            NwInstall(module, "closesocket", (LPVOID)&NwCloseDetour, (LPVOID*)&gNwClose);
        }
        BOOL ready = gNwConnect && gNwWsaConnect && gNwSend && gNwRecv && gNwSendTo && gNwRecvFrom &&
                     gNwWsaSend && gNwWsaRecv && gNwWsaSendTo && gNwWsaRecvFrom && gNwClose;
        if (ready) {
            InterlockedExchange(&gNwActive, 1);
            LogInfo("[winsock] backend ready (call activity only; asynchronous completions not tracked)\n");
        } else LogWarn("[winsock] backend inactive: incomplete hook installation\n");
    }
    if (gHookLockReady) LeaveCriticalSection(&gHookLock);
}
