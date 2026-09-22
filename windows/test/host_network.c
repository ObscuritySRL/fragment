/* Local raw TCP/UDP fixture: no HTTP or TLS library. */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#pragma comment(lib, "ws2_32.lib")

static const char payload[] = {'f','r','a','g',0,(char)255,(char)128,'\r','\n'};
static const char reply[] = {'o','k',0,(char)254,(char)129,'\r','\n','!'};

static int address(int family, int port, struct sockaddr_storage* target) {
    memset(target, 0, sizeof(*target));
    if (family == AF_INET6) {
        struct sockaddr_in6* six = (struct sockaddr_in6*)target;
        six->sin6_family = AF_INET6;
        six->sin6_addr.u.Byte[15] = 1;
        six->sin6_port = htons((u_short)port);
        return sizeof(*six);
    }
    struct sockaddr_in* four = (struct sockaddr_in*)target;
    four->sin_family = AF_INET;
    four->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    four->sin_port = htons((u_short)port);
    return sizeof(*four);
}

static int await_transfer(SOCKET socket, WSAOVERLAPPED* overlapped, DWORD expected) {
    DWORD amount = 0, flags = 0;
    if (WSAWaitForMultipleEvents(1, &overlapped->hEvent, TRUE, 5000, FALSE) != WSA_WAIT_EVENT_0) return 0;
    return WSAGetOverlappedResult(socket, overlapped, &amount, FALSE, &flags) && amount == expected;
}

static int tcp(int family, int port, int wsa, int pending, int asyncSend) {
    SOCKET socketValue = WSASocketW(family, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    struct sockaddr_storage remote;
    int length = address(family, port, &remote), good = 0;
    char result[sizeof(reply)] = {0};
    DWORD timeout = 5000;
    WSAOVERLAPPED readOperation = {0}, writeOperation = {0};
    if (socketValue == INVALID_SOCKET) return 0;
    setsockopt(socketValue, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(socketValue, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
    int connected = wsa
        ? WSAConnect(socketValue, (struct sockaddr*)&remote, length, NULL, NULL, NULL, NULL)
        : connect(socketValue, (struct sockaddr*)&remote, length);
    if (connected) goto done;
    if (pending) {
        WSABUF buffer = {sizeof(result), result};
        DWORD flags = 0;
        readOperation.hEvent = WSACreateEvent();
        if (readOperation.hEvent == WSA_INVALID_EVENT) goto done;
        int rc = WSARecv(socketValue, &buffer, 1, NULL, &flags, &readOperation, NULL);
        if (rc != SOCKET_ERROR || WSAGetLastError() != WSA_IO_PENDING) goto done;
    }
    if (wsa) {
        WSABUF buffers[2] = {{4, (char*)payload}, {sizeof(payload) - 4, (char*)payload + 4}};
        DWORD sent = 0;
        if (asyncSend) {
            writeOperation.hEvent = WSACreateEvent();
            if (writeOperation.hEvent == WSA_INVALID_EVENT) goto done;
            int rc = WSASend(socketValue, buffers, 2, NULL, 0, &writeOperation, NULL);
            if (rc != 0 && (rc != SOCKET_ERROR || WSAGetLastError() != WSA_IO_PENDING)) goto done;
            if (!await_transfer(socketValue, &writeOperation, sizeof(payload))) goto done;
        } else if (WSASend(socketValue, buffers, 2, &sent, 0, NULL, NULL) || sent != sizeof(payload)) goto done;
    } else {
        int sent = 0;
        while (sent < sizeof(payload)) {
            int n = send(socketValue, payload + sent, (int)sizeof(payload) - sent, 0);
            if (n <= 0) goto done;
            sent += n;
        }
    }
    if (pending) {
        if (!await_transfer(socketValue, &readOperation, sizeof(reply))) goto done;
    } else {
        unsigned received = 0;
        while (received < sizeof(result)) {
            if (wsa) {
                WSABUF buffer = {sizeof(result) - received, result + received};
                DWORD amount = 0, flags = 0;
                if (WSARecv(socketValue, &buffer, 1, &amount, &flags, NULL, NULL) || !amount) goto done;
                received += amount;
            } else {
                int amount = recv(socketValue, result + received, (int)sizeof(result) - received, 0);
                if (amount <= 0) goto done;
                received += amount;
            }
        }
    }
    good = !memcmp(result, reply, sizeof(reply));
done:
    closesocket(socketValue);
    if (readOperation.hEvent) WSACloseEvent(readOperation.hEvent);
    if (writeOperation.hEvent) WSACloseEvent(writeOperation.hEvent);
    return good;
}

static int udp(int family, int port, int wsa, int pending, int asyncSend) {
    SOCKET socketValue = WSASocketW(family, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
    struct sockaddr_storage remote, local, source;
    int length = address(family, port, &remote), sourceLength = sizeof(source), good = 0;
    int localLength = address(family, 0, &local);
    char result[sizeof(reply)] = {0};
    DWORD timeout = 5000;
    WSAOVERLAPPED readOperation = {0}, writeOperation = {0};
    if (socketValue == INVALID_SOCKET) return 0;
    setsockopt(socketValue, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    if (bind(socketValue, (struct sockaddr*)&local, localLength)) goto done;
    if (pending) {
        WSABUF buffer = {sizeof(result), result};
        DWORD flags = 0;
        readOperation.hEvent = WSACreateEvent();
        if (readOperation.hEvent == WSA_INVALID_EVENT) goto done;
        int rc = WSARecvFrom(socketValue, &buffer, 1, NULL, &flags, (struct sockaddr*)&source,
                             &sourceLength, &readOperation, NULL);
        if (rc != SOCKET_ERROR || WSAGetLastError() != WSA_IO_PENDING) goto done;
    }
    if (wsa) {
        WSABUF buffer = {sizeof(payload), (char*)payload};
        DWORD sent = 0;
        if (asyncSend) {
            writeOperation.hEvent = WSACreateEvent();
            if (writeOperation.hEvent == WSA_INVALID_EVENT) goto done;
            int rc = WSASendTo(socketValue, &buffer, 1, NULL, 0, (struct sockaddr*)&remote, length, &writeOperation, NULL);
            if (rc != 0 && (rc != SOCKET_ERROR || WSAGetLastError() != WSA_IO_PENDING)) goto done;
            if (!await_transfer(socketValue, &writeOperation, sizeof(payload))) goto done;
        } else if (WSASendTo(socketValue, &buffer, 1, &sent, 0, (struct sockaddr*)&remote,
                             length, NULL, NULL) || sent != sizeof(payload)) goto done;
    } else if (sendto(socketValue, payload, sizeof(payload), 0, (struct sockaddr*)&remote, length) != sizeof(payload)) goto done;
    if (pending) {
        if (!await_transfer(socketValue, &readOperation, sizeof(reply))) goto done;
    } else if (wsa) {
        WSABUF buffer = {sizeof(result), result};
        DWORD amount = 0, flags = 0;
        if (WSARecvFrom(socketValue, &buffer, 1, &amount, &flags, (struct sockaddr*)&source,
                        &sourceLength, NULL, NULL) || amount != sizeof(reply)) goto done;
    } else if (recvfrom(socketValue, result, sizeof(result), 0, (struct sockaddr*)&source, &sourceLength) != sizeof(reply)) goto done;
    good = !memcmp(result, reply, sizeof(reply));
done:
    closesocket(socketValue);
    if (readOperation.hEvent) WSACloseEvent(readOperation.hEvent);
    if (writeOperation.hEvent) WSACloseEvent(writeOperation.hEvent);
    return good;
}

static int failure_probe(void) {
    char byte;
    WSASetLastError(12345);
    if (recv(INVALID_SOCKET, &byte, 1, 0) != SOCKET_ERROR || WSAGetLastError() != WSAENOTSOCK) return 0;
    SOCKET socketValue = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_storage local;
    int length = address(AF_INET, 0, &local), good = 0;
    u_long enabled = 1;
    if (socketValue == INVALID_SOCKET) return 0;
    if (bind(socketValue, (struct sockaddr*)&local, length) || ioctlsocket(socketValue, FIONBIO, &enabled)) goto done;
    if (recv(socketValue, &byte, 1, 0) != SOCKET_ERROR || WSAGetLastError() != WSAEWOULDBLOCK) goto done;
    good = 1;
done:
    closesocket(socketValue);
    return good;
}

int main(int argc, char** argv) {
    if (argc < 6) return 64;
    if (strcmp(argv[5], "bare") && !LoadLibraryA(argv[1])) {
        fprintf(stderr, "LoadLibrary(Fragment) failed: %lu\n", GetLastError()); return 65;
    }
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data)) return 66;
    int wsa = strcmp(argv[4], "sync") && strcmp(argv[4], "ipv6");
    int pending = !strcmp(argv[4], "pending");
    int asyncSend = !strcmp(argv[4], "async-send");
    int family = !strcmp(argv[4], "ipv6") ? AF_INET6 : AF_INET;
    int iterations = argc > 6 ? atoi(argv[6]) : 1, good = 1;
    if (iterations < 1 || iterations > 100) return 64;
    if (!strcmp(argv[4], "failure")) good = failure_probe();
    else for (int i = 0; i < iterations && good; ++i)
        good = tcp(family, atoi(argv[2]), wsa, pending, asyncSend) &&
               udp(family, atoi(argv[3]), wsa, pending, asyncSend);
    WSACleanup();
    if (good) puts("Raw TCP/UDP bytes preserved");
    else fprintf(stderr, "Raw network fixture failed (%s)\n", argv[4]);
    return good ? 0 : 1;
}
