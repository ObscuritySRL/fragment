#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"

/* The observer has its own sink: TLS records are byte streams, not synthetic
 * HTTP requests to the redirect proxy. One file belongs to one process/run.
 * CREATE_NEW prevents overwriting an earlier capture; FILE_SHARE_READ permits
 * live inspection. No network I/O or buffered CRT file locks in this path.
 * The DLL is pinned; the OS closes the handle on exit (no DllMain flush wait).
 */
#define FRAGMENT_CAPTURE_LIMIT (1024u * 1024u)
static HANDLE gCaptureFile = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION gCaptureLock;
static volatile LONG gCaptureReady;
static unsigned long long gCaptureSequence, gCaptureConnection;
static char gCaptureSession[64];

static unsigned long long CaptureTime(void) {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER ticks;
    ticks.LowPart = ft.dwLowDateTime;
    ticks.HighPart = ft.dwHighDateTime;
    return (ticks.QuadPart - 116444736000000000ULL) / 10000;
}

static BOOL CaptureAvailable(void) {
    return InterlockedCompareExchange(&gCaptureReady, 0, 0) != 0;
}

static void CaptureError(const char* message, DWORD error) {
    char text[256];
    int n = _snprintf_s(text, sizeof(text), _TRUNCATE,
                       "[Fragment] capture %s (Windows error %lu)\n", message, error);
    OutputDebugStringA(text);
    HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
    DWORD written;
    if (n > 0 && err && err != INVALID_HANDLE_VALUE) WriteFile(err, text, (DWORD)n, &written, NULL);
    LogError("%s", text);
}

/* Caller holds gCaptureLock. A write failure disables recording, never TLS.
 * Readers reject an incomplete last record instead of inventing stream bytes.
 */
static BOOL CaptureAppend(const char* data, size_t length) {
    if (!CaptureAvailable()) return FALSE;
    while (length) {
        DWORD written = 0;
        if (!WriteFile(gCaptureFile, data, (DWORD)length, &written, NULL) || !written) {
            DWORD error = GetLastError();
            InterlockedExchange(&gCaptureReady, 0);
            /* Do not acquire diagnostic-log locks while holding capture lock. */
            char message[160];
            _snprintf_s(message, sizeof(message), _TRUNCATE,
                        "[Fragment] capture write failed (%lu); recording stopped\n", error);
            OutputDebugStringA(message);
            return FALSE;
        }
        data += written;
        length -= written;
    }
    return TRUE;
}

static int CapturePrefix(char* out, size_t capacity, const char* type) {
    return _snprintf_s(out, capacity, _TRUNCATE,
        "{\"v\":1,\"type\":\"%s\",\"session\":\"%s\",\"seq\":%llu,\"time\":%llu,\"pid\":%lu,\"tid\":%lu",
        type, gCaptureSession, ++gCaptureSequence, CaptureTime(),
        GetCurrentProcessId(), GetCurrentThreadId());
}

static BOOL CaptureInit(const wchar_t* path) {
    InitializeCriticalSection(&gCaptureLock);
    gCaptureFile = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                              CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (gCaptureFile == INVALID_HANDLE_VALUE) {
        CaptureError("cannot create output (choose a new writable file)", GetLastError());
        return FALSE;
    }
    if (GetFileType(gCaptureFile) != FILE_TYPE_DISK) {
        CloseHandle(gCaptureFile);
        gCaptureFile = INVALID_HANDLE_VALUE;
        CaptureError("requires a regular disk file", ERROR_INVALID_HANDLE);
        return FALSE;
    }
    _snprintf_s(gCaptureSession, sizeof(gCaptureSession), _TRUNCATE, "%llu-%lu",
                CaptureTime(), GetCurrentProcessId());
    InterlockedExchange(&gCaptureReady, 1);
    char line[512];
    int n = CapturePrefix(line, sizeof(line), "session");
    if (n > 0) n += sprintf_s(line + n, sizeof(line) - n, ",\"mode\":\"observe\"}\n");
    BOOL ok = n > 0 && CaptureAppend(line, (size_t)n);
    if (!ok) {
        CloseHandle(gCaptureFile);
        gCaptureFile = INVALID_HANDLE_VALUE;
        InterlockedExchange(&gCaptureReady, 0);
    }
    return ok;
}

static unsigned long long CaptureNextConnection(void) {
    EnterCriticalSection(&gCaptureLock);
    unsigned long long result = ++gCaptureConnection;
    LeaveCriticalSection(&gCaptureLock);
    return result;
}

/* backend and direction are internal fixed literals, never application input. */
static void CaptureBackend(const char* backend, BOOL ready) {
    if (!CaptureAvailable()) return;
    DWORD error = GetLastError();
    EnterCriticalSection(&gCaptureLock);
    char line[512];
    int n = CapturePrefix(line, sizeof(line), "backend");
    if (n > 0) n += sprintf_s(line + n, sizeof(line) - n,
        ",\"backend\":\"%s\",\"ready\":%s}\n", backend, ready ? "true" : "false");
    if (n > 0) CaptureAppend(line, (size_t)n);
    LeaveCriticalSection(&gCaptureLock);
    SetLastError(error);
}

/* Reasons are fixed internal identifiers, not untrusted application text. */
static void CaptureGap(const char* backend, unsigned long long connection,
                       const char* direction, const char* reason) {
    if (!CaptureAvailable()) return;
    DWORD error = GetLastError();
    EnterCriticalSection(&gCaptureLock);
    char line[768];
    int n = CapturePrefix(line, sizeof(line), "gap");
    if (n > 0) n += sprintf_s(line + n, sizeof(line) - n,
        ",\"backend\":\"%s\",\"connection\":%llu,\"direction\":\"%s\",\"reason\":\"%s\"}\n",
        backend, connection, direction, reason);
    if (n > 0) CaptureAppend(line, (size_t)n);
    LeaveCriticalSection(&gCaptureLock);
    SetLastError(error);
}

/* Addresses are formatted numeric sockaddr values, never DNS/app strings. */
static void CaptureNetwork(unsigned long long connection, const char* event,
                           const char* transport, const char* local, const char* remote,
                           unsigned long long bytes, const char* status, int socketError) {
    if (!CaptureAvailable()) return;
    DWORD error = GetLastError();
    EnterCriticalSection(&gCaptureLock);
    char line[1536];
    int n = CapturePrefix(line, sizeof(line), "network");
    if (n > 0) n += sprintf_s(line + n, sizeof(line) - n,
        ",\"backend\":\"winsock\",\"connection\":%llu,\"event\":\"%s\",\"transport\":\"%s\",\"local\":\"%s\",\"remote\":\"%s\",\"bytes\":%llu,\"status\":\"%s\",\"error\":%d}\n",
        connection, event, transport, local, remote, bytes, status, socketError);
    if (n > 0) CaptureAppend(line, (size_t)n);
    LeaveCriticalSection(&gCaptureLock);
    SetLastError(error);
}

static void CaptureWrite(const char* backend, unsigned long long connection,
                         const char* direction, const void* data,
                         size_t captured, size_t original) {
    if (!CaptureAvailable() || !data || !captured) return;
    DWORD error = GetLastError();
    if (captured > FRAGMENT_CAPTURE_LIMIT) captured = FRAGMENT_CAPTURE_LIMIT;
    if (original < captured) original = captured;
    size_t capacity = 768 + 4 * ((captured + 2) / 3);
    char* line = (char*)HeapAlloc(GetProcessHeap(), 0, capacity);
    if (!line) {
        CaptureGap(backend, connection, direction, "capture-allocation-failed");
        SetLastError(error);
        return;
    }
    EnterCriticalSection(&gCaptureLock);
    int n = CapturePrefix(line, capacity, "data");
    if (n > 0) n += sprintf_s(line + n, capacity - n,
        ",\"backend\":\"%s\",\"connection\":%llu,\"direction\":\"%s\",\"length\":%llu,\"captured\":%llu,\"truncated\":%s,\"data\":\"",
        backend, connection, direction, (unsigned long long)original,
        (unsigned long long)captured, original > captured ? "true" : "false");
    if (n > 0) {
        static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        const unsigned char* bytes = (const unsigned char*)data;
        size_t pos = (size_t)n;
        for (size_t i = 0; i < captured; i += 3) {
            unsigned int value = (unsigned int)bytes[i] << 16;
            if (i + 1 < captured) value |= (unsigned int)bytes[i + 1] << 8;
            if (i + 2 < captured) value |= bytes[i + 2];
            line[pos++] = alphabet[(value >> 18) & 63];
            line[pos++] = alphabet[(value >> 12) & 63];
            line[pos++] = i + 1 < captured ? alphabet[(value >> 6) & 63] : '=';
            line[pos++] = i + 2 < captured ? alphabet[value & 63] : '=';
        }
        memcpy(line + pos, "\"}\n", 3);
        CaptureAppend(line, pos + 3);
    }
    LeaveCriticalSection(&gCaptureLock);
    HeapFree(GetProcessHeap(), 0, line);
    SetLastError(error);
}
