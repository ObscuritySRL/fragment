#pragma once

#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <windows.h>
#include <security.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>
#include "capture.h"

/* Passive TLS plaintext observation at the Windows SSPI dispatcher. This does
 * not change destinations, certificates, QOP, buffers, or return values. SSPI
 * is also used by authentication packages: only a positively identified
 * Schannel context is eligible. Provider APIs are called from live message
 * detours, never from module discovery / loader notifications.
 *
 * Secur32's forwarded exports and InitSecurityInterfaceA/W tables on supported
 * Windows builds point to the same SSPICLI message entry points. Hook their
 * actual owning image, including tables obtained before Fragment was loaded.
 * Do not call InitSecurityInterface in DllMain to discover those tables.
 * The integration suite exercises both export and table entry paths.
 */

#define SC_CAPTURE_LIMIT (1024u * 1024u)
#define SC_BUFFER_LIMIT 64u
#define SC_CONTEXT_LIMIT 16384u

static ENCRYPT_MESSAGE_FN gScEncrypt = NULL;
static DECRYPT_MESSAGE_FN gScDecrypt = NULL;
static DELETE_SECURITY_CONTEXT_FN gScDelete = NULL;
static QUERY_CONTEXT_ATTRIBUTES_FN_W gScQuery = NULL;
static FREE_CONTEXT_BUFFER_FN gScFree = NULL;
static HMODULE gScModule = NULL;
static volatile LONG gScActive = 0;
static volatile LONG gScReported = 0;
static volatile LONG gScEpoch = 1;
static CRITICAL_SECTION gScLock;
static HANDLE gScHeap = NULL;
static DWORD gScTls = TLS_OUT_OF_INDEXES;

typedef struct ScContext {
    CtxtHandle handle;                 /* values, not address of caller storage */
    unsigned long long connection;
    struct ScContext* next;
} ScContext;

static ScContext* gScContexts = NULL;
static size_t gScContextCount = 0;
static LONG gScContextEpoch = 1;

typedef struct ScSnapshot {
    unsigned char* data;
    size_t captured;
    size_t original;
    const char* omitted;
} ScSnapshot;

/* Called once during process attach, before hooks can be published. A private
 * heap avoids sharing CRT allocation locks with code under the loader lock. */
static void SchannelInit(void) {
    InitializeCriticalSection(&gScLock);
    gScHeap = HeapCreate(0, 0, 0);
    gScTls = TlsAlloc();
}

static BOOL ScSameContext(const CtxtHandle* a, const CtxtHandle* b) {
    return a->dwLower == b->dwLower && a->dwUpper == b->dwUpper;
}

/* Instrumentation must not turn an invalid caller argument into a new access
 * violation before SSPI can return its own error. MSVC/clang-cl SEH also guards
 * against a buffer becoming inaccessible during the best-effort snapshot. */
static BOOL ScCopyHandle(PCtxtHandle source, CtxtHandle* dest) {
    if (!source) return FALSE;
    __try {
        *dest = *source;
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

/* gScLock must be held. Unload advances the epoch without taking this lock:
 * no loader callback waits for a live provider query or capture operation. */
static void ScRefreshContexts(void) {
    LONG epoch = InterlockedCompareExchange(&gScEpoch, 0, 0);
    if (epoch == gScContextEpoch) return;
    while (gScContexts) {
        ScContext* next = gScContexts->next;
        HeapFree(gScHeap, 0, gScContexts);
        gScContexts = next;
    }
    gScContextCount = 0;
    gScContextEpoch = epoch;
}

static BOOL ScIsSchannel(PCtxtHandle context) {
    SecPkgContext_PackageInfoW info = {0};
    QUERY_CONTEXT_ATTRIBUTES_FN_W query = gScQuery;
    FREE_CONTEXT_BUFFER_FN release = gScFree;
    if (!query || !release || query(context, SECPKG_ATTR_PACKAGE_INFO, &info) != SEC_E_OK)
        return FALSE;
    BOOL recognized = FALSE;
    if (info.PackageInfo && info.PackageInfo->Name) {
        const wchar_t* name = info.PackageInfo->Name;
        /* Names from the Windows SDK's Schannel provider definitions. Avoid
         * including <schannel.h>, which would collide with this local header. */
        recognized = !_wcsicmp(name, L"Microsoft Unified Security Protocol Provider") ||
                     !_wcsicmp(name, L"Schannel") ||
                     !_wcsicmp(name, L"Microsoft TLS 1.0") ||
                     !_wcsicmp(name, L"Microsoft SSL 3.0") ||
                     !_wcsicmp(name, L"Microsoft SSL 2.0") ||
                     !_wcsicmp(name, L"Microsoft PCT 1.0");
    }
    if (info.PackageInfo) release(info.PackageInfo);
    return recognized;
}

static unsigned long long ScConnection(PCtxtHandle context, const char** omitted) {
    CtxtHandle key;
    if (!ScCopyHandle(context, &key)) return 0;
    EnterCriticalSection(&gScLock);
    ScRefreshContexts();
    for (ScContext* entry = gScContexts; entry; entry = entry->next) {
        if (ScSameContext(&entry->handle, &key)) {
            unsigned long long id = entry->connection;
            LeaveCriticalSection(&gScLock);
            return id;
        }
    }
    LONG epoch = gScContextEpoch;
    LeaveCriticalSection(&gScLock);

    /* A provider can itself load modules. Never hold gScLock while invoking it. */
    if (!ScIsSchannel(&key)) return 0;
    ScContext* fresh = (ScContext*) HeapAlloc(gScHeap, 0, sizeof(*fresh));
    if (!fresh) { *omitted = "context_allocation_failed"; return 0; }
    fresh->handle = key;
    fresh->connection = CaptureNextConnection();
    EnterCriticalSection(&gScLock);
    ScRefreshContexts();
    unsigned long long id = 0;
    if (gScActive && epoch == gScContextEpoch) {
        /* Simultaneous encrypt/decrypt on one context is explicitly supported
         * by Schannel. Both directions must receive the same connection ID. */
        for (ScContext* entry = gScContexts; entry; entry = entry->next) {
            if (ScSameContext(&entry->handle, &key)) {
                id = entry->connection;
                break;
            }
        }
        if (!id && gScContextCount < SC_CONTEXT_LIMIT) {
            fresh->next = gScContexts;
            gScContexts = fresh;
            ++gScContextCount;
            id = fresh->connection;
            fresh = NULL;
        }
        if (!id) *omitted = "context_limit";
    } else {
        *omitted = "context_unavailable";
    }
    LeaveCriticalSection(&gScLock);
    if (fresh) HeapFree(gScHeap, 0, fresh);
    return id;
}

static void ScForget(const CtxtHandle* key) {
    EnterCriticalSection(&gScLock);
    ScRefreshContexts();
    ScContext** link = &gScContexts;
    while (*link) {
        ScContext* entry = *link;
        if (ScSameContext(&entry->handle, key)) {
            *link = entry->next;
            --gScContextCount;
            HeapFree(gScHeap, 0, entry);
            break;
        }
        link = &entry->next;
    }
    LeaveCriticalSection(&gScLock);
}

static void ScSnapshotFree(ScSnapshot* snapshot) {
    if (snapshot->data) HeapFree(gScHeap, 0, snapshot->data);
    memset(snapshot, 0, sizeof(*snapshot));
}

static void ScSnapshotMessage(PSecBufferDesc message, ScSnapshot* snapshot) {
    SecBuffer buffers[SC_BUFFER_LIMIT];
    memset(snapshot, 0, sizeof(*snapshot));
    __try {
        if (!message || message->ulVersion != SECBUFFER_VERSION || !message->pBuffers) {
            snapshot->omitted = "invalid_descriptor";
            return;
        }
        if (message->cBuffers > SC_BUFFER_LIMIT) {
            snapshot->omitted = "buffer_count_limit";
            return;
        }
        if (!message->cBuffers) return;
        ULONG count = message->cBuffers;
        memcpy(buffers, message->pBuffers, count * sizeof(*buffers));
        size_t total = 0;
        for (ULONG i = 0; i < count; ++i) {
            /* Exact DATA deliberately excludes READONLY / WITH_CHECKSUM data,
             * which is not encrypted, along with TOKEN, EXTRA, headers, trailers. */
            if (buffers[i].BufferType != SECBUFFER_DATA || !buffers[i].cbBuffer) continue;
            if (!buffers[i].pvBuffer) { snapshot->omitted = "unreadable_buffer"; return; }
            if (SIZE_MAX - total < buffers[i].cbBuffer) {
                snapshot->omitted = "length_overflow";
                return;
            }
            total += buffers[i].cbBuffer;
        }
        if (!total) return;
        size_t limit = total < SC_CAPTURE_LIMIT ? total : SC_CAPTURE_LIMIT;
        snapshot->data = (unsigned char*) HeapAlloc(gScHeap, 0, limit);
        if (!snapshot->data) { snapshot->omitted = "snapshot_allocation_failed"; return; }
        for (ULONG i = 0; i < count && snapshot->captured < limit; ++i) {
            if (buffers[i].BufferType != SECBUFFER_DATA || !buffers[i].cbBuffer) continue;
            size_t take = buffers[i].cbBuffer;
            if (take > limit - snapshot->captured) take = limit - snapshot->captured;
            memcpy(snapshot->data + snapshot->captured, buffers[i].pvBuffer, take);
            snapshot->captured += take;
        }
        snapshot->original = total;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ScSnapshotFree(snapshot);
        snapshot->omitted = "unreadable_buffer";
    }
}

static BOOL ScEnter(void) {
    if (!gScActive || !CaptureAvailable() || TlsGetValue(gScTls)) return FALSE;
    if (!TlsSetValue(gScTls, (void*)1)) return FALSE;
    /* The file sink can block: announce readiness from application execution,
     * never from discovery while the Windows loader lock is held. */
    if (InterlockedCompareExchange(&gScReported, 1, 0) == 0)
        CaptureBackend("schannel", TRUE);
    return TRUE;
}

static SECURITY_STATUS SEC_ENTRY ScEncryptDetour(PCtxtHandle context, ULONG qop,
                                                PSecBufferDesc message, ULONG sequence) {
    DWORD incomingError = GetLastError();
    ENCRYPT_MESSAGE_FN original = gScEncrypt;
    BOOL observing = qop != SECQOP_WRAP_OOB_DATA && ScEnter();
    ScSnapshot snapshot = {0};
    unsigned long long connection = 0;
    const char* omitted = NULL;
    if (observing) {
        connection = ScConnection(context, &omitted);
        if (connection) ScSnapshotMessage(message, &snapshot);
    }
    SetLastError(incomingError);
    SECURITY_STATUS status = original(context, qop, message, sequence);
    DWORD outgoingError = GetLastError();
    if (observing) {
        /* SEC_E_OK means accepted for encryption, not delivered on a socket. */
        if (status == SEC_E_OK && snapshot.captured)
            CaptureWrite("schannel", connection, "out", snapshot.data, snapshot.captured, snapshot.original);
        if (status == SEC_E_OK && (omitted || snapshot.omitted))
            CaptureGap("schannel", connection, "out", omitted ? omitted : snapshot.omitted);
        ScSnapshotFree(&snapshot);
        TlsSetValue(gScTls, NULL);
    }
    SetLastError(outgoingError);
    return status;
}

static SECURITY_STATUS SEC_ENTRY ScDecryptDetour(PCtxtHandle context, PSecBufferDesc message,
                                                ULONG sequence, PULONG qop) {
    DWORD incomingError = GetLastError();
    DECRYPT_MESSAGE_FN original = gScDecrypt;
    BOOL observing = ScEnter();
    SetLastError(incomingError);
    SECURITY_STATUS status = original(context, message, sequence, qop);
    DWORD outgoingError = GetLastError();
    if (observing) {
        /* Conservatively capture only SEC_E_OK. Incomplete messages and
         * informational statuses (shutdown / renegotiation) are omitted. */
        if (status == SEC_E_OK) {
            const char* omitted = NULL;
            unsigned long long connection = ScConnection(context, &omitted);
            if (connection) {
                ScSnapshot snapshot;
                ScSnapshotMessage(message, &snapshot);
                if (snapshot.captured)
                    CaptureWrite("schannel", connection, "in", snapshot.data, snapshot.captured, snapshot.original);
                if (snapshot.omitted)
                    CaptureGap("schannel", connection, "in", snapshot.omitted);
                ScSnapshotFree(&snapshot);
            }
            if (omitted) CaptureGap("schannel", connection, "in", omitted);
        }
        TlsSetValue(gScTls, NULL);
    }
    SetLastError(outgoingError);
    return status;
}

static SECURITY_STATUS SEC_ENTRY ScDeleteDetour(PCtxtHandle context) {
    DWORD incomingError = GetLastError();
    DELETE_SECURITY_CONTEXT_FN original = gScDelete;
    CtxtHandle key;
    BOOL haveKey = gScActive && ScCopyHandle(context, &key);
    /* Forget before the provider can release/recycle the numeric handle. An
     * eviction after return could erase another thread's newly reused context.
     * A failed delete may split one stream across IDs; merging unrelated TLS
     * connections is worse than this explicit conservative boundary. */
    if (haveKey) ScForget(&key);
    SetLastError(incomingError);
    SECURITY_STATUS status = original(context);
    DWORD outgoingError = GetLastError();
    SetLastError(outgoingError);
    return status;
}

/* gHookLock serializes this with discovery. Do not free state or acquire the
 * runtime map lock while the loader lock is held. Trampolines are retained by
 * the hook engine for in-flight detours, matching its unload policy. */
static void SchannelModuleUnloaded(HMODULE module) {
    if (gScModule != module) return;
    InterlockedExchange(&gScActive, 0);
    InterlockedExchange(&gScReported, 0);
    InterlockedIncrement(&gScEpoch);
    gScModule = NULL;
    gScEncrypt = NULL;
    gScDecrypt = NULL;
    gScDelete = NULL;
    gScQuery = NULL;
    gScFree = NULL;
}

static void ScInstall(HMODULE module, const char* name, LPVOID detour, LPVOID* original) {
    if (*original) return;
    LPVOID target = (LPVOID) GetProcAddress(module, name);
    if (target && !FrIsHooked(target) && CreateAndEnableHook(name, target, detour, original))
        LogInfo("[hook] %s @ 0x%p\n", name, target);
}

static void HookSchannel(HMODULE module) {
    if (!module || !gCfg.observe || !gScHeap || gScTls == TLS_OUT_OF_INDEXES) return;
    char path[MAX_PATH] = {0};
    GetModuleFileNameA(module, path, MAX_PATH);
    const char* name = path;
    for (const char* p = path; *p; ++p)
        if (*p == '\\' || *p == '/') name = p + 1;
    /* SSPICLI owns the dispatcher exports. Avoid resolving secur32 forwards
     * here: GetProcAddress on a forward can load its owner under notification. */
    if (_stricmp(name, "sspicli.dll")) return;

    if (gHookLockReady) EnterCriticalSection(&gHookLock);
    if ((!gScModule || gScModule == module) && !gScActive) {
        gScModule = module;
        gScQuery = (QUERY_CONTEXT_ATTRIBUTES_FN_W)(void*) GetProcAddress(module, "QueryContextAttributesW");
        gScFree = (FREE_CONTEXT_BUFFER_FN)(void*) GetProcAddress(module, "FreeContextBuffer");
        if (gScQuery && gScFree) {
            ScInstall(module, "EncryptMessage", (LPVOID)&ScEncryptDetour, (LPVOID*)&gScEncrypt);
            ScInstall(module, "DecryptMessage", (LPVOID)&ScDecryptDetour, (LPVOID*)&gScDecrypt);
            ScInstall(module, "DeleteSecurityContext", (LPVOID)&ScDeleteDetour, (LPVOID*)&gScDelete);
        }
        BOOL ready = gScQuery && gScFree && gScEncrypt && gScDecrypt && gScDelete;
        if (ready) InterlockedExchange(&gScActive, 1);
        if (ready) LogInfo("[schannel] backend ready (three hooks installed; passive plaintext observation)\n");
        else LogWarn("[schannel] backend inactive: incomplete hook installation\n");
    }
    if (gHookLockReady) LeaveCriticalSection(&gHookLock);
}
