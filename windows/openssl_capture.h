#pragma once

#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include "capture.h"

/* Exported OpenSSL libssl ABI only. No signatures, SSL layout assumptions,
 * provider calls during discovery, certificate changes, or socket redirects.
 * Statically linked / hidden-symbol TLS implementations are not covered.
 *
 * Slots are immutable for one module generation, including after unload. A
 * returning detour must never see another library's trampoline. Thirty-two
 * lifetime module loads are supported; exhaustion fails closed with a log.
 * Plain C dispatch wrappers retain cdecl on x86 as well as x64/ARM64 ABIs.
 */
#define OS_MODULE_LIMIT 32u
#define OS_CONTEXT_LIMIT 16384u
#define OS_CAPTURE_LIMIT (1024u * 1024u)

typedef int (__cdecl *OsReadFn)(void*, void*, int);
typedef int (__cdecl *OsWriteFn)(void*, const void*, int);
typedef int (__cdecl *OsReadExFn)(void*, void*, size_t, size_t*);
typedef int (__cdecl *OsWriteExFn)(void*, const void*, size_t, size_t*);
typedef void (__cdecl *OsFreeFn)(void*);
typedef int (__cdecl *OsClearFn)(void*);

typedef struct OsModule {
    HMODULE module;
    volatile LONG active;
    volatile LONG reported;
    OsReadFn read;
    OsWriteFn write;
    OsReadExFn readEx;
    OsWriteExFn writeEx;
    OsFreeFn free;
    OsClearFn clear;
} OsModule;

typedef struct OsContext {
    OsModule* owner;                  /* immutable module-generation identity */
    void* ssl;
    unsigned long long connection;
    struct OsContext* next;
} OsContext;

typedef struct OsSnapshot {
    unsigned char* data;
    size_t captured;
    const char* omitted;
} OsSnapshot;

static OsModule gOsModules[OS_MODULE_LIMIT];
static unsigned int gOsModuleCount;
static BOOL gOsLimitReported;
static CRITICAL_SECTION gOsLock;
static HANDLE gOsHeap;
static DWORD gOsTls = TLS_OUT_OF_INDEXES;
static OsContext* gOsContexts;
static size_t gOsContextCount;

static void OpenSslInit(void) {
    InitializeCriticalSection(&gOsLock);
    gOsHeap = HeapCreate(0, 0, 0);
    gOsTls = TlsAlloc();
}

/* Runtime only, gOsLock held. Unload never waits for a data detour's lock. */
static void OsRetireContexts(void) {
    OsContext** link = &gOsContexts;
    while (*link) {
        OsContext* entry = *link;
        if (!entry->owner->active) {
            *link = entry->next;
            --gOsContextCount;
            HeapFree(gOsHeap, 0, entry);
        } else link = &entry->next;
    }
}

static unsigned long long OsConnection(OsModule* owner, void* ssl, const char** omitted) {
    EnterCriticalSection(&gOsLock);
    OsRetireContexts();
    for (OsContext* entry = gOsContexts; entry; entry = entry->next) {
        if (entry->owner == owner && entry->ssl == ssl) {
            unsigned long long id = entry->connection;
            LeaveCriticalSection(&gOsLock);
            return id;
        }
    }
    LeaveCriticalSection(&gOsLock);
    OsContext* fresh = (OsContext*) HeapAlloc(gOsHeap, 0, sizeof(*fresh));
    if (!fresh) { *omitted = "context_allocation_failed"; return 0; }
    fresh->owner = owner;
    fresh->ssl = ssl;
    /* The sink has a separate lock; do not nest it inside gOsLock. */
    fresh->connection = CaptureNextConnection();
    EnterCriticalSection(&gOsLock);
    OsRetireContexts();
    unsigned long long id = 0;
    if (owner->active) {
        for (OsContext* entry = gOsContexts; entry; entry = entry->next) {
            if (entry->owner == owner && entry->ssl == ssl) {
                id = entry->connection;
                break;
            }
        }
        if (!id && gOsContextCount < OS_CONTEXT_LIMIT) {
            fresh->next = gOsContexts;
            gOsContexts = fresh;
            ++gOsContextCount;
            id = fresh->connection;
            fresh = NULL;
        }
        if (!id) *omitted = "context_limit";
    } else *omitted = "module_unloaded";
    LeaveCriticalSection(&gOsLock);
    if (fresh) HeapFree(gOsHeap, 0, fresh);
    return id;
}

static void OsForget(OsModule* owner, void* ssl) {
    EnterCriticalSection(&gOsLock);
    OsContext** link = &gOsContexts;
    while (*link) {
        OsContext* entry = *link;
        if (entry->owner == owner && entry->ssl == ssl) {
            *link = entry->next;
            --gOsContextCount;
            HeapFree(gOsHeap, 0, entry);
            break;
        }
        link = &entry->next;
    }
    LeaveCriticalSection(&gOsLock);
}

static void OsSnapshotFree(OsSnapshot* snapshot) {
    if (snapshot->data) HeapFree(gOsHeap, 0, snapshot->data);
    memset(snapshot, 0, sizeof(*snapshot));
}

static void OsSnapshotBytes(const void* buffer, size_t length, OsSnapshot* snapshot) {
    memset(snapshot, 0, sizeof(*snapshot));
    if (!length) return;
    size_t take = length < OS_CAPTURE_LIMIT ? length : OS_CAPTURE_LIMIT;
    snapshot->data = (unsigned char*) HeapAlloc(gOsHeap, 0, take);
    if (!snapshot->data) { snapshot->omitted = "snapshot_allocation_failed"; return; }
    __try {
        memcpy(snapshot->data, buffer, take);
        snapshot->captured = take;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        OsSnapshotFree(snapshot);
        snapshot->omitted = "unreadable_buffer";
    }
}

static BOOL OsReadCount(const size_t* source, size_t* result) {
    __try {
        if (!source) return FALSE;
        *result = *source;
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

static BOOL OsEnter(OsModule* owner) {
    if (!owner->active || !CaptureAvailable() || TlsGetValue(gOsTls)) return FALSE;
    if (!TlsSetValue(gOsTls, (void*)1)) return FALSE;
    if (InterlockedCompareExchange(&owner->reported, 1, 0) == 0)
        CaptureBackend("openssl", TRUE);
    return TRUE;
}

/* The guard spans the original call: several OpenSSL versions implement the
 * old and _ex APIs through one another. Capture the outer accepted operation
 * exactly once, including partial writes; failed/WANT_READ/WANT_WRITE calls
 * produce no data. We never call SSL_get_error or touch OpenSSL's error queue. */
static int OsTransfer(unsigned int slot, void* ssl, void* buffer, int count,
                      size_t length, size_t* transferred, BOOL writing, BOOL extended) {
    DWORD incomingError = GetLastError();
    int incomingErrno = errno;
    OsModule* owner = &gOsModules[slot];
    BOOL observing = OsEnter(owner);
    OsSnapshot snapshot = {0};
    if (observing && writing) OsSnapshotBytes(buffer, length, &snapshot);
    errno = incomingErrno;
    SetLastError(incomingError);
    int result;
    if (extended)
        result = writing ? owner->writeEx(ssl, buffer, length, transferred)
                         : owner->readEx(ssl, buffer, length, transferred);
    else
        result = writing ? owner->write(ssl, buffer, count)
                         : owner->read(ssl, buffer, count);
    DWORD outgoingError = GetLastError();
    int outgoingErrno = errno;
    if (observing) {
        BOOL success = extended ? result == 1 : result > 0;
        if (success) {
            size_t accepted = extended ? 0 : (size_t)result;
            const char* omitted = NULL;
            if (extended && !OsReadCount(transferred, &accepted)) omitted = "unreadable_byte_count";
            else if (accepted > length) omitted = "invalid_byte_count";
            if (accepted || omitted) {
                unsigned long long connection = OsConnection(owner, ssl, &omitted);
                if (!writing && !omitted) OsSnapshotBytes(buffer, accepted, &snapshot);
                if (!omitted) omitted = snapshot.omitted;
                const char* direction = writing ? "out" : "in";
                if (omitted) CaptureGap("openssl", connection, direction, omitted);
                else if (connection && accepted) {
                    size_t captured = snapshot.captured < accepted ? snapshot.captured : accepted;
                    CaptureWrite("openssl", connection, direction, snapshot.data, captured, accepted);
                }
            }
        }
        OsSnapshotFree(&snapshot);
        TlsSetValue(gOsTls, NULL);
    }
    errno = outgoingErrno;
    SetLastError(outgoingError);
    return result;
}

static void OsFree(unsigned int slot, void* ssl) {
    DWORD incomingError = GetLastError();
    int incomingErrno = errno;
    OsModule* owner = &gOsModules[slot];
    /* Evict before the allocation can be recycled by another thread. SSL_free
     * can merely decrement a reference count; that conservatively starts a new
     * capture ID if a remaining reference is used, rather than merging objects. */
    if (owner->active && ssl) OsForget(owner, ssl);
    errno = incomingErrno;
    SetLastError(incomingError);
    owner->free(ssl);
}

static int OsClear(unsigned int slot, void* ssl) {
    OsModule* owner = &gOsModules[slot];
    int result = owner->clear(ssl);
    DWORD error = GetLastError();
    int savedErrno = errno;
    if (result == 1 && owner->active && ssl) OsForget(owner, ssl);
    errno = savedErrno;
    SetLastError(error);
    return result;
}

#define OS_EACH_SLOT(X) \
    X(0) X(1) X(2) X(3) X(4) X(5) X(6) X(7) \
    X(8) X(9) X(10) X(11) X(12) X(13) X(14) X(15) \
    X(16) X(17) X(18) X(19) X(20) X(21) X(22) X(23) \
    X(24) X(25) X(26) X(27) X(28) X(29) X(30) X(31)

#define OS_DEFINE_SLOT(N) \
    static int __cdecl OsRead##N(void* s, void* b, int n) { \
        return OsTransfer(N, s, b, n, n > 0 ? (size_t)n : 0, NULL, FALSE, FALSE); } \
    static int __cdecl OsWrite##N(void* s, const void* b, int n) { \
        return OsTransfer(N, s, (void*)b, n, n > 0 ? (size_t)n : 0, NULL, TRUE, FALSE); } \
    static int __cdecl OsReadEx##N(void* s, void* b, size_t n, size_t* a) { \
        return OsTransfer(N, s, b, 0, n, a, FALSE, TRUE); } \
    static int __cdecl OsWriteEx##N(void* s, const void* b, size_t n, size_t* a) { \
        return OsTransfer(N, s, (void*)b, 0, n, a, TRUE, TRUE); } \
    static void __cdecl OsFree##N(void* s) { OsFree(N, s); } \
    static int __cdecl OsClear##N(void* s) { return OsClear(N, s); }
OS_EACH_SLOT(OS_DEFINE_SLOT)
#undef OS_DEFINE_SLOT

#define OS_READ_SLOT(N) &OsRead##N,
#define OS_WRITE_SLOT(N) &OsWrite##N,
#define OS_READ_EX_SLOT(N) &OsReadEx##N,
#define OS_WRITE_EX_SLOT(N) &OsWriteEx##N,
#define OS_FREE_SLOT(N) &OsFree##N,
#define OS_CLEAR_SLOT(N) &OsClear##N,
static const OsReadFn gOsReadDetours[] = { OS_EACH_SLOT(OS_READ_SLOT) };
static const OsWriteFn gOsWriteDetours[] = { OS_EACH_SLOT(OS_WRITE_SLOT) };
static const OsReadExFn gOsReadExDetours[] = { OS_EACH_SLOT(OS_READ_EX_SLOT) };
static const OsWriteExFn gOsWriteExDetours[] = { OS_EACH_SLOT(OS_WRITE_EX_SLOT) };
static const OsFreeFn gOsFreeDetours[] = { OS_EACH_SLOT(OS_FREE_SLOT) };
static const OsClearFn gOsClearDetours[] = { OS_EACH_SLOT(OS_CLEAR_SLOT) };
#undef OS_READ_SLOT
#undef OS_WRITE_SLOT
#undef OS_READ_EX_SLOT
#undef OS_WRITE_EX_SLOT
#undef OS_FREE_SLOT
#undef OS_CLEAR_SLOT
#undef OS_EACH_SLOT

/* Unlike GetProcAddress, this never resolves an export forwarder by loading
 * another DLL. Only a local code address with an exact public API name is used. */
static LPVOID OsLocalExport(HMODULE module, const char* name) {
    /* Discovery probes every mapped image, including application-managed
     * images whose metadata pages may no longer be readable. */
    __try {
        if (!module || !name) return NULL;
        unsigned char* base = (unsigned char*)module;
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < (LONG)sizeof(*dos) ||
            (size_t)dos->e_lfanew > UINTPTR_MAX - (uintptr_t)base) return NULL;
        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC ||
            nt->FileHeader.SizeOfOptionalHeader < offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory) + sizeof(IMAGE_DATA_DIRECTORY) ||
            nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) return NULL;
        size_t size = nt->OptionalHeader.SizeOfImage;
        if (!size || size > UINTPTR_MAX - (uintptr_t)base || (size_t)dos->e_lfanew >= size ||
            sizeof(*nt) > size - (size_t)dos->e_lfanew) return NULL;
        IMAGE_DATA_DIRECTORY directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!directory.VirtualAddress || directory.VirtualAddress >= size ||
            directory.Size < sizeof(IMAGE_EXPORT_DIRECTORY) || directory.Size > size - directory.VirtualAddress)
            return NULL;
        IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)(base + directory.VirtualAddress);
        if (exports->AddressOfNames >= size || exports->NumberOfNames > (size - exports->AddressOfNames) / sizeof(DWORD) ||
            exports->AddressOfNameOrdinals >= size || exports->NumberOfNames > (size - exports->AddressOfNameOrdinals) / sizeof(WORD) ||
            exports->AddressOfFunctions >= size || exports->NumberOfFunctions > (size - exports->AddressOfFunctions) / sizeof(DWORD))
            return NULL;
        DWORD* names = (DWORD*)(base + exports->AddressOfNames);
        WORD* ordinals = (WORD*)(base + exports->AddressOfNameOrdinals);
        DWORD* functions = (DWORD*)(base + exports->AddressOfFunctions);
        size_t nameSize = strlen(name) + 1;
        for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
            if (names[i] >= size || nameSize > size - names[i] || memcmp(base + names[i], name, nameSize)) continue;
            if (ordinals[i] >= exports->NumberOfFunctions) return NULL;
            DWORD address = functions[ordinals[i]];
            if (!address || address >= size ||
                (address >= directory.VirtualAddress && address - directory.VirtualAddress < directory.Size))
                return NULL;
            MEMORY_BASIC_INFORMATION region;
            if (VirtualQuery(base + address, &region, sizeof(region)) != sizeof(region) || !IsExecRegion(&region))
                return NULL;
            return base + address;
        }
        return NULL;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
}

static void OsInstall(const char* name, LPVOID target, LPVOID detour, LPVOID* original) {
    if (*original || !target || FrIsHooked(target)) return;
    if (CreateAndEnableHook(name, target, detour, original))
        LogInfo("[hook] %s @ 0x%p\n", name, target);
}

/* Called with gHookLock held. Keep trampoline and slot metadata forever, just
 * retire the generation. Context map cleanup happens on its next runtime use. */
static void OpenSslModuleUnloaded(HMODULE module) {
    for (unsigned int i = 0; i < gOsModuleCount; ++i) {
        if (gOsModules[i].module == module) {
            InterlockedExchange(&gOsModules[i].active, 0);
            gOsModules[i].module = NULL;
        }
    }
}

static void HookOpenSsl(HMODULE module) {
    if (!module || !gCfg.observe || !gOsHeap || gOsTls == TLS_OUT_OF_INDEXES) return;
    LPVOID read = OsLocalExport(module, "SSL_read");
    if (!read) return;
    LPVOID write = OsLocalExport(module, "SSL_write");
    LPVOID release = OsLocalExport(module, "SSL_free");
    LPVOID clear = OsLocalExport(module, "SSL_clear");
    if (!write || !release || !clear || !OsLocalExport(module, "SSL_new") ||
        !OsLocalExport(module, "SSL_CTX_new") || !OsLocalExport(module, "SSL_get_error")) return;
    LPVOID readEx = OsLocalExport(module, "SSL_read_ex");
    LPVOID writeEx = OsLocalExport(module, "SSL_write_ex");

    if (gHookLockReady) EnterCriticalSection(&gHookLock);
    unsigned int slot;
    for (slot = 0; slot < gOsModuleCount; ++slot)
        if (gOsModules[slot].module == module) break;
    if (slot == gOsModuleCount) {
        if (gOsModuleCount == OS_MODULE_LIMIT) {
            if (!gOsLimitReported) {
                gOsLimitReported = TRUE;
                LogWarn("[openssl] module generation limit reached; additional libraries remain unobserved\n");
            }
            if (gHookLockReady) LeaveCriticalSection(&gHookLock);
            return;
        }
        gOsModules[slot].module = module;
        ++gOsModuleCount;
    }
    OsModule* owner = &gOsModules[slot];
    if (!owner->active) {
        OsInstall("SSL_read", read, (LPVOID)gOsReadDetours[slot], (LPVOID*)&owner->read);
        OsInstall("SSL_write", write, (LPVOID)gOsWriteDetours[slot], (LPVOID*)&owner->write);
        OsInstall("SSL_free", release, (LPVOID)gOsFreeDetours[slot], (LPVOID*)&owner->free);
        OsInstall("SSL_clear", clear, (LPVOID)gOsClearDetours[slot], (LPVOID*)&owner->clear);
        OsInstall("SSL_read_ex", readEx, (LPVOID)gOsReadExDetours[slot], (LPVOID*)&owner->readEx);
        OsInstall("SSL_write_ex", writeEx, (LPVOID)gOsWriteExDetours[slot], (LPVOID*)&owner->writeEx);
        BOOL ready = owner->read && owner->write && owner->free && owner->clear &&
                     (!readEx || owner->readEx) && (!writeEx || owner->writeEx);
        if (ready) {
            InterlockedExchange(&owner->active, 1);
            LogInfo("[openssl] backend ready (exported libssl, module %u)\n", slot + 1);
        } else LogWarn("[openssl] backend inactive: incomplete hook installation\n");
    }
    if (gHookLockReady) LeaveCriticalSection(&gHookLock);
}
