#pragma once

#include <windows.h>
#include <winhttp.h>
#include <stdlib.h>
#include <wchar.h>
#include "log.h"
#include "config.h"
#include "util.h"   // CreateAndEnableHook
#include "hook.h"   // FrIsHooked

/*
 * WinHTTP backend -- the same "redirect the intent to the local proxy BEFORE
 * TLS" idea as the libcurl backend, applied to winhttp.dll.
 *
 * Why it is not a copy of the curl backend: libcurl funnels the whole
 * destination through ONE variadic setter (curl_easy_setopt(CURLOPT_URL)), so a
 * single detour rewrites the URL string. WinHTTP has no such call -- a request
 * is assembled across handles:
 *
 *     WinHttpConnect(hSession, host, port, ...)        -> hConnect   (host+port)
 *     WinHttpOpenRequest(hConnect, verb, path, ..., flags) -> hRequest (path+scheme)
 *     WinHttpSendRequest(hRequest, ...)                              (sends)
 *
 * The host lives on the connection handle and the path/scheme live on the
 * request handle, so we hook BOTH and correlate by HINTERNET: WinHttpConnect
 * remembers the original (host, port) keyed by the handle it returns, and
 * WinHttpOpenRequest looks that up to rebuild the full original URL into the
 * request's object name, exactly as the curl prefix does:
 *
 *     GET /https://api.example.com/health   ->   proxy at 127.0.0.1:9020
 *
 * Like curl, the rewrite happens before any connection or handshake, so cert
 * pinning is never engaged: the origin TLS session simply never starts.
 *
 * Resolution is by export only -- winhttp.dll is a stable system module, so the
 * static-signature scan the curl backend needs has no analogue here. There is
 * one winhttp.dll per process, so (unlike curl's per-module caller stubs) plain
 * global trampolines suffice.
 *
 * Scope: a redirect-to-LOCAL-proxy inspection backend, for software/systems the
 * operator is authorized to analyze (see README). No remote egress.
 */

/* ---- WinHTTP entry points we hook (signatures per the SDK) ------------- */
typedef HINTERNET (WINAPI *WhOpenFn)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET (WINAPI *WhConnectFn)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET (WINAPI *WhOpenRequestFn)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL      (WINAPI *WhCloseHandleFn)(HINTERNET);
typedef BOOL      (WINAPI *WhSetOptionFn)(HINTERNET, DWORD, LPVOID, DWORD);

static WhOpenFn        gWhOpen        = NULL;
static WhConnectFn     gWhConnect     = NULL;
static WhOpenRequestFn gWhOpenRequest = NULL;
static WhCloseHandleFn gWhClose       = NULL;
static WhSetOptionFn   gWhSetOption   = NULL;

/* ---- hConnect -> original (host, port) map ---------------------------- */
typedef struct WhConn {
    HINTERNET      handle;   /* connection handle (map key)           */
    HINTERNET      session;  /* parent session handle (cascade evict) */
    wchar_t*       host;     /* original server name (owned)          */
    INTERNET_PORT  port;     /* original port (0 == INTERNET_DEFAULT) */
    struct WhConn* next;
} WhConn;

static WhConn*          gWhConns = NULL;
static CRITICAL_SECTION gWhLock;
static volatile LONG    gWhLockReady = 0;   /* set AFTER gWhLock is constructed */

static void WhRemember(HINTERNET session, HINTERNET h, LPCWSTR host, INTERNET_PORT port) {
    if (!h) return;
    WhConn* e = (WhConn*) malloc(sizeof(WhConn));
    if (!e) return;
    e->handle  = h;
    e->session = session;
    e->port    = port;
    e->host    = host ? _wcsdup(host) : NULL;
    EnterCriticalSection(&gWhLock);
    e->next  = gWhConns;
    gWhConns = e;
    LeaveCriticalSection(&gWhLock);
}

/* Copy the origin for `h` into caller storage (caller frees *outHost).
 * Returns FALSE if the handle was never seen (e.g. a connection opened before
 * the hook installed) -- the caller then leaves the request untouched. */
static BOOL WhLookup(HINTERNET h, wchar_t** outHost, INTERNET_PORT* outPort) {
    BOOL found = FALSE;
    EnterCriticalSection(&gWhLock);
    for (WhConn* e = gWhConns; e; e = e->next) {
        if (e->handle == h) {
            *outHost = e->host ? _wcsdup(e->host) : NULL;
            *outPort = e->port;
            found = TRUE;
            break;
        }
    }
    LeaveCriticalSection(&gWhLock);
    return found;
}

/* Evict every entry whose connection handle OR parent session handle is `h`.
 * Closing the session handle is the common teardown that frees its child
 * connection handles implicitly -- never through this hooked close -- so
 * matching on the session too is what keeps the map from growing without
 * bound. */
static void WhForget(HINTERNET h) {
    EnterCriticalSection(&gWhLock);
    WhConn** pp = &gWhConns;
    while (*pp) {
        WhConn* cur = *pp;
        if (cur->handle == h || cur->session == h) {
            *pp = cur->next;
            free(cur->host);
            free(cur);
        } else {
            pp = &cur->next;
        }
    }
    LeaveCriticalSection(&gWhLock);
}

/* ---- detours ---------------------------------------------------------- */

/* Force a DIRECT session: the proxy IS our destination, so an app's upstream
 * proxy must not be interposed between the target and 127.0.0.1:9020. Mirrors
 * the curl backend forcing CURLOPT_PROXY="". Gated on a usable proxy host: with
 * none, the backend is inert (WhConnectDetour passes through), so forcing
 * NO_PROXY here would strip the app's own proxy and strand it. */
static HINTERNET WINAPI WhOpenDetour(LPCWSTR agent, DWORD accessType, LPCWSTR proxy,
                                     LPCWSTR proxyBypass, DWORD flags) {
    if (gCfg.proxyHostW[0] && accessType != WINHTTP_ACCESS_TYPE_NO_PROXY) {
        LogDebug("[winhttp] WinHttpOpen: forcing NO_PROXY (was %lu)\n", accessType);
        accessType  = WINHTTP_ACCESS_TYPE_NO_PROXY;
        proxy       = WINHTTP_NO_PROXY_NAME;
        proxyBypass = WINHTTP_NO_PROXY_BYPASS;
    }
    return gWhOpen(agent, accessType, proxy, proxyBypass, flags);
}

/* Redirect the connection to the local proxy and remember the real origin,
 * keyed by the returned handle, for WinHttpOpenRequest to rebuild. */
static HINTERNET WINAPI WhConnectDetour(HINTERNET session, LPCWSTR server,
                                        INTERNET_PORT port, DWORD reserved) {
    if (!gCfg.proxyHostW[0])                     /* no usable proxy host: pass through */
        return gWhConnect(session, server, port, reserved);

    HINTERNET h = gWhConnect(session, gCfg.proxyHostW, (INTERNET_PORT) gCfg.proxyPort, reserved);
    if (h) {
        WhRemember(session, h, server, port);
        LogDebug("[winhttp] WinHttpConnect: %ls:%u -> %ls:%u (h=0x%p)\n",
                 server ? server : L"(null)", (unsigned) port,
                 gCfg.proxyHostW, (unsigned) gCfg.proxyPort, h);
    }
    return h;
}

/* Rebuild the object name to <mount>/<origin-scheme>://<host>[:port]<path> so the
 * proxy receives the full original URL (the optional <mount> is the proxy's own
 * path prefix, kept in lock-step with the curl backend's "<proxyPrefix><url>"),
 * and set the request's secure flag from the PROXY's scheme (what we speak to
 * 127.0.0.1:9020), not the origin's. */
static HINTERNET WINAPI WhOpenRequestDetour(HINTERNET connect, LPCWSTR verb,
                                            LPCWSTR object, LPCWSTR version,
                                            LPCWSTR referrer, LPCWSTR* acceptTypes,
                                            DWORD flags) {
    wchar_t*      host     = NULL;
    INTERNET_PORT origPort = 0;
    wchar_t*      newObject = NULL;

    if (WhLookup(connect, &host, &origPort)) {
        BOOL           originSecure = (flags & WINHTTP_FLAG_SECURE) != 0;
        const wchar_t* scheme       = originSecure ? L"https" : L"http";
        INTERNET_PORT  defPort      = originSecure ? 443 : 80;
        const wchar_t* path         = (object && *object) ? object : L"/";
        const wchar_t* lead         = (path[0] == L'/') ? L"" : L"/";

        const wchar_t* mount = gCfg.proxyPathW;   /* "" or "/inspect" (no trailing /) */
        size_t cap = wcslen(mount) + 1 + 5 + 3 + (host ? wcslen(host) : 0) + 6 + 1 + wcslen(path) + 1;
        newObject = (wchar_t*) malloc(cap * sizeof(wchar_t));
        if (newObject) {
            if (origPort != 0 && origPort != defPort)
                _snwprintf_s(newObject, cap, _TRUNCATE, L"%ls/%ls://%ls:%u%ls%ls",
                             mount, scheme, host ? host : L"", (unsigned) origPort, lead, path);
            else
                _snwprintf_s(newObject, cap, _TRUNCATE, L"%ls/%ls://%ls%ls%ls",
                             mount, scheme, host ? host : L"", lead, path);
            object = newObject;
            LogDebug("[winhttp] WinHttpOpenRequest -> %ls\n", newObject);
        }

        if (gCfg.proxySecure) flags |=  WINHTTP_FLAG_SECURE;
        else                  flags &= ~WINHTTP_FLAG_SECURE;
    }

    HINTERNET h = gWhOpenRequest(connect, verb, object, version, referrer, acceptTypes, flags);

    free(newObject);
    free(host);
    return h;
}

/* Evict the connection entry (and any siblings sharing this session handle)
 * before the handle value can be recycled by a later WinHttpConnect. Closing a
 * request handle matches nothing and is a no-op. */
static BOOL WINAPI WhCloseDetour(HINTERNET h) {
    WhForget(h);
    return gWhClose(h);
}

/* Swallow a proxy set AFTER the session is open: an app that calls
 * WinHttpSetOption(WINHTTP_OPTION_PROXY) would otherwise re-introduce an
 * upstream proxy between the target and our local proxy, undoing the NO_PROXY we
 * forced at WinHttpOpen. Report success so the app proceeds; the session stays
 * direct (mirrors the curl backend dropping CURLOPT_PROXY). */
static BOOL WINAPI WhSetOptionDetour(HINTERNET h, DWORD option, LPVOID buf, DWORD len) {
    /* Only swallow the proxy re-set when we have a proxy of our own to protect;
     * with no usable proxy host the backend is inert, so let the app set its
     * proxy normally (consistent with WhOpenDetour and WhConnectDetour). */
    if (gCfg.proxyHostW[0] && option == WINHTTP_OPTION_PROXY) {
        LogDebug("[winhttp] swallow WinHttpSetOption(WINHTTP_OPTION_PROXY)\n");
        return TRUE;
    }
    return gWhSetOption(h, option, buf, len);
}

/* ---- install ---------------------------------------------------------- */

static void WhInstall(HMODULE m, const char* name, LPVOID detour, LPVOID* orig) {
    if (*orig) return;                               /* one winhttp.dll: bind once */
    LPVOID target = (LPVOID) GetProcAddress(m, name);
    if (!target || FrIsHooked(target)) return;
    if (CreateAndEnableHook(name, target, detour, orig))
        LogInfo("[hook] %s @ 0x%p\n", name, target);
    else
        LogWarn("[winhttp] failed to hook %s\n", name);
}

/* Install the WinHTTP backend when winhttp.dll appears. Reuses the curl
 * backend's gHookLock (defined in main.c, above this header's include point) so
 * resolve+dedup+install is serialized against the curl path's shared registry. */
/* winhttp.dll by name, OR any module exporting the WinHTTP request entry points
 * -- this catches a copy loaded from a non-System32 path or an SxS-redirected
 * name. Nothing but WinHTTP exports these symbols, so the export probe will not
 * false-match (and once a backend slot is bound, WhInstall skips re-binding). */
static BOOL WhIsWinHttp(HMODULE m, const char* nm) {
    if (!_stricmp(nm, "winhttp.dll")) return TRUE;
    return GetProcAddress(m, "WinHttpConnect") && GetProcAddress(m, "WinHttpOpenRequest");
}

void HookWinHttp(HMODULE module) {
    if (!module) return;

    char path[MAX_PATH] = {0};
    GetModuleFileNameA(module, path, MAX_PATH);
    const char* nm = path;
    for (const char* p = path; *p; ++p)
        if (*p == '\\' || *p == '/') nm = p + 1;
    if (!WhIsWinHttp(module, nm)) return;

    if (gHookLockReady) EnterCriticalSection(&gHookLock);
    /* Construct gWhLock exactly once, serialized by gHookLock (or single-threaded
     * during the DllMain sweep, before gHookLock is ready). Publishing
     * gWhLockReady only AFTER InitializeCriticalSection completes -- and binding
     * the detours that use gWhLock below under this same lock -- guarantees no
     * detour can ever enter an unconstructed section (mirrors HookLockInit). */
    if (!gWhLockReady) {
        InitializeCriticalSection(&gWhLock);
        InterlockedExchange(&gWhLockReady, 1);
    }
    WhInstall(module, "WinHttpOpen",        (LPVOID) &WhOpenDetour,        (LPVOID*) &gWhOpen);
    WhInstall(module, "WinHttpConnect",     (LPVOID) &WhConnectDetour,     (LPVOID*) &gWhConnect);
    WhInstall(module, "WinHttpOpenRequest", (LPVOID) &WhOpenRequestDetour, (LPVOID*) &gWhOpenRequest);
    WhInstall(module, "WinHttpCloseHandle", (LPVOID) &WhCloseDetour,       (LPVOID*) &gWhClose);
    WhInstall(module, "WinHttpSetOption",   (LPVOID) &WhSetOptionDetour,   (LPVOID*) &gWhSetOption);
    if (gHookLockReady) LeaveCriticalSection(&gHookLock);
}
