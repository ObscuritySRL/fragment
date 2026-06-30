/*
 * host_winhttp.c -- WinHTTP exerciser for Fragment's WinHTTP backend.
 *
 * Mirrors host.c (the curl driver): it self-loads Fragment.dll in-process for a
 * deterministic test, then drives REAL WinHTTP through dynamically-resolved
 * entry points -- so it needs no winhttp.lib and can control DLL load order
 * (to exercise both the loader-notification and already-mapped-sweep paths).
 * run_winhttp.py decides PASS/FAIL from which port+path the request lands on.
 *
 *   host_winhttp.exe <fragment_dll> <url> [mode] [a] [b]
 *
 * url   : http[s]://host[:port][/path[?query]]
 * modes :
 *   (default)    load Fragment, then winhttp, one GET   (notification path)
 *   swept        load winhttp, then Fragment, one GET   (already-mapped sweep)
 *   post         one POST (verb must be preserved)
 *   appproxy     set WinHttpOpen NAMED_PROXY = <a> (neutralization at Open)
 *   setoptproxy  set WinHttpSetOption(PROXY) = <a> (neutralization post-Open)
 *   stress       <a> threads x <b> requests, concurrent
 *   sessiononly  <a> cycles, closing ONLY the session handle each time
 *   bare         do NOT load Fragment (baseline, or external injection)
 *
 * Exit code is the request rc (0 = ok); the runner judges by the servers.
 */
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <process.h>

typedef HINTERNET (WINAPI *pOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET (WINAPI *pConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET (WINAPI *pOpenReq)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL      (WINAPI *pSend)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL      (WINAPI *pRecv)(HINTERNET, LPVOID);
typedef BOOL      (WINAPI *pClose)(HINTERNET);
typedef BOOL      (WINAPI *pSetOpt)(HINTERNET, DWORD, LPVOID, DWORD);

typedef struct {
    pOpen open; pConnect connect; pOpenReq openreq; pSend send; pRecv recv; pClose close; pSetOpt setopt;
    int           secure;
    wchar_t       hostW[256];
    INTERNET_PORT port;
    wchar_t       pathW[2048];
    const wchar_t* verbW;
    DWORD         access;            /* WinHttpOpen access type            */
    wchar_t       proxyW[256];       /* NAMED_PROXY name for appproxy mode */
    int           setopt_proxy;      /* setoptproxy mode                   */
    wchar_t       setoptProxyW[256];
} Req;

static void A2W(const char* a, wchar_t* w, int cap) {
    if (!a || !MultiByteToWideChar(CP_ACP, 0, a, -1, w, cap)) w[0] = 0;
}

static int parse_url(const char* url, int* secure, char* host, size_t hc,
                     INTERNET_PORT* port, char* path, size_t pc) {
    const char* p = strstr(url, "://");
    if (!p) return 0;
    size_t sl = (size_t)(p - url);
    *secure = (sl == 5 && !_strnicmp(url, "https", 5));
    const char* h = p + 3;
    const char* slash = strchr(h, '/');
    const char* hostend = slash ? slash : h + strlen(h);
    const char* colon = NULL;
    for (const char* q = h; q < hostend; ++q) if (*q == ':') colon = q;
    const char* he = colon ? colon : hostend;
    size_t hl = (size_t)(he - h);
    if (hl >= hc) hl = hc - 1;
    memcpy(host, h, hl); host[hl] = 0;
    *port = colon ? (INTERNET_PORT) atoi(colon + 1) : (INTERNET_PORT)(*secure ? 443 : 80);
    if (slash) _snprintf_s(path, pc, _TRUNCATE, "%s", slash);
    else       strcpy_s(path, pc, "/");
    return 1;
}

static int do_one(Req* r) {
    LPCWSTR proxyName = r->proxyW[0] ? r->proxyW : WINHTTP_NO_PROXY_NAME;
    HINTERNET hs = r->open(L"frag-winhttp-test", r->access, proxyName, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hs) return 1;
    if (r->setopt_proxy && r->setopt) {
        WINHTTP_PROXY_INFO pi; memset(&pi, 0, sizeof(pi));
        pi.dwAccessType   = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
        pi.lpszProxy      = r->setoptProxyW;
        pi.lpszProxyBypass = NULL;
        r->setopt(hs, WINHTTP_OPTION_PROXY, &pi, sizeof(pi));
    }
    HINTERNET hc = r->connect(hs, r->hostW, r->port, 0);
    if (!hc) { r->close(hs); return 2; }
    DWORD flags = r->secure ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hr = r->openreq(hc, r->verbW, r->pathW, NULL,
                              WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hr) { r->close(hc); r->close(hs); return 3; }
    int rc = 0;
    if (!r->send(hr, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) rc = 4;
    else if (!r->recv(hr, NULL)) rc = 5;
    r->close(hr); r->close(hc); r->close(hs);
    return rc;
}

typedef struct { Req* r; int per; volatile LONG* fails; } WArg;
static unsigned __stdcall worker(void* a) {
    WArg* w = (WArg*) a;
    for (int i = 0; i < w->per; i++)
        if (do_one(w->r)) InterlockedIncrement(w->fails);
    return 0;
}

static int resolve(HMODULE wh, Req* r) {
    r->open    = (pOpen)    (void*) GetProcAddress(wh, "WinHttpOpen");
    r->connect = (pConnect) (void*) GetProcAddress(wh, "WinHttpConnect");
    r->openreq = (pOpenReq) (void*) GetProcAddress(wh, "WinHttpOpenRequest");
    r->send    = (pSend)    (void*) GetProcAddress(wh, "WinHttpSendRequest");
    r->recv    = (pRecv)    (void*) GetProcAddress(wh, "WinHttpReceiveResponse");
    r->close   = (pClose)   (void*) GetProcAddress(wh, "WinHttpCloseHandle");
    r->setopt  = (pSetOpt)  (void*) GetProcAddress(wh, "WinHttpSetOption");
    return r->open && r->connect && r->openreq && r->send && r->recv && r->close;
}

int main(int argc, char** argv) {
    if (argc < 3) { fprintf(stderr, "usage: host_winhttp <fragment_dll> <url> [mode] [a] [b]\n"); return 64; }
    const char* dll  = argv[1];
    const char* url  = argv[2];
    const char* mode = argc > 3 ? argv[3] : "";

    Req r; memset(&r, 0, sizeof(r));
    r.verbW = L"GET";
    r.access = WINHTTP_ACCESS_TYPE_NO_PROXY;

    int bare  = !strcmp(mode, "bare");
    int swept = !strcmp(mode, "swept");
    HMODULE wh = NULL, frag = NULL;
    if (swept)      { wh = LoadLibraryW(L"winhttp.dll"); frag = LoadLibraryA(dll); }
    else if (bare)  { wh = LoadLibraryW(L"winhttp.dll"); }
    else            { frag = LoadLibraryA(dll); wh = LoadLibraryW(L"winhttp.dll"); }

    if (!bare && !frag) { fprintf(stderr, "LoadLibrary(%s) failed %lu\n", dll, GetLastError()); return 65; }
    if (!wh)            { fprintf(stderr, "LoadLibrary(winhttp.dll) failed %lu\n", GetLastError()); return 66; }
    if (!resolve(wh, &r)) { fprintf(stderr, "WinHTTP export resolve failed\n"); return 67; }

    char host[256], path[2048];
    if (!parse_url(url, &r.secure, host, sizeof host, &r.port, path, sizeof path)) {
        fprintf(stderr, "bad url: %s\n", url); return 68;
    }
    A2W(host, r.hostW, 256);
    A2W(path, r.pathW, 2048);

    if (!strcmp(mode, "post")) r.verbW = L"POST";
    if (!strcmp(mode, "appproxy")) {
        r.access = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
        if (argc > 4) A2W(argv[4], r.proxyW, 256);
    }
    if (!strcmp(mode, "setoptproxy")) {
        r.setopt_proxy = 1;
        A2W(argc > 4 ? argv[4] : "127.0.0.1:9999", r.setoptProxyW, 256);
    }

    printf("host_winhttp: mode=%s url=%s secure=%d host=%ls port=%u path=%ls\n",
           mode[0] ? mode : "(default)", url, r.secure, r.hostW, (unsigned) r.port, r.pathW);

    if (!strcmp(mode, "stress")) {
        int T = argc > 4 ? atoi(argv[4]) : 4, PER = argc > 5 ? atoi(argv[5]) : 50;
        if (T < 1) T = 1; if (T > 64) T = 64;
        HANDLE th[64]; WArg wa; volatile LONG fails = 0;
        wa.r = &r; wa.per = PER; wa.fails = &fails;
        for (int i = 0; i < T; i++) th[i] = (HANDLE) _beginthreadex(NULL, 0, worker, &wa, 0, NULL);
        for (int i = 0; i < T; i++) if (th[i]) { WaitForSingleObject(th[i], INFINITE); CloseHandle(th[i]); }
        printf("stress: %dx%d done, fails=%ld\n", T, PER, (long) fails);
        return fails ? 70 : 0;
    }

    if (!strcmp(mode, "sessiononly")) {
        /* Close ONLY the session handle each cycle. WinHTTP frees the derived
         * connect/request handles internally WITHOUT routing through the hooked
         * WinHttpCloseHandle, so this drives the cascade eviction of the
         * hConnect->origin map (audit fix #1). Every request must still land on
         * the proxy with the rewritten path. */
        int K = argc > 4 ? atoi(argv[4]) : 5;
        if (K < 1) K = 1; if (K > 1000) K = 1000;
        int bad = 0;
        for (int i = 0; i < K; i++) {
            HINTERNET hs = r.open(L"frag-winhttp-test", r.access,
                                  WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
            if (!hs) { bad++; continue; }
            HINTERNET hc = r.connect(hs, r.hostW, r.port, 0);
            if (!hc) { r.close(hs); bad++; continue; }
            DWORD flags = r.secure ? WINHTTP_FLAG_SECURE : 0;
            HINTERNET hr = r.openreq(hc, r.verbW, r.pathW, NULL,
                                     WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
            if (!hr) { r.close(hs); bad++; continue; }
            if (!r.send(hr, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) bad++;
            else if (!r.recv(hr, NULL)) bad++;
            r.close(hs);   /* close ONLY the session; children freed implicitly */
        }
        printf("sessiononly: %d iters, bad=%d\n", K, bad);
        return bad ? 71 : 0;
    }

    int rc = do_one(&r);
    printf("request rc=%d\n", rc);
    return rc;
}
