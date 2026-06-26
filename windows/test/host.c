/* Test host for the DLL-export path.
 *
 * Mirrors the real "injected" flow without a separate injector:
 *   1. LoadLibrary(Fragment.dll)  -> DllMain installs LoadLibraryA/W detours
 *                                    and scans already-loaded modules.
 *   2. LoadLibrary(libcurl.dll)   -> our LoadLibraryA detour fires -> HookCurl().
 *   3. Resolve curl_easy_* and perform a request to a localhost URL.
 *
 * If the hook + rewrite works the request lands on the proxy port (9020);
 * otherwise it lands on the origin port (9999). The Python driver decides
 * PASS/FAIL purely from which port received the request.
 *
 * curl option ids are part of libcurl's stable ABI and identical on every
 * version since well before 7.30, so hardcoding the numbers is safe.
 */
#include <stdio.h>
#include <windows.h>

#define CURLOPT_PORT                 3
#define CURLOPT_URL              10002
#define CURLOPT_WRITEFUNCTION    20011
#define CURLOPT_TIMEOUT_MS         155
#define CURLOPT_CONNECTTIMEOUT_MS  156
#define CURLOPT_NOSIGNAL            99
#define CURL_GLOBAL_DEFAULT          3

typedef void* CURL;
typedef int   CURLcode;
typedef CURL     (*curl_easy_init_t)(void);
typedef CURLcode (*curl_easy_setopt_t)(CURL, int, ...);
typedef CURLcode (*curl_easy_perform_t)(CURL);
typedef void     (*curl_easy_cleanup_t)(CURL);
typedef CURLcode (*curl_global_init_t)(long);

static size_t sink(char *p, size_t s, size_t n, void *u) {
    (void)p; (void)u;
    return s * n;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: host <Fragment.dll> <libcurl.dll> [url]\n");
        return 2;
    }
    const char *fragPath = argv[1];
    const char *curlPath = argv[2];
    const char *url = (argc > 3) ? argv[3] : "http://127.0.0.1:9999/ORIG";

    int noinject = 0, setPort = 0, useLdrEx = 0;
    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "--noinject") == 0) noinject = 1;
        if (strcmp(argv[i], "port") == 0) setPort = 1;
        if (strcmp(argv[i], "ldrex") == 0) useLdrEx = 1;   /* load curl via LoadLibraryExW */
    }

    if (!noinject) {
        HMODULE hf = LoadLibraryA(fragPath);
        if (!hf) { fprintf(stderr, "[host] LoadLibrary(Fragment) failed %lu\n", GetLastError()); return 3; }
        printf("[host] Fragment loaded @ %p\n", (void*)hf);
    }

    /* Let the curl module find its sibling dependency DLLs (ssl/zlib/etc.)
     * in its own directory, while still going through the hooked
     * LoadLibraryA so the LoadLibrary detour fires. */
    char dir[MAX_PATH];
    strncpy(dir, curlPath, sizeof(dir) - 1);
    dir[sizeof(dir) - 1] = 0;
    for (char *p = dir + strlen(dir); p >= dir; --p) {
        if (*p == '\\' || *p == '/') { *p = 0; break; }
    }
    SetDllDirectoryA(dir);
    SetCurrentDirectoryA(dir);

    HMODULE hc;
    if (useLdrEx) {
        /* A load path the LoadLibraryA/W detours do NOT intercept; only a
         * loader-level notification catches it. */
        wchar_t wpath[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, curlPath, -1, wpath, MAX_PATH);
        hc = LoadLibraryExW(wpath, NULL, 0);
    } else {
        hc = LoadLibraryA(curlPath);
    }
    if (!hc) { fprintf(stderr, "[host] LoadLibrary(curl) failed %lu\n", GetLastError()); return 4; }
    printf("[host] curl loaded @ %p (%s)\n", (void*)hc, curlPath);

    curl_global_init_t  cgi = (curl_global_init_t) (void*)GetProcAddress(hc, "curl_global_init");
    curl_easy_init_t    cei = (curl_easy_init_t)   (void*)GetProcAddress(hc, "curl_easy_init");
    curl_easy_setopt_t  ces = (curl_easy_setopt_t) (void*)GetProcAddress(hc, "curl_easy_setopt");
    curl_easy_perform_t cep = (curl_easy_perform_t)(void*)GetProcAddress(hc, "curl_easy_perform");
    curl_easy_cleanup_t cec = (curl_easy_cleanup_t)(void*)GetProcAddress(hc, "curl_easy_cleanup");
    if (!cei || !ces || !cep) { fprintf(stderr, "[host] missing curl exports\n"); return 5; }

    if (cgi) cgi(CURL_GLOBAL_DEFAULT);
    CURL h = cei();
    if (!h) { fprintf(stderr, "[host] curl_easy_init returned NULL\n"); return 6; }

    ces(h, CURLOPT_URL, url);
    if (setPort) ces(h, CURLOPT_PORT, (long)9999);   // attempt a port-based bypass
    ces(h, CURLOPT_CONNECTTIMEOUT_MS, (long)3000);
    ces(h, CURLOPT_TIMEOUT_MS, (long)5000);
    ces(h, CURLOPT_NOSIGNAL, (long)1);
    ces(h, CURLOPT_WRITEFUNCTION, sink);

    CURLcode rc = cep(h);
    printf("[host] curl_easy_perform rc=%d\n", (int)rc);

    if (cec) cec(h);
    return 0;
}
