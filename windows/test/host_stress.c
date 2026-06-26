/*
 * Concurrency stress driver:
 *   host_stress <Fragment.dll> <libcurl.dll> <url> <threads> <perThread>
 *
 * One hook is installed (single-threaded, at load). Then N threads each issue
 * `perThread` requests concurrently, every one through the hooked
 * curl_easy_setopt + detour (which malloc/free a rewritten URL per call). The
 * Python driver then asserts every request reached the proxy, none leaked to
 * the origin, and no path was double-prefixed -- exercising detour-time
 * concurrency, BuildProxiedUrl alloc churn, and rewrite idempotency under load.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define CURLOPT_URL              10002
#define CURLOPT_WRITEFUNCTION    20011
#define CURLOPT_TIMEOUT_MS         155
#define CURLOPT_CONNECTTIMEOUT_MS  156
#define CURLOPT_NOSIGNAL            99
#define CURL_GLOBAL_DEFAULT          3

typedef void* CURL;
typedef CURL (*init_t)(void);
typedef int  (*setopt_t)(CURL, int, ...);
typedef int  (*perform_t)(CURL);
typedef void (*cleanup_t)(CURL);
typedef int  (*ginit_t)(long);

static init_t cei; static setopt_t ces; static perform_t cep; static cleanup_t cec;
static const char* g_url; static int g_per;

static size_t sink(char* p, size_t s, size_t n, void* u) { (void)p; (void)u; return s * n; }

static DWORD WINAPI worker(LPVOID arg) {
    (void)arg;
    for (int i = 0; i < g_per; i++) {
        CURL h = cei();
        if (!h) continue;
        ces(h, CURLOPT_URL, g_url);
        ces(h, CURLOPT_CONNECTTIMEOUT_MS, (long)3000);
        ces(h, CURLOPT_TIMEOUT_MS, (long)5000);
        ces(h, CURLOPT_NOSIGNAL, (long)1);
        ces(h, CURLOPT_WRITEFUNCTION, sink);
        cep(h);
        cec(h);
    }
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 6) { fprintf(stderr, "usage: host_stress <Fragment.dll> <curl.dll> <url> <threads> <per>\n"); return 2; }
    if (!LoadLibraryA(argv[1])) { fprintf(stderr, "[stress] Fragment load failed %lu\n", GetLastError()); return 3; }

    char dir[MAX_PATH];
    strncpy(dir, argv[2], MAX_PATH - 1); dir[MAX_PATH - 1] = 0;
    for (char* p = dir + strlen(dir); p >= dir; --p)
        if (*p == '\\' || *p == '/') { *p = 0; break; }
    SetDllDirectoryA(dir);
    SetCurrentDirectoryA(dir);

    HMODULE hc = LoadLibraryA(argv[2]);
    if (!hc) { fprintf(stderr, "[stress] curl load failed %lu\n", GetLastError()); return 4; }

    ginit_t cgi = (ginit_t)(void*)GetProcAddress(hc, "curl_global_init");
    cei = (init_t)(void*)GetProcAddress(hc, "curl_easy_init");
    ces = (setopt_t)(void*)GetProcAddress(hc, "curl_easy_setopt");
    cep = (perform_t)(void*)GetProcAddress(hc, "curl_easy_perform");
    cec = (cleanup_t)(void*)GetProcAddress(hc, "curl_easy_cleanup");
    if (!cei || !ces || !cep) { fprintf(stderr, "[stress] missing curl exports\n"); return 5; }
    if (cgi) cgi(CURL_GLOBAL_DEFAULT);   /* not thread-safe: call once, up front */

    g_url = argv[3];
    int threads = atoi(argv[4]); g_per = atoi(argv[5]);
    if (threads < 1) threads = 1;
    if (threads > 256) threads = 256;

    HANDLE th[256];
    int n = 0;
    for (int i = 0; i < threads; i++) {
        th[n] = CreateThread(NULL, 0, worker, NULL, 0, NULL);
        if (th[n]) n++;
    }
    WaitForMultipleObjects(n, th, TRUE, 120000);
    for (int i = 0; i < n; i++) CloseHandle(th[i]);

    printf("[stress] %d threads x %d requests done\n", n, g_per);
    return 0;
}
