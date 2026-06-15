/* Test host for the curl_url (URL-API) path.
 *
 *   host_urlapi <Fragment.dll> <libcurl.dll> <full|parts> <origin-url> [marker]
 *
 * "full"  : curl_url_set(uh, CURLUPART_URL, origin-url, 0)   -> exercises
 *           the curl_url_set hook.
 * "parts" : build the URL piecewise (SCHEME/HOST/PORT/PATH) and never set
 *           CURLUPART_URL -> exercises the CURLOPT_CURLU read-back rewrite.
 *
 * Then curl_easy_setopt(h, CURLOPT_CURLU, uh) + perform. PASS iff the
 * request lands on the proxy port with the rewritten path.
 */
#include <stdio.h>
#include <windows.h>
#include <string.h>

#define CURLOPT_URL              10002
#define CURLOPT_CURLU            10282
#define CURLOPT_WRITEFUNCTION    20011
#define CURLOPT_TIMEOUT_MS         155
#define CURLOPT_CONNECTTIMEOUT_MS  156
#define CURLOPT_NOSIGNAL            99
#define CURL_GLOBAL_DEFAULT          3

#define CURLUPART_URL    0
#define CURLUPART_SCHEME 1
#define CURLUPART_HOST   5
#define CURLUPART_PORT   6
#define CURLUPART_PATH   7

typedef void* CURL;
typedef void* CURLU;
typedef int   CURLcode;
typedef int   CURLUcode;
typedef CURLU    (*curl_url_t)(void);
typedef CURLUcode(*curl_url_set_t)(CURLU, int, const char*, unsigned int);
typedef void     (*curl_url_cleanup_t)(CURLU);
typedef CURL     (*curl_easy_init_t)(void);
typedef CURLcode (*curl_easy_setopt_t)(CURL, int, ...);
typedef CURLcode (*curl_easy_perform_t)(CURL);
typedef void     (*curl_easy_cleanup_t)(CURL);
typedef CURLcode (*curl_global_init_t)(long);

static size_t sink(char *p, size_t s, size_t n, void *u) { (void)p;(void)u; return s*n; }

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: host_urlapi <Fragment.dll> <libcurl.dll> <full|parts> <url> [marker]\n");
        return 2;
    }
    const char *fragPath = argv[1], *curlPath = argv[2], *mode = argv[3], *url = argv[4];
    const char *marker = (argc > 5) ? argv[5] : "ORIG";

    if (!LoadLibraryA(fragPath)) { fprintf(stderr, "[host] Fragment load failed %lu\n", GetLastError()); return 3; }

    char dir[MAX_PATH];
    strncpy(dir, curlPath, sizeof(dir) - 1); dir[sizeof(dir) - 1] = 0;
    for (char *p = dir + strlen(dir); p >= dir; --p)
        if (*p == '\\' || *p == '/') { *p = 0; break; }
    SetDllDirectoryA(dir);
    SetCurrentDirectoryA(dir);

    HMODULE hc = LoadLibraryA(curlPath);
    if (!hc) { fprintf(stderr, "[host] curl load failed %lu\n", GetLastError()); return 4; }

    curl_global_init_t  cgi = (curl_global_init_t) (void*)GetProcAddress(hc, "curl_global_init");
    curl_url_t          cu  = (curl_url_t)         (void*)GetProcAddress(hc, "curl_url");
    curl_url_set_t      cus = (curl_url_set_t)     (void*)GetProcAddress(hc, "curl_url_set");
    curl_url_cleanup_t  cuc = (curl_url_cleanup_t) (void*)GetProcAddress(hc, "curl_url_cleanup");
    curl_easy_init_t    cei = (curl_easy_init_t)   (void*)GetProcAddress(hc, "curl_easy_init");
    curl_easy_setopt_t  ces = (curl_easy_setopt_t) (void*)GetProcAddress(hc, "curl_easy_setopt");
    curl_easy_perform_t cep = (curl_easy_perform_t)(void*)GetProcAddress(hc, "curl_easy_perform");
    curl_easy_cleanup_t cec = (curl_easy_cleanup_t)(void*)GetProcAddress(hc, "curl_easy_cleanup");
    if (!cu || !cus || !cei || !ces || !cep) { fprintf(stderr, "[host] no URL-API in this libcurl\n"); return 5; }

    if (cgi) cgi(CURL_GLOBAL_DEFAULT);
    CURLU uh = cu();
    if (!uh) { fprintf(stderr, "[host] curl_url() NULL\n"); return 6; }

    if (strcmp(mode, "parts") == 0) {
        char path[256];
        _snprintf(path, sizeof(path), "/%s", marker);
        cus(uh, CURLUPART_SCHEME, "http", 0);
        cus(uh, CURLUPART_HOST, "127.0.0.1", 0);
        cus(uh, CURLUPART_PORT, "9999", 0);
        cus(uh, CURLUPART_PATH, path, 0);
    } else {
        cus(uh, CURLUPART_URL, url, 0);
    }

    CURL h = cei();
    ces(h, CURLOPT_CURLU, uh);
    ces(h, CURLOPT_CONNECTTIMEOUT_MS, (long)3000);
    ces(h, CURLOPT_TIMEOUT_MS, (long)5000);
    ces(h, CURLOPT_NOSIGNAL, (long)1);
    ces(h, CURLOPT_WRITEFUNCTION, sink);

    CURLcode rc = cep(h);
    printf("[host] urlapi(%s) perform rc=%d\n", mode, (int)rc);

    if (cec) cec(h);
    if (cuc) cuc(uh);
    return 0;
}
