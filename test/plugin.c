/*
 * Transitive-load fixture. This DLL STATICALLY imports libcurl (via a
 * generated import library), so the Windows loader maps libcurl automatically
 * as a dependency the instant plugin.dll itself is loaded -- there is NO
 * LoadLibrary call for curl anywhere. The old "hook LoadLibraryA/W" approach
 * cannot see this load; only a loader-level notification can. plugin_fetch
 * then drives a request so the test can observe whether curl was hooked.
 */
#include <windows.h>

#define CURLOPT_URL              10002
#define CURLOPT_WRITEFUNCTION    20011
#define CURLOPT_TIMEOUT_MS         155
#define CURLOPT_CONNECTTIMEOUT_MS  156
#define CURLOPT_NOSIGNAL            99
#define CURL_GLOBAL_DEFAULT          3

typedef void* CURL;

/* Resolved at link time from the import library => libcurl is a static
 * dependency recorded in plugin.dll's import table. */
extern long  curl_global_init(long);
extern CURL  curl_easy_init(void);
extern int   curl_easy_setopt(CURL, int, ...);
extern int   curl_easy_perform(CURL);
extern void  curl_easy_cleanup(CURL);

static size_t sink(char* p, size_t s, size_t n, void* u) { (void)p; (void)u; return s * n; }

__declspec(dllexport) int plugin_fetch(const char* url) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL h = curl_easy_init();
    if (!h) return -1;
    curl_easy_setopt(h, CURLOPT_URL, url);
    curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT_MS, (long)3000);
    curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, (long)5000);
    curl_easy_setopt(h, CURLOPT_NOSIGNAL, (long)1);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, sink);
    int rc = curl_easy_perform(h);
    curl_easy_cleanup(h);
    return rc;
}

BOOL APIENTRY DllMain(HINSTANCE h, DWORD reason, LPVOID l) {
    (void)h; (void)reason; (void)l;
    return TRUE;
}
