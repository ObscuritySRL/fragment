/*
 * Transitive-load fixture. This .so links against libcurl (a DT_NEEDED
 * dependency), so when a host dlopens plugin.so the loader maps libcurl as a
 * side effect and resolves plugin.so's curl references against the global scope
 * -- which, under LD_PRELOAD=libfragment.so, binds them to Fragment's
 * interposers. There is no direct curl call in the host at all; this proves a
 * transitively-pulled-in libcurl is still rewritten. plugin_fetch then drives a
 * request so the test can observe whether curl was interposed.
 */
#include <stddef.h>

#define CURLOPT_URL              10002
#define CURLOPT_WRITEFUNCTION    20011
#define CURLOPT_TIMEOUT_MS         155
#define CURLOPT_CONNECTTIMEOUT_MS  156
#define CURLOPT_NOSIGNAL            99
#define CURL_GLOBAL_DEFAULT          3

typedef void* CURL;

extern int  curl_global_init(long);
extern CURL curl_easy_init(void);
extern int  curl_easy_setopt(CURL, int, ...);
extern int  curl_easy_perform(CURL);
extern void curl_easy_cleanup(CURL);

static size_t sink(char* p, size_t s, size_t n, void* u) { (void)p; (void)u; return s * n; }

__attribute__((visibility("default")))
int plugin_fetch(const char* url) {
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
