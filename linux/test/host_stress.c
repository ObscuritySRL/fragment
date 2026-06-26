/*
 * Concurrency stress driver:
 *   LD_PRELOAD=libfragment.so  host_stress <url> <threads> <perThread>
 *
 * Linked against libcurl, interposed by the preloaded Fragment. N threads each
 * issue `perThread` requests concurrently, every one through the interposed
 * curl_easy_setopt (which malloc/free a rewritten URL per call). The Python
 * driver then asserts every request reached the proxy, none leaked to the
 * origin, and no path was double-prefixed -- exercising interposer-time
 * concurrency, BuildProxiedUrl alloc churn, and rewrite idempotency under load.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

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

static const char* g_url;
static int g_per;

static size_t sink(char* p, size_t s, size_t n, void* u) { (void)p; (void)u; return s * n; }

static void* worker(void* arg) {
    (void)arg;
    for (int i = 0; i < g_per; i++) {
        CURL h = curl_easy_init();
        if (!h) continue;
        curl_easy_setopt(h, CURLOPT_URL, g_url);
        curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT_MS, (long)3000);
        curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, (long)5000);
        curl_easy_setopt(h, CURLOPT_NOSIGNAL, (long)1);
        curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, sink);
        curl_easy_perform(h);
        curl_easy_cleanup(h);
    }
    return NULL;
}

int main(int argc, char** argv) {
    if (argc < 4) { fprintf(stderr, "usage: host_stress <url> <threads> <per>\n"); return 2; }
    g_url = argv[1];
    int threads = atoi(argv[2]); g_per = atoi(argv[3]);
    if (threads < 1) threads = 1;
    if (threads > 256) threads = 256;

    curl_global_init(CURL_GLOBAL_DEFAULT);   /* not thread-safe: call once, up front */

    pthread_t th[256];
    int n = 0;
    for (int i = 0; i < threads; i++)
        if (pthread_create(&th[n], NULL, worker, NULL) == 0) n++;
    for (int i = 0; i < n; i++) pthread_join(th[i], NULL);

    printf("[stress] %d threads x %d requests done\n", n, g_per);
    return 0;
}
