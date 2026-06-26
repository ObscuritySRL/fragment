/* Test host for the curl_url (URL-API) path.
 *
 *   host_urlapi <full|parts> <origin-url> [marker]
 *
 * Linked against libcurl, run under LD_PRELOAD=libfragment.so.
 *
 * "full"  : curl_url_set(uh, CURLUPART_URL, origin-url, 0)   -> exercises the
 *           interposed curl_url_set.
 * "parts" : build the URL piecewise (SCHEME/HOST/PORT/PATH) and never set
 *           CURLUPART_URL -> exercises the CURLOPT_CURLU read-back rewrite.
 *
 * Then curl_easy_setopt(h, CURLOPT_CURLU, uh) + perform. PASS iff the request
 * lands on the proxy port with the rewritten path.
 */
#define _GNU_SOURCE
#include <stdio.h>
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

extern int    curl_global_init(long);
extern CURLU  curl_url(void);
extern int    curl_url_set(CURLU, int, const char*, unsigned int);
extern void   curl_url_cleanup(CURLU);
extern CURL   curl_easy_init(void);
extern int    curl_easy_setopt(CURL, int, ...);
extern int    curl_easy_perform(CURL);
extern void   curl_easy_cleanup(CURL);

static size_t sink(char* p, size_t s, size_t n, void* u) { (void)p; (void)u; return s * n; }

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: host_urlapi <full|parts> <url> [marker]\n");
        return 2;
    }
    const char* mode = argv[1];
    const char* url = argv[2];
    const char* marker = (argc > 3) ? argv[3] : "ORIG";

    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURLU uh = curl_url();
    if (!uh) { fprintf(stderr, "[host] curl_url() NULL\n"); return 6; }

    if (strcmp(mode, "parts") == 0) {
        char path[256];
        snprintf(path, sizeof(path), "/%s", marker);
        curl_url_set(uh, CURLUPART_SCHEME, "http", 0);
        curl_url_set(uh, CURLUPART_HOST, "127.0.0.1", 0);
        curl_url_set(uh, CURLUPART_PORT, "9999", 0);
        curl_url_set(uh, CURLUPART_PATH, path, 0);
    } else {
        curl_url_set(uh, CURLUPART_URL, url, 0);
    }

    CURL h = curl_easy_init();
    curl_easy_setopt(h, CURLOPT_CURLU, uh);
    curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT_MS, (long)3000);
    curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, (long)5000);
    curl_easy_setopt(h, CURLOPT_NOSIGNAL, (long)1);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, sink);

    int rc = curl_easy_perform(h);
    printf("[host] urlapi(%s) perform rc=%d\n", mode, rc);

    curl_easy_cleanup(h);
    curl_url_cleanup(uh);
    return 0;
}
