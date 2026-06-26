/* Test host for the symbol-interposition path.
 *
 *   host <url> [port] [dlopen] [loop:N:MS]
 *
 * Linked against libcurl and run under LD_PRELOAD=libfragment.so (or the
 * fragment launcher): the program's curl_easy_* calls go through the PLT, which
 * the preloaded library interposes. If the hook + rewrite works the request
 * lands on the proxy port (9020); otherwise on the origin port (9999). The
 * Python driver decides PASS/FAIL purely from which port received the request.
 *
 * Modes:
 *   port          also set CURLOPT_PORT (a port-based bypass attempt)
 *   dlopen        reach libcurl via dlopen + dlsym pointers instead of the link
 *                 (exercises the dlopen-interposer inline-hook path)
 *   loop:N:MS     issue N requests MS ms apart (used by the --pid injection test:
 *                 the early ones precede injection, the later ones follow it)
 *
 * curl option ids are part of libcurl's stable ABI and identical on every
 * version, so hardcoding the numbers is safe.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>

#define CURLOPT_PORT                 3
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

/* Linked entry points (resolved via -lcurl; the calls go through the PLT, so a
 * preloaded library shadows them). */
extern int  curl_global_init(long);
extern CURL curl_easy_init(void);
extern int  curl_easy_setopt(CURL, int, ...);
extern int  curl_easy_perform(CURL);
extern void curl_easy_cleanup(CURL);

static size_t sink(char* p, size_t s, size_t n, void* u) { (void)p; (void)u; return s * n; }

static int do_one(init_t ci, setopt_t cs, perform_t cp, cleanup_t cc, const char* url, int setPort) {
    CURL h = ci();
    if (!h) return -1;
    cs(h, CURLOPT_URL, url);
    if (setPort) cs(h, CURLOPT_PORT, (long)9999);   /* attempt a port-based bypass */
    cs(h, CURLOPT_CONNECTTIMEOUT_MS, (long)3000);
    cs(h, CURLOPT_TIMEOUT_MS, (long)5000);
    cs(h, CURLOPT_NOSIGNAL, (long)1);
    cs(h, CURLOPT_WRITEFUNCTION, sink);
    int rc = cp(h);
    cc(h);
    return rc;
}

int main(int argc, char** argv) {
    if (argc < 2) { fprintf(stderr, "usage: host <url> [port] [dlopen] [loop:N:MS]\n"); return 2; }
    const char* url = argv[1];
    int setPort = 0, useDlopen = 0, loopN = 0, loopMs = 0;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "port")) setPort = 1;
        else if (!strcmp(argv[i], "dlopen")) useDlopen = 1;
        else if (!strncmp(argv[i], "loop:", 5)) sscanf(argv[i] + 5, "%d:%d", &loopN, &loopMs);
    }

    init_t ci; setopt_t cs; perform_t cp; cleanup_t cc; ginit_t cg;
    if (useDlopen) {
        /* Reach libcurl only through dlsym pointers -- interposition cannot see
         * these calls, so they are caught (if at all) by the dlopen interposer
         * inline-hooking the resolved function. */
        void* lib = dlopen("libcurl.so.4", RTLD_NOW | RTLD_GLOBAL);
        if (!lib) { fprintf(stderr, "[host] dlopen libcurl failed: %s\n", dlerror()); return 4; }
        cg = (ginit_t)   dlsym(lib, "curl_global_init");
        ci = (init_t)    dlsym(lib, "curl_easy_init");
        cs = (setopt_t)  dlsym(lib, "curl_easy_setopt");
        cp = (perform_t) dlsym(lib, "curl_easy_perform");
        cc = (cleanup_t) dlsym(lib, "curl_easy_cleanup");
    } else {
        cg = curl_global_init; ci = curl_easy_init; cs = (setopt_t) curl_easy_setopt;
        cp = curl_easy_perform; cc = curl_easy_cleanup;
    }
    if (!ci || !cs || !cp || !cc) { fprintf(stderr, "[host] missing curl functions\n"); return 5; }
    if (cg) cg(CURL_GLOBAL_DEFAULT);

    if (loopN > 0) {
        for (int i = 0; i < loopN; i++) {
            int rc = do_one(ci, cs, cp, cc, url, setPort);
            printf("[host] loop %d perform rc=%d\n", i, rc);
            fflush(stdout);
            if (loopMs) usleep((useconds_t)loopMs * 1000);
        }
    } else {
        int rc = do_one(ci, cs, cp, cc, url, setPort);
        printf("[host] perform rc=%d\n", rc);
    }
    return 0;
}
