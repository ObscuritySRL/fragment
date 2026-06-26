/*
 * Self-contained integration test (no servers, no real libcurl):
 *   LD_PRELOAD=libfragment.so  host_mock
 *
 * Links against the mock libcurl and runs under the preloaded Fragment, which
 * interposes the mock's exported curl_easy_setopt. It asserts the interposer's
 * behaviour directly from what the mock received AFTER the rewrite ran:
 *   1. CURLOPT_URL is rewritten to the proxy prefix.
 *   2. Re-setting an already-proxied URL does NOT double-prefix (idempotent).
 *   3. CURLOPT_RESOLVE is dropped (mock receives NULL).
 *   4. CURLOPT_PROXY is forced to "" (direct), NOT NULL.
 *   5. CURLOPT_UNIX_SOCKET_PATH / ABSTRACT are dropped (NULL).
 *   6. CURLOPT_PORT is dropped (mock receives 0).
 * Exit 0 = all pass. Run with the FRAGMENT_* environment cleared so the default
 * proxy prefix (http://127.0.0.1:9020/) is in force.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define CURLOPT_PORT              3
#define CURLOPT_URL           10002
#define CURLOPT_PROXY         10004
#define CURLOPT_RESOLVE       10203
#define CURLOPT_UNIX_SOCKET_PATH     10231
#define CURLOPT_ABSTRACT_UNIX_SOCKET 10264

extern void*       curl_easy_init(void);
extern int         curl_easy_setopt(void*, int, ...);
extern const char* mock_last_url(void);
extern void*       mock_last_resolve(void);
extern void*       mock_last_proxy(void);
extern void*       mock_last_unix(void);
extern void*       mock_last_abstract(void);
extern long        mock_last_port(void);

static int fails = 0;
#define CHECK(cond, ...) do { if (cond) { printf("  ok:   " __VA_ARGS__); } \
                              else { printf("  FAIL: " __VA_ARGS__); fails++; } printf("\n"); } while (0)

int main(void) {
    const char* PREFIX = "http://127.0.0.1:9020/";   /* the default prefix */
    void* h = curl_easy_init();

    /* 1. rewrite */
    const char* orig = "http://127.0.0.1:9999/probe";
    char expected[4096];
    snprintf(expected, sizeof(expected), "%s%s", PREFIX, orig);
    curl_easy_setopt(h, CURLOPT_URL, orig);
    CHECK(strcmp(mock_last_url(), expected) == 0, "CURLOPT_URL rewritten to proxy (got '%s')", mock_last_url());

    /* 2. idempotency: re-setting the already-proxied URL must not double-prefix */
    curl_easy_setopt(h, CURLOPT_URL, expected);
    CHECK(strcmp(mock_last_url(), expected) == 0, "already-proxied URL not double-prefixed (got '%s')", mock_last_url());

    /* 3. CURLOPT_RESOLVE dropped (mock must receive NULL) */
    curl_easy_setopt(h, CURLOPT_RESOLVE, (void*)(uintptr_t)0x1234ABCD);
    CHECK(mock_last_resolve() == NULL, "CURLOPT_RESOLVE dropped (got %p)", mock_last_resolve());

    /* 4. CURLOPT_PROXY forced to direct "" (NOT NULL, which would fall back to
     *    the http_proxy env var). */
    curl_easy_setopt(h, CURLOPT_PROXY, "http://10.0.0.1:8080");
    CHECK(mock_last_proxy() != NULL && strcmp((const char*)mock_last_proxy(), "") == 0,
          "CURLOPT_PROXY forced to direct \"\" (got %p)", mock_last_proxy());

    /* 5. CURLOPT_UNIX_SOCKET_PATH / ABSTRACT dropped (mock must receive NULL) */
    curl_easy_setopt(h, CURLOPT_UNIX_SOCKET_PATH, "/var/run/docker.sock");
    CHECK(mock_last_unix() == NULL, "CURLOPT_UNIX_SOCKET_PATH dropped (got %p)", mock_last_unix());
    curl_easy_setopt(h, CURLOPT_ABSTRACT_UNIX_SOCKET, "fragment-abstract");
    CHECK(mock_last_abstract() == NULL, "CURLOPT_ABSTRACT_UNIX_SOCKET dropped (got %p)", mock_last_abstract());

    /* 6. CURLOPT_PORT dropped (mock must receive 0) */
    curl_easy_setopt(h, CURLOPT_PORT, (long)8443);
    CHECK(mock_last_port() == 0, "CURLOPT_PORT dropped (got %ld)", mock_last_port());

    printf(fails ? "\nMOCK INTEGRATION FAILED (%d)\n" : "\nMOCK INTEGRATION OK\n", fails);
    return fails ? 1 : 0;
}
