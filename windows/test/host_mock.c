/*
 * Self-contained integration test (no servers, no real libcurl):
 *   host_mock <Fragment.dll> <mockcurl.dll>
 *
 * Loads Fragment, then the mock libcurl (Fragment hooks its exported
 * curl_easy_setopt), and asserts the detour's behaviour directly from what the
 * mock received AFTER the hook ran:
 *   1. CURLOPT_URL is rewritten to the proxy prefix.
 *   2. Re-setting an already-proxied URL does NOT double-prefix (idempotent).
 *   3. CURLOPT_RESOLVE is dropped (mock receives NULL).
 *   4. CURLOPT_PORT is dropped (mock receives 0).
 * Exit 0 = all pass. This proves the export-resolution + setopt rewrite/drop
 * path on a clean machine (e.g. in CI), complementing the engine unit test
 * (which proves prologue relocation) and the real-libcurl matrix (run locally).
 *
 * Uses the default proxy prefix; run with the FRAGMENT_* environment cleared.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define CURLOPT_PORT              3
#define CURLOPT_URL           10002
#define CURLOPT_PROXY         10004
#define CURLOPT_RESOLVE       10203
#define CURLOPT_UNIX_SOCKET_PATH     10231
#define CURLOPT_ABSTRACT_UNIX_SOCKET 10264

typedef void*       (*init_t)(void);
typedef int         (*setopt_t)(void*, int, ...);
typedef const char* (*lasturl_t)(void);
typedef void*       (*lastptr_t)(void);
typedef long        (*lastport_t)(void);

static int fails = 0;
#define CHECK(cond, ...) do { if (cond) { printf("  ok:   " __VA_ARGS__); } \
                              else { printf("  FAIL: " __VA_ARGS__); fails++; } printf("\n"); } while (0)

int main(int argc, char** argv) {
    if (argc < 3) { fprintf(stderr, "usage: host_mock <Fragment.dll> <mockcurl.dll>\n"); return 2; }
    const char* PREFIX = "http://127.0.0.1:9020/";   /* the default prefix */

    /* Self-hermetic: clear the config env that would change the asserted
     * behaviour, so the test is deterministic however it is launched (CI runs
     * it directly, not through run.py's hermetic env). Fragment reads config
     * once in DllMain, so clearing before the load below suffices. */
    SetEnvironmentVariableA("FRAGMENT_PROXY", NULL);
    SetEnvironmentVariableA("FRAGMENT_PROXY_HOST", NULL);
    SetEnvironmentVariableA("FRAGMENT_PROXY_PORT", NULL);
    SetEnvironmentVariableA("FRAGMENT_ENABLED", NULL);
    SetEnvironmentVariableA("FRAGMENT_DISABLE", NULL);

    if (!LoadLibraryA(argv[1])) { fprintf(stderr, "[host_mock] Fragment load failed %lu\n", GetLastError()); return 3; }
    HMODULE m = LoadLibraryA(argv[2]);
    if (!m) { fprintf(stderr, "[host_mock] mockcurl load failed %lu\n", GetLastError()); return 4; }

    init_t      init    = (init_t)    (void*)GetProcAddress(m, "curl_easy_init");
    setopt_t    setopt  = (setopt_t)  (void*)GetProcAddress(m, "curl_easy_setopt");
    lasturl_t   lastUrl = (lasturl_t) (void*)GetProcAddress(m, "mock_last_url");
    lastptr_t   lastRes = (lastptr_t) (void*)GetProcAddress(m, "mock_last_resolve");
    lastptr_t   lastProxy= (lastptr_t)(void*)GetProcAddress(m, "mock_last_proxy");
    lastptr_t   lastUnix= (lastptr_t)(void*)GetProcAddress(m, "mock_last_unix");
    lastptr_t   lastAbs = (lastptr_t)(void*)GetProcAddress(m, "mock_last_abstract");
    lastport_t  lastPort= (lastport_t)(void*)GetProcAddress(m, "mock_last_port");
    if (!init || !setopt || !lastUrl || !lastRes || !lastProxy || !lastUnix || !lastAbs || !lastPort) { fprintf(stderr, "[host_mock] missing mock exports\n"); return 5; }

    void* h = init();

    /* 1. rewrite */
    const char* orig = "http://127.0.0.1:9999/probe";
    char expected[4096];
    _snprintf_s(expected, sizeof(expected), _TRUNCATE, "%s%s", PREFIX, orig);
    setopt(h, CURLOPT_URL, orig);
    CHECK(strcmp(lastUrl(), expected) == 0, "CURLOPT_URL rewritten to proxy (got '%s')", lastUrl());

    /* 2. idempotency: re-setting the already-proxied URL must not double-prefix */
    setopt(h, CURLOPT_URL, expected);
    CHECK(strcmp(lastUrl(), expected) == 0, "already-proxied URL not double-prefixed (got '%s')", lastUrl());

    /* 3. CURLOPT_RESOLVE dropped (mock must receive NULL) */
    setopt(h, CURLOPT_RESOLVE, (void*)(UINT_PTR)0x1234ABCD);
    CHECK(lastRes() == NULL, "CURLOPT_RESOLVE dropped (got %p)", lastRes());

    /* 4. CURLOPT_PROXY forced to "" (an upstream proxy would carry the rewritten
     *    request off-box). It must be the empty string, NOT NULL: NULL is curl's
     *    default that falls back to the http_proxy env var, whereas "" forces a
     *    direct connection and suppresses that env var. */
    setopt(h, CURLOPT_PROXY, "http://10.0.0.1:8080");
    CHECK(lastProxy() != NULL && strcmp((const char*)lastProxy(), "") == 0,
          "CURLOPT_PROXY forced to direct \"\" (got %p)", lastProxy());

    /* 5. CURLOPT_UNIX_SOCKET_PATH dropped (a local socket would replace the TCP
     *    path to our proxy; mock must receive NULL) */
    setopt(h, CURLOPT_UNIX_SOCKET_PATH, "/var/run/docker.sock");
    CHECK(lastUnix() == NULL, "CURLOPT_UNIX_SOCKET_PATH dropped (got %p)", lastUnix());
    setopt(h, CURLOPT_ABSTRACT_UNIX_SOCKET, "fragment-abstract");
    CHECK(lastAbs() == NULL, "CURLOPT_ABSTRACT_UNIX_SOCKET dropped (got %p)", lastAbs());

    /* 6. CURLOPT_PORT dropped (mock must receive 0) */
    setopt(h, CURLOPT_PORT, (long)8443);
    CHECK(lastPort() == 0, "CURLOPT_PORT dropped (got %ld)", lastPort());

    printf(fails ? "\nMOCK INTEGRATION FAILED (%d)\n" : "\nMOCK INTEGRATION OK\n", fails);
    return fails ? 1 : 0;
}
