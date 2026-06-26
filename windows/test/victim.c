/* Passive injection target for the cross-bitness end-to-end test. It loads the
 * mock libcurl and issues curl_easy_setopt(CURLOPT_URL, ...) in a loop, then
 * reports whether the URL came back rewritten. Crucially it NEVER loads
 * Fragment itself -- so a rewrite proves the DLL was INJECTED into this process
 * and hooked the (later) mock load.
 *
 *   victim <mock-dll> [url]
 *
 * Exit 0 = a request was rewritten to the proxy prefix (injection worked);
 * exit 1 = the URL never changed within the window (also the non-vacuous
 * negative control: run un-injected, it must report 1). The loop models the
 * inject-into-a-running-process reality -- a request made AFTER the hook lands
 * is rewritten, exactly as the ptrace mid-flight injection asserts on Linux.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define CURLOPT_URL 10002

typedef void*       (*init_fn)(void);
typedef int         (*setopt_fn)(void*, int, ...);
typedef const char* (*lasturl_fn)(void);

int main(int argc, char** argv) {
    const char* mock = argc > 1 ? argv[1] : "mockcurl.dll";
    const char* url  = argc > 2 ? argv[2] : "http://127.0.0.1:9999/marker";

    HMODULE h = LoadLibraryA(mock);
    if (!h) { fprintf(stderr, "victim: LoadLibrary(%s) failed %lu\n", mock, GetLastError()); return 2; }
    init_fn    init    = (init_fn)   (void*) GetProcAddress(h, "curl_easy_init");
    setopt_fn  setopt  = (setopt_fn) (void*) GetProcAddress(h, "curl_easy_setopt");
    lasturl_fn lasturl = (lasturl_fn)(void*) GetProcAddress(h, "mock_last_url");
    if (!init || !setopt || !lasturl) { fprintf(stderr, "victim: missing mock exports\n"); return 2; }

    void* c = init();
    for (int i = 0; i < 100; i++) {           /* ~5s; injection lands during the target's startup */
        setopt(c, CURLOPT_URL, url);
        const char* got = lasturl();
        if (got && strncmp(got, "http://127.0.0.1:9020/", 22) == 0) {
            printf("victim: rewritten -> %s (iter %d)\n", got, i);
            return 0;
        }
        Sleep(50);
    }
    printf("victim: NOT rewritten (last=%s)\n", lasturl());
    return 1;
}
