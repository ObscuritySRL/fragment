/*
 * Driver for the transitive-load coverage test:
 *   host_plugin <Fragment.dll> <plugin.dll> <curl-dir> <url>
 *
 * 1. LoadLibrary(Fragment)  -> registers the loader notification + scans.
 * 2. LoadLibrary(plugin)    -> the loader maps plugin.dll AND its static
 *                              dependency libcurl as a side effect (no curl
 *                              LoadLibrary call). Fragment must still hook it.
 * 3. plugin_fetch(url)      -> drives a request; PASS iff it lands on the proxy.
 */
#include <windows.h>
#include <stdio.h>

typedef int (*fetch_t)(const char*);

int main(int argc, char** argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: host_plugin <Fragment.dll> <plugin.dll> <curl-dir> <url>\n");
        return 2;
    }
    if (!LoadLibraryA(argv[1])) { fprintf(stderr, "[host_plugin] Fragment load failed %lu\n", GetLastError()); return 3; }

    /* Let the loader find libcurl (and its siblings) in the corpus dir when it
     * resolves plugin.dll's static imports. */
    SetDllDirectoryA(argv[3]);
    SetCurrentDirectoryA(argv[3]);

    HMODULE hp = LoadLibraryA(argv[2]);
    if (!hp) { fprintf(stderr, "[host_plugin] plugin load failed %lu\n", GetLastError()); return 4; }

    fetch_t f = (fetch_t)(void*)GetProcAddress(hp, "plugin_fetch");
    if (!f) { fprintf(stderr, "[host_plugin] no plugin_fetch export\n"); return 5; }

    int rc = f(argv[4]);
    printf("[host_plugin] plugin_fetch rc=%d\n", rc);
    return 0;
}
