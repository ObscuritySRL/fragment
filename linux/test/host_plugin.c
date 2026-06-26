/*
 * Driver for the transitive-load coverage test:
 *   LD_PRELOAD=libfragment.so  host_plugin <plugin.so> <url>
 *
 * 1. dlopen(plugin.so)  -> the loader maps plugin.so AND its DT_NEEDED libcurl,
 *                          resolving the curl references against the global
 *                          scope (which includes the preloaded Fragment).
 * 2. plugin_fetch(url)  -> drives a request; PASS iff it lands on the proxy.
 *
 * The host itself never references libcurl -- only the plugin does -- so this
 * specifically exercises interposition of a transitively pulled-in libcurl.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

typedef int (*fetch_t)(const char*);

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: host_plugin <plugin.so> <url>\n");
        return 2;
    }
    void* hp = dlopen(argv[1], RTLD_NOW | RTLD_GLOBAL);
    if (!hp) { fprintf(stderr, "[host_plugin] dlopen plugin failed: %s\n", dlerror()); return 4; }

    fetch_t f = (fetch_t) dlsym(hp, "plugin_fetch");
    if (!f) { fprintf(stderr, "[host_plugin] no plugin_fetch export\n"); return 5; }

    int rc = f(argv[2]);
    printf("[host_plugin] plugin_fetch rc=%d\n", rc);
    return 0;
}
