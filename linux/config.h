#pragma once

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "log.h"

/*
 * All knobs are read ONCE at load time from the environment, so the very
 * same shipped .so can be pointed at a different proxy, toggled off, or made
 * verbose WITHOUT recompiling. Defaults reproduce the classic behaviour
 * (rewrite every request to http://127.0.0.1:9020/<original-url>).
 *
 *   FRAGMENT_PROXY        full base, e.g. "http://127.0.0.1:9020" or
 *                         "https://10.0.0.5:8888" (scheme/host/port; a
 *                         trailing slash is normalised). Wins if set.
 *   FRAGMENT_PROXY_HOST   host when FRAGMENT_PROXY is unset (default 127.0.0.1)
 *   FRAGMENT_PROXY_PORT   port when FRAGMENT_PROXY is unset (default 9020)
 *   FRAGMENT_ENABLED      0/false/no/off => load but do not rewrite
 *   FRAGMENT_DISABLE      1/true/yes/on  => load but do not rewrite
 *   FRAGMENT_LOG_LEVEL    off|error|warn|info|debug
 *   FRAGMENT_LOG_FILE     path; if unset, logs go to stderr
 *   FRAGMENT_LOG_CONSOLE  1 => also tee logs to stderr when a file is set
 *   FRAGMENT_LOADER       auto|interpose|audit|hook -- which curl-interception
 *                         approach to use (diagnostic / compatibility override;
 *                         default auto = layer them by coverage, degrading
 *                         gracefully).
 */

/* Curl-interception strategy. Fragment catches every way a curl module can be
 * reached by layering independent approaches; this selects which one(s) to use.
 * 'auto' (the default) combines symbol interposition with an inline-hook sweep
 * of any statically-linked curl, so neither a dlopen nor a static link can slip
 * past, and the two never double-process (interposition catches dynamic-symbol
 * curl; the inline hook is applied only where there is no dynamic symbol). */
enum {
    FRAG_LOADER_AUTO = 0,     /* interposition (+ dlsym/dlopen) + static inline-hook sweep */
    FRAG_LOADER_INTERPOSE,    /* only LD_PRELOAD symbol interposition + dlsym/dlopen        */
    FRAG_LOADER_AUDIT,        /* rely on the rtld-audit (LD_AUDIT) rebind; interposers idle */
    FRAG_LOADER_HOOK          /* force inline byte-patch hooking, even for dynamic curl     */
};

typedef struct {
    int    enabled;
    char   proxyPrefix[600];   /* always ends in '/', e.g. http://h:p/ */
    size_t proxyPrefixLen;
    int    loaderMode;         /* one of FRAG_LOADER_*                  */
} FragmentConfig;

static FragmentConfig gCfg;

static int EnvFalsey(const char* v) {
    return v && (!strcasecmp(v, "0") || !strcasecmp(v, "false") ||
                 !strcasecmp(v, "no") || !strcasecmp(v, "off"));
}
static int EnvTruthy(const char* v) {
    return v && (!strcasecmp(v, "1") || !strcasecmp(v, "true") ||
                 !strcasecmp(v, "yes") || !strcasecmp(v, "on"));
}

static int ParseLogLevel(const char* v) {
    if (!v || !*v) return -1;
    if (!strcasecmp(v, "off")   || !strcasecmp(v, "none") || !strcasecmp(v, "0")) return FRAG_LOG_OFF;
    if (!strcasecmp(v, "error") || !strcasecmp(v, "err"))     return FRAG_LOG_ERROR;
    if (!strcasecmp(v, "warn")  || !strcasecmp(v, "warning")) return FRAG_LOG_WARN;
    if (!strcasecmp(v, "info"))                               return FRAG_LOG_INFO;
    if (!strcasecmp(v, "debug") || !strcasecmp(v, "trace") || !strcasecmp(v, "all")) return FRAG_LOG_DEBUG;
    return -1;
}

/* Read an env var into a fixed buffer; out[0]=0 if unset or oversized. */
static void EnvGet(const char* name, char* out, size_t cap) {
    const char* v = getenv(name);
    if (!v) { out[0] = 0; return; }
    size_t n = strlen(v);
    if (n >= cap) { out[0] = 0; return; }
    memcpy(out, v, n + 1);
}

static void ConfigInit(void) {
    char buf[600];

    /* -- diagnostics FIRST, so any config warning below is visible ------- */
    char lvl[32], file[512], con[32];
    EnvGet("FRAGMENT_LOG_LEVEL", lvl, sizeof(lvl));
    EnvGet("FRAGMENT_LOG_FILE", file, sizeof(file));
    EnvGet("FRAGMENT_LOG_CONSOLE", con, sizeof(con));
    int level = ParseLogLevel(lvl);
    if (level < 0) {
#ifdef DEBUG
        level = FRAG_LOG_DEBUG;                 /* dev builds stay chatty */
#else
        level = (file[0] || EnvTruthy(con)) ? FRAG_LOG_INFO : FRAG_LOG_OFF;
#endif
    }
    LogOpen(level, file, EnvTruthy(con));

    /* -- enabled? (FRAGMENT_DISABLE overrides FRAGMENT_ENABLED) ----------- */
    gCfg.enabled = 1;
    EnvGet("FRAGMENT_ENABLED", buf, sizeof(buf));
    if (buf[0] && EnvFalsey(buf)) gCfg.enabled = 0;
    EnvGet("FRAGMENT_DISABLE", buf, sizeof(buf));
    if (buf[0] && EnvTruthy(buf)) gCfg.enabled = 0;

    /* -- curl-interception strategy -------------------------------------- */
    char ldr[32];
    EnvGet("FRAGMENT_LOADER", ldr, sizeof(ldr));
    gCfg.loaderMode = FRAG_LOADER_AUTO;
    if      (!strcasecmp(ldr, "interpose") || !strcasecmp(ldr, "preload")) gCfg.loaderMode = FRAG_LOADER_INTERPOSE;
    else if (!strcasecmp(ldr, "audit")     || !strcasecmp(ldr, "rtld"))    gCfg.loaderMode = FRAG_LOADER_AUDIT;
    else if (!strcasecmp(ldr, "hook")      || !strcasecmp(ldr, "inline"))  gCfg.loaderMode = FRAG_LOADER_HOOK;
    else if (ldr[0] && strcasecmp(ldr, "auto"))
        LogWarn("[Fragment] unknown FRAGMENT_LOADER=\"%s\"; using auto\n", ldr);

    /* -- proxy base ------------------------------------------------------ */
    char base[560];
    EnvGet("FRAGMENT_PROXY", base, sizeof(base));
    if (!base[0]) {
        char host[256], port[32];
        EnvGet("FRAGMENT_PROXY_HOST", host, sizeof(host));
        EnvGet("FRAGMENT_PROXY_PORT", port, sizeof(port));
        if (!host[0]) strcpy(host, "127.0.0.1");
        if (!port[0]) strcpy(port, "9020");
        snprintf(base, sizeof(base), "http://%s:%s", host, port);
    }
    /* normalise: strip trailing slashes */
    size_t L = strlen(base);
    while (L > 0 && base[L - 1] == '/') base[--L] = 0;
    /* Reject degenerate values (empty / scheme-less). Otherwise a value like
     * "///" would collapse the prefix to "/", which both produces malformed
     * URLs AND makes the idempotency guard swallow every '/'-leading string
     * (silently disabling rewriting). Fall back to the default instead. */
    if (!base[0] || !strstr(base, "://")) {
        LogWarn("[Fragment] ignoring invalid FRAGMENT_PROXY=\"%s\"; using default\n",
                base[0] ? base : "");
        strcpy(base, "http://127.0.0.1:9020");
    }
    snprintf(gCfg.proxyPrefix, sizeof(gCfg.proxyPrefix), "%s/", base);
    gCfg.proxyPrefixLen = strlen(gCfg.proxyPrefix);
}
