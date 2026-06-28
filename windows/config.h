#pragma once

#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"

/*
 * All knobs are read ONCE at load time from the environment, so the very
 * same shipped DLL can be pointed at a different proxy, toggled off, or made
 * verbose WITHOUT recompiling. Defaults reproduce the classic behaviour
 * (rewrite every request to http://127.0.0.1:9020/<original-url>).
 *
 *   FRAGMENT_PROXY        full base, e.g. "http://127.0.0.1:9020" or
 *                         "https://10.0.0.5:8888" (scheme/host/port; a
 *                         trailing slash is normalised). Wins if set.
 *   FRAGMENT_PROXY_HOST   host when FRAGMENT_PROXY is unset (default 127.0.0.1)
 *   FRAGMENT_PROXY_PORT   port when FRAGMENT_PROXY is unset (default 9020)
 *   FRAGMENT_ENABLED      0/false/no/off => do not hook at all
 *   FRAGMENT_DISABLE      1/true/yes/on  => do not hook at all
 *   FRAGMENT_LOG_LEVEL    off|error|warn|info|debug
 *   FRAGMENT_LOG_FILE     path; if unset, logs go to the debugger output
 *   FRAGMENT_LOG_CONSOLE  1 => allocate a console and tee stdout there
 *   FRAGMENT_LOADER       auto|notify|ldrloaddll|loadlibrary -- which module-
 *                         load interception approach to use (diagnostic /
 *                         compatibility override; default auto = try all in
 *                         order of coverage, degrading gracefully).
 */

/* Module-load interception strategy. Fragment catches every way a curl module
 * can enter the process by layering independent approaches; this selects which
 * one(s) to use. 'auto' (the default) tries them top-down and uses the first
 * that installs, so a single mechanism being unavailable never blinds us. */
enum {
    FRAG_LOADER_AUTO = 0,     /* notification -> LdrLoadDll -> LoadLibraryA/W   */
    FRAG_LOADER_NOTIFY,       /* only LdrRegisterDllNotification                */
    FRAG_LOADER_LDRLOADDLL,   /* only the LdrLoadDll ntdll-chokepoint hook      */
    FRAG_LOADER_LOADLIBRARY   /* only the LoadLibraryA/W detours (legacy)       */
};

typedef struct {
    BOOL   enabled;
    char   proxyPrefix[600];   /* always ends in '/', e.g. http://h:p/ */
    size_t proxyPrefixLen;
    int    loaderMode;         /* one of FRAG_LOADER_*                  */
    /* The same proxy, split for backends that take host/port/scheme as separate
     * arguments rather than one URL string (WinHTTP's WinHttpConnect, ...). */
    wchar_t        proxyHostW[256]; /* proxy host, wide                     */
    unsigned short proxyPort;       /* proxy port                           */
    BOOL           proxySecure;     /* proxy base scheme == https           */
} FragmentConfig;

static FragmentConfig gCfg;

static BOOL EnvFalsey(const char* v) {
    return v && (!_stricmp(v, "0") || !_stricmp(v, "false") ||
                 !_stricmp(v, "no") || !_stricmp(v, "off"));
}
static BOOL EnvTruthy(const char* v) {
    return v && (!_stricmp(v, "1") || !_stricmp(v, "true") ||
                 !_stricmp(v, "yes") || !_stricmp(v, "on"));
}

static int ParseLogLevel(const char* v) {
    if (!v || !*v) return -1;
    if (!_stricmp(v, "off")   || !_stricmp(v, "none") || !_stricmp(v, "0")) return FRAG_LOG_OFF;
    if (!_stricmp(v, "error") || !_stricmp(v, "err"))     return FRAG_LOG_ERROR;
    if (!_stricmp(v, "warn")  || !_stricmp(v, "warning")) return FRAG_LOG_WARN;
    if (!_stricmp(v, "info"))                             return FRAG_LOG_INFO;
    if (!_stricmp(v, "debug") || !_stricmp(v, "trace") || !_stricmp(v, "all")) return FRAG_LOG_DEBUG;
    return -1;
}

/* Read an env var into a fixed buffer; out[0]=0 if unset or oversized. */
static void EnvGet(const char* name, char* out, DWORD cap) {
    DWORD n = GetEnvironmentVariableA(name, out, cap);
    if (n == 0 || n >= cap) out[0] = 0;
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
    gCfg.enabled = TRUE;
    EnvGet("FRAGMENT_ENABLED", buf, sizeof(buf));
    if (buf[0] && EnvFalsey(buf)) gCfg.enabled = FALSE;
    EnvGet("FRAGMENT_DISABLE", buf, sizeof(buf));
    if (buf[0] && EnvTruthy(buf)) gCfg.enabled = FALSE;

    /* -- module-load interception strategy ------------------------------- */
    char ldr[32];
    EnvGet("FRAGMENT_LOADER", ldr, sizeof(ldr));
    gCfg.loaderMode = FRAG_LOADER_AUTO;
    if      (!_stricmp(ldr, "notify"))                            gCfg.loaderMode = FRAG_LOADER_NOTIFY;
    else if (!_stricmp(ldr, "ldrloaddll") || !_stricmp(ldr, "ldr")) gCfg.loaderMode = FRAG_LOADER_LDRLOADDLL;
    else if (!_stricmp(ldr, "loadlibrary") || !_stricmp(ldr, "ll")) gCfg.loaderMode = FRAG_LOADER_LOADLIBRARY;
    else if (ldr[0] && _stricmp(ldr, "auto"))
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
        _snprintf_s(base, sizeof(base), _TRUNCATE, "http://%s:%s", host, port);
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
    _snprintf_s(gCfg.proxyPrefix, sizeof(gCfg.proxyPrefix), _TRUNCATE, "%s/", base);
    gCfg.proxyPrefixLen = strlen(gCfg.proxyPrefix);

    /* -- split the (validated) base into host / port / scheme. `base` is
     *    "scheme://host[:port]" with no path or trailing slash here. IPv6
     *    literals in [brackets] are not split (rare for a local proxy; set
     *    FRAGMENT_PROXY_HOST/PORT explicitly for those). */
    {
        const char* sep   = strstr(base, "://");
        const char* host0 = sep ? sep + 3 : base;
        const char* colon = strrchr(host0, ':');
        char host[256];
        gCfg.proxySecure = (sep && (size_t)(sep - base) == 5 && !_strnicmp(base, "https", 5));
        if (colon && colon[1]) {
            size_t hl = (size_t)(colon - host0);
            if (hl >= sizeof(host)) hl = sizeof(host) - 1;
            memcpy(host, host0, hl);
            host[hl] = 0;
            gCfg.proxyPort = (unsigned short) atoi(colon + 1);
        } else {
            _snprintf_s(host, sizeof(host), _TRUNCATE, "%s", host0);
            gCfg.proxyPort = gCfg.proxySecure ? 443 : 80;
        }
        if (!MultiByteToWideChar(CP_ACP, 0, host, -1, gCfg.proxyHostW,
                                 (int)(sizeof(gCfg.proxyHostW) / sizeof(wchar_t))))
            gCfg.proxyHostW[0] = 0;
        LogDebug("[Fragment] proxy split: host=%ls port=%u secure=%d\n",
                 gCfg.proxyHostW, (unsigned) gCfg.proxyPort, (int) gCfg.proxySecure);
    }
}
