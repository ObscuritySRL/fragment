/*
 * Mock libcurl: the minimal real-DLL surface needed to prove Fragment's
 * export-resolution + curl_easy_setopt detour end to end, with NO third-party
 * binaries. It exports a genuine variadic curl_easy_setopt (same ABI shape as
 * real libcurl: register varargs spilled to the home space), so Fragment hooks
 * it by export exactly as it would a real libcurl. Each setopt records what it
 * actually received AFTER the detour ran, and accessor exports let the host
 * assert the rewrite/idempotency/option-drop behaviour. Self-contained =>
 * runnable in CI on a clean machine, unlike the real-libcurl matrix.
 */
#include <windows.h>
#include <stdarg.h>
#include <string.h>

#define CURLOPT_PORT              3
#define CURLOPT_URL           10002
#define CURLOPT_PROXY         10004
#define CURLOPT_RESOLVE       10203
#define CURLOPT_UNIX_SOCKET_PATH     10231
#define CURLOPT_ABSTRACT_UNIX_SOCKET 10264

static char  g_lastUrl[4096];
static void* g_lastResolve  = (void*)~(UINT_PTR)0;  /* sentinel != NULL */
static void* g_lastProxy    = (void*)~(UINT_PTR)0;  /* sentinel != NULL */
static void* g_lastUnix     = (void*)~(UINT_PTR)0;  /* sentinel != NULL */
static void* g_lastAbstract = (void*)~(UINT_PTR)0;  /* sentinel != NULL */
static long  g_lastPort = -1;

__declspec(dllexport) void* curl_easy_init(void) { return (void*)(UINT_PTR)0x1234; }

__declspec(dllexport) int curl_easy_setopt(void* handle, int option, ...) {
    (void)handle;
    va_list ap;
    va_start(ap, option);
    if (option == CURLOPT_URL) {
        const char* u = va_arg(ap, const char*);
        if (u) { strncpy(g_lastUrl, u, sizeof(g_lastUrl) - 1); g_lastUrl[sizeof(g_lastUrl) - 1] = 0; }
        else   { g_lastUrl[0] = 0; }
    } else if (option == CURLOPT_RESOLVE) {
        g_lastResolve = va_arg(ap, void*);
    } else if (option == CURLOPT_PROXY) {
        g_lastProxy = va_arg(ap, void*);
    } else if (option == CURLOPT_UNIX_SOCKET_PATH) {
        g_lastUnix = va_arg(ap, void*);
    } else if (option == CURLOPT_ABSTRACT_UNIX_SOCKET) {
        g_lastAbstract = va_arg(ap, void*);
    } else if (option == CURLOPT_PORT) {
        g_lastPort = va_arg(ap, long);
    }
    va_end(ap);
    return 0;
}

__declspec(dllexport) int  curl_easy_perform(void* handle) { (void)handle; return 0; }
__declspec(dllexport) void curl_easy_cleanup(void* handle) { (void)handle; }

__declspec(dllexport) const char* mock_last_url(void)     { return g_lastUrl; }
__declspec(dllexport) void*       mock_last_resolve(void) { return g_lastResolve; }
__declspec(dllexport) void*       mock_last_proxy(void)   { return g_lastProxy; }
__declspec(dllexport) void*       mock_last_unix(void)     { return g_lastUnix; }
__declspec(dllexport) void*       mock_last_abstract(void) { return g_lastAbstract; }
__declspec(dllexport) long        mock_last_port(void)     { return g_lastPort; }
