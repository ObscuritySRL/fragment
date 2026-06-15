/*
 * Benchmark driver (in-process A/B):
 *   host_bench <Fragment.dll> <libcurl.dll> <url>
 *
 * Measures curl_easy_setopt(CURLOPT_URL) cost BEFORE and AFTER injecting
 * Fragment, in ONE process and on the SAME curl handle, so baseline and hooked
 * numbers share the same CPU clock/thermal state (no cross-process drift) -- and
 * so it mirrors the real scenario: curl already loaded, then Fragment injected,
 * which hooks the already-mapped module.
 *
 * Timing uses the TSC (rdtscp), not QPC: a setopt call is ~tens of ns, far below
 * QPC's ~100 ns tick, so QPC cannot resolve a single call. The TSC is calibrated
 * against QPC once and is invariant on all supported (x64, post-2008) CPUs. The
 * rdtscp-pair overhead is calibrated and subtracted, so per-call p50/p95/p99 are
 * TRUE per-call latencies (the tail is where the detour's malloc slow-path would
 * show), and their mean gives a stable calls/sec.
 *
 * Reports (parsed by run.py):
 *   INJECT_MS                time for LoadLibrary(Fragment) = install hooks
 *   BASE / HOOK p50/p95/p99  per-call setopt latency (ns); cps = mean calls/sec
 *   E2E hook_reqps           full localhost req/s, I/O-bound context only
 *
 * Note: setting CURLOPT_URL in a tight loop is a synthetic WORST CASE -- the
 * detour allocates every call, whereas a real client sets the URL once per
 * handle (paying the cost once per request). run.py frames it accordingly.
 */
#include <windows.h>
#include <intrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static double g_cyclesPerNs;   /* TSC cycles per nanosecond (from calibration) */

/* Serialized TSC read (rdtscp waits for prior instructions to retire; the
 * lfence keeps the following read from starting early). */
static unsigned long long rd(void) {
    unsigned int aux;
    unsigned long long t = __rdtscp(&aux);
    _mm_lfence();
    return t;
}

/* Calibrate the TSC rate against QPC over ~40 ms of busy-wait. */
static void calibrate(void) {
    LARGE_INTEGER f, q0, q1;
    QueryPerformanceFrequency(&f);
    double target = (double)f.QuadPart * 0.04;
    QueryPerformanceCounter(&q0);
    unsigned long long c0 = rd();
    do { QueryPerformanceCounter(&q1); } while ((double)(q1.QuadPart - q0.QuadPart) < target);
    unsigned long long c1 = rd();
    double secs = (double)(q1.QuadPart - q0.QuadPart) / (double)f.QuadPart;
    g_cyclesPerNs = ((double)(c1 - c0) / secs) / 1e9;
    if (g_cyclesPerNs <= 0.0) g_cyclesPerNs = 1.0;   /* defensive */
}

static int cmp_dbl(const void* a, const void* b) {
    double x = *(const double*)a, y = *(const double*)b;
    return (x > y) - (x < y);
}
static size_t sink(char* p, size_t s, size_t n, void* u) { (void)p; (void)u; return s * n; }

typedef struct { double p50, p95, p99, cps; } Stat;

/* Per-call setopt(CURLOPT_URL) latency on handle h (ns), rdtscp-timed with the
 * timer-pair overhead removed. Fills p50/p95/p99 and mean->cps. */
static int measure_setopt(setopt_t ces, CURL h, const char* url, Stat* out) {
    const int WARM = 8000, N = 60000, OVN = 20000;

    /* Median rdtscp-pair overhead (cycles), subtracted from each sample. */
    double* ov = (double*)malloc((size_t)OVN * sizeof(double));
    if (!ov) return 0;
    for (int i = 0; i < OVN; i++) { unsigned long long a = rd(), b = rd(); ov[i] = (double)(b - a); }
    qsort(ov, OVN, sizeof(double), cmp_dbl);
    double ovCyc = ov[OVN / 2];
    free(ov);

    for (int i = 0; i < WARM; i++) ces(h, CURLOPT_URL, url);

    double* samp = (double*)malloc((size_t)N * sizeof(double));
    if (!samp) return 0;
    double sum = 0.0;
    for (int i = 0; i < N; i++) {
        unsigned long long t0 = rd();
        ces(h, CURLOPT_URL, url);
        double cyc = (double)(rd() - t0) - ovCyc;
        double nsv = (cyc > 0.0 ? cyc : 0.0) / g_cyclesPerNs;
        samp[i] = nsv;
        sum += nsv;
    }
    qsort(samp, N, sizeof(double), cmp_dbl);
    out->p50 = samp[N / 2];
    out->p95 = samp[(int)(N * 0.95)];
    out->p99 = samp[(int)(N * 0.99)];
    double meanNs = sum / N;
    out->cps = meanNs > 0.0 ? 1e9 / meanNs : 0.0;
    free(samp);
    return 1;
}

/* Full localhost request throughput (network/server-bound context only). Kept
 * small to avoid flooding the test server's ephemeral ports / TIME_WAIT. */
static double measure_e2e(init_t cei, setopt_t ces, perform_t cep, cleanup_t cec, const char* url) {
    const int WARMREQ = 30, M = 300;
    LARGE_INTEGER f, t0; QueryPerformanceFrequency(&f); t0.QuadPart = 0;
    for (int i = 0; i < WARMREQ + M; i++) {
        if (i == WARMREQ) QueryPerformanceCounter(&t0);
        CURL r = cei();
        if (!r) continue;
        ces(r, CURLOPT_URL, url);
        ces(r, CURLOPT_CONNECTTIMEOUT_MS, (long)3000);
        ces(r, CURLOPT_TIMEOUT_MS, (long)5000);
        ces(r, CURLOPT_NOSIGNAL, (long)1);
        ces(r, CURLOPT_WRITEFUNCTION, sink);
        cep(r);
        cec(r);
    }
    LARGE_INTEGER t1; QueryPerformanceCounter(&t1);
    double secs = (double)(t1.QuadPart - t0.QuadPart) / (double)f.QuadPart;
    return secs > 0.0 ? M / secs : 0.0;
}

int main(int argc, char** argv) {
    if (argc < 4) { fprintf(stderr, "usage: host_bench <Fragment.dll> <curl.dll> <url>\n"); return 2; }
    const char* frag = argv[1], *curlPath = argv[2], *url = argv[3];

    calibrate();

    char dir[MAX_PATH];
    strncpy(dir, curlPath, MAX_PATH - 1); dir[MAX_PATH - 1] = 0;
    for (char* p = dir + strlen(dir); p >= dir; --p)
        if (*p == '\\' || *p == '/') { *p = 0; break; }
    SetDllDirectoryA(dir);
    SetCurrentDirectoryA(dir);

    HMODULE hc = LoadLibraryA(curlPath);
    if (!hc) { fprintf(stderr, "[bench] curl load failed %lu\n", GetLastError()); return 4; }
    ginit_t   cgi = (ginit_t)(void*)GetProcAddress(hc, "curl_global_init");
    init_t    cei = (init_t)(void*)GetProcAddress(hc, "curl_easy_init");
    setopt_t  ces = (setopt_t)(void*)GetProcAddress(hc, "curl_easy_setopt");
    perform_t cep = (perform_t)(void*)GetProcAddress(hc, "curl_easy_perform");
    cleanup_t cec = (cleanup_t)(void*)GetProcAddress(hc, "curl_easy_cleanup");
    if (!cei || !ces || !cep || !cec) { fprintf(stderr, "[bench] missing curl exports\n"); return 5; }
    if (cgi) cgi(CURL_GLOBAL_DEFAULT);

    CURL h = cei();
    if (!h) { fprintf(stderr, "[bench] curl_easy_init failed\n"); return 6; }

    Stat base, hook;
    if (!measure_setopt(ces, h, url, &base)) { fprintf(stderr, "[bench] OOM (baseline)\n"); return 7; }

    /* Inject Fragment: DllMain sweeps already-mapped modules and hooks curl. */
    unsigned long long inj0 = rd();
    if (!LoadLibraryA(frag)) { fprintf(stderr, "[bench] Fragment load failed %lu\n", GetLastError()); return 3; }
    double injectMs = ((double)(rd() - inj0) / g_cyclesPerNs) / 1e6;

    if (!measure_setopt(ces, h, url, &hook)) { fprintf(stderr, "[bench] OOM (hooked)\n"); return 7; }
    double e2eHook = measure_e2e(cei, ces, cep, cec, url);

    cec(h);

    printf("INJECT_MS %.3f\n", injectMs);
    printf("BASE p50=%.1f p95=%.1f p99=%.1f cps=%.0f\n", base.p50, base.p95, base.p99, base.cps);
    printf("HOOK p50=%.1f p95=%.1f p99=%.1f cps=%.0f\n", hook.p50, hook.p95, hook.p99, hook.cps);
    printf("E2E hook_reqps=%.1f\n", e2eHook);
    return 0;
}
