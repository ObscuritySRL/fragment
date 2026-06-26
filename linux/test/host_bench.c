/*
 * Benchmark driver (informational):
 *   host_bench <url>
 *
 * Measures curl_easy_setopt(CURLOPT_URL) per-call latency and full localhost
 * request throughput. The Python driver runs this BOTH without and with
 * LD_PRELOAD=libfragment.so and reports the delta, so baseline and interposed
 * numbers come from the identical code path -- the only difference being
 * whether Fragment shadows curl_easy_setopt.
 *
 * Timing uses CLOCK_MONOTONIC (vDSO-backed, ~tens of ns) with the timer-pair
 * overhead calibrated and subtracted, so per-call p50/p95/p99 are true per-call
 * latencies (the tail is where the rewrite's malloc slow-path would show).
 *
 * Reports (parsed by run.py):
 *   SETOPT p50/p95/p99   per-call setopt latency (ns); cps = mean calls/sec
 *   E2E reqps            full localhost req/s (I/O-bound context only)
 *
 * Note: setting CURLOPT_URL in a tight loop is a synthetic WORST CASE -- the
 * interposer allocates every call, whereas a real client sets the URL once per
 * handle. run.py frames it accordingly.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CURLOPT_URL              10002
#define CURLOPT_WRITEFUNCTION    20011
#define CURLOPT_TIMEOUT_MS         155
#define CURLOPT_CONNECTTIMEOUT_MS  156
#define CURLOPT_NOSIGNAL            99
#define CURL_GLOBAL_DEFAULT          3

typedef void* CURL;
extern int  curl_global_init(long);
extern CURL curl_easy_init(void);
extern int  curl_easy_setopt(CURL, int, ...);
extern int  curl_easy_perform(CURL);
extern void curl_easy_cleanup(CURL);

static size_t sink(char* p, size_t s, size_t n, void* u) { (void)p; (void)u; return s * n; }

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static int cmp_dbl(const void* a, const void* b) {
    double x = *(const double*)a, y = *(const double*)b;
    return (x > y) - (x < y);
}

int main(int argc, char** argv) {
    if (argc < 2) { fprintf(stderr, "usage: host_bench <url>\n"); return 2; }
    const char* url = argv[1];

    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL h = curl_easy_init();
    if (!h) { fprintf(stderr, "[bench] curl_easy_init failed\n"); return 6; }

    const int WARM = 8000, N = 60000, OVN = 20000;

    /* Median timer-pair overhead (ns), subtracted from each sample. */
    double* ov = (double*)malloc((size_t)OVN * sizeof(double));
    for (int i = 0; i < OVN; i++) { double a = now_ns(), b = now_ns(); ov[i] = b - a; }
    qsort(ov, OVN, sizeof(double), cmp_dbl);
    double ovNs = ov[OVN / 2];
    free(ov);

    for (int i = 0; i < WARM; i++) curl_easy_setopt(h, CURLOPT_URL, url);

    double* samp = (double*)malloc((size_t)N * sizeof(double));
    double sum = 0.0;
    for (int i = 0; i < N; i++) {
        double t0 = now_ns();
        curl_easy_setopt(h, CURLOPT_URL, url);
        double v = (now_ns() - t0) - ovNs;
        if (v < 0.0) v = 0.0;
        samp[i] = v;
        sum += v;
    }
    qsort(samp, N, sizeof(double), cmp_dbl);
    double p50 = samp[N / 2], p95 = samp[(int)(N * 0.95)], p99 = samp[(int)(N * 0.99)];
    double meanNs = sum / N;
    double cps = meanNs > 0.0 ? 1e9 / meanNs : 0.0;
    free(samp);

    /* Full localhost request throughput (network/server-bound context only). */
    const int WARMREQ = 30, M = 300;
    double t0 = 0.0;
    for (int i = 0; i < WARMREQ + M; i++) {
        if (i == WARMREQ) t0 = now_ns();
        CURL r = curl_easy_init();
        if (!r) continue;
        curl_easy_setopt(r, CURLOPT_URL, url);
        curl_easy_setopt(r, CURLOPT_CONNECTTIMEOUT_MS, (long)3000);
        curl_easy_setopt(r, CURLOPT_TIMEOUT_MS, (long)5000);
        curl_easy_setopt(r, CURLOPT_NOSIGNAL, (long)1);
        curl_easy_setopt(r, CURLOPT_WRITEFUNCTION, sink);
        curl_easy_perform(r);
        curl_easy_cleanup(r);
    }
    double secs = (now_ns() - t0) / 1e9;
    double reqps = secs > 0.0 ? M / secs : 0.0;

    curl_easy_cleanup(h);

    printf("SETOPT p50=%.1f p95=%.1f p99=%.1f cps=%.0f\n", p50, p95, p99, cps);
    printf("E2E reqps=%.1f\n", reqps);
    return 0;
}
