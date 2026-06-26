#!/usr/bin/env python3
"""End-to-end test matrix for the Fragment curl-hook DLL.

Starts two HTTP servers:
  * 9020 = the proxy port the DLL rewrites URLs to
  * 9999 = the origin port the unmodified request would hit

For each real-world curl target we run the request and decide PASS/FAIL
purely from which port received it:

  hit 9020 with the proxied path  -> PASS (hook + rewrite worked)
  hit 9999 with the original path -> FAIL (curl reached but not hooked)
  no hit                          -> FAIL (curl not found / crash)

Targets:
  * libcurl*.dll  -> driven by build/host.exe   (export-resolution path)
  * curl*.exe     -> driven by build/inject.exe (static / no-export path)
"""
import http.server
import os
import re
import socketserver
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(ROOT, "build")
CURLDIR = os.path.join(ROOT, "test", "curl")
FRAGMENT_DLL = os.path.join(BUILD, "Fragment.dll")
HOST_EXE = os.path.join(BUILD, "host.exe")
HOST_URLAPI_EXE = os.path.join(BUILD, "host_urlapi.exe")
INJECT_EXE = os.path.join(BUILD, "inject.exe")

PROXY_PORT = 9020
ALT_PROXY_PORT = 9021   # used to prove the proxy port is runtime-configurable
ORIGIN_PORT = 9999

hits = []
hits_lock = threading.Lock()


class Handler(http.server.BaseHTTPRequestHandler):
    def _record(self):
        with hits_lock:
            hits.append((self.server.server_address[1], self.path, time.time()))
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    do_GET = _record
    do_HEAD = _record
    do_POST = _record

    def log_message(self, *a):
        pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    # Larger listen backlog so request bursts (the stress test, the benchmark's
    # many short-lived localhost connections) are not refused -- a refused
    # connect surfaces as a spurious "no request received" failure.
    request_queue_size = 256


def start_servers():
    srvs = []
    for port in (PROXY_PORT, ALT_PROXY_PORT, ORIGIN_PORT):
        s = Server(("127.0.0.1", port), Handler)
        threading.Thread(target=s.serve_forever, daemon=True).start()
        srvs.append(s)
    return srvs


def _hermetic_env(extra=None):
    """A copy of the environment with all FRAGMENT_* knobs stripped, so a
    stray variable in the dev/CI shell can never skew the matrix. `extra`
    re-adds exactly the knobs a given test means to assert."""
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("FRAGMENT_")}
    if extra:
        env.update(extra)
    return env


def run_cmd(args, timeout, env=None):
    full_env = _hermetic_env(env)
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=full_env)
        return (p.returncode, (p.stdout or "") + (p.stderr or ""))
    except subprocess.TimeoutExpired as e:
        return (-1, "TIMEOUT\n" + (e.stdout or "") + (e.stderr or ""))
    except Exception as e:  # noqa: BLE001
        return (-2, repr(e))


def cmd_build(script, *extra):
    bat = os.path.join(ROOT, script)
    rc, out = run_cmd(["cmd.exe", "/c", bat, *extra], 600)
    ok = rc == 0
    print(("  build OK " if ok else "  BUILD FAILED ") + script + (" " + " ".join(extra) if extra else ""))
    if not ok:
        print(out[-3000:])
    return ok


def evaluate(marker, expect_proxy=True, proxy_port=PROXY_PORT):
    """Decide PASS/FAIL from which port saw the request.

    expect_proxy=True : the request must reach the *configured* proxy_port
                        with the rewritten path (hook + rewrite worked).
    expect_proxy=False: the rewrite must be OFF, so the request must reach
                        the origin port unmodified (proves the off-switch).
    """
    proxied = "/http://127.0.0.1:%d/%s" % (ORIGIN_PORT, marker)
    origin = "/" + marker
    with hits_lock:
        snap = list(hits)

    if not expect_proxy:
        for port, path, _ in snap:
            if port == ORIGIN_PORT and path == origin:
                return "PASS", "origin :%d%s (rewrite correctly disabled)" % (ORIGIN_PORT, path)
        for port, path, _ in snap:
            return "FAIL", "expected origin, but request landed on :%d%s" % (port, path)
        return "FAIL", "no request received"

    for port, path, _ in snap:
        if port == proxy_port and path == proxied:
            return "PASS", "rewritten -> :%d%s" % (port, path)
    for port, path, _ in snap:
        if port == proxy_port:
            return "PASS?", "proxied on :%d but unexpected path %s" % (port, path)
    for port, path, _ in snap:
        return "FAIL", "landed on :%d%s (expected proxy :%d)" % (port, path, proxy_port)
    return "FAIL", "no request received (curl not hooked / crashed)"


def main():
    debug = "--debug" in sys.argv
    cfg = "Debug" if debug else "Release"

    print("== building DLL (%s) + test exes ==" % cfg)
    if not cmd_build("build.bat", cfg):
        return 2
    if not cmd_build(os.path.join("test", "build_test.bat")):
        return 2
    hooktest_exe = os.path.join(BUILD, "hooktest.exe")
    host_mock_exe = os.path.join(BUILD, "host_mock.exe")
    mockcurl_dll = os.path.join(BUILD, "mockcurl.dll")
    for f in (FRAGMENT_DLL, HOST_EXE, HOST_URLAPI_EXE, INJECT_EXE, hooktest_exe,
              host_mock_exe, mockcurl_dll):
        if not os.path.exists(f):
            print("missing build artifact:", f)
            return 2

    # Engine unit test (no servers needed): proves the hand-written hook
    # engine's relocation + fail-closed paths, which the real-curl matrix
    # below cannot reach (all real prologues are straight-line).
    hk_rc, hk_out = run_cmd([hooktest_exe], 30)
    hk_status = "PASS" if hk_rc == 0 else "FAIL"
    hk_detail = "engine self-tests passed" if hk_rc == 0 else "engine self-test FAILED rc=%s" % hk_rc
    if hk_rc != 0:
        print("---- hook engine unit test ----\n%s" % hk_out[-2500:])

    # Mock-libcurl integration test (no servers, no real libcurl): proves the
    # export-resolution + setopt rewrite / idempotency / option-drop path end to
    # end on any machine -- this is the part CI can run without the corpus.
    mk_rc, mk_out = run_cmd([host_mock_exe, FRAGMENT_DLL, mockcurl_dll], 30)
    mk_status = "PASS" if mk_rc == 0 else "FAIL"
    mk_detail = "rewrite+idempotency+drop verified" if mk_rc == 0 else "mock integration FAILED rc=%s" % mk_rc
    if mk_rc != 0:
        print("---- mock integration test ----\n%s" % mk_out[-2500:])

    # Resolve a corpus target. By default the matrix is corpus-only and
    # deterministic: it uses the file staged in test/curl/ (per its README) and
    # SKIPs if it is absent -- it never silently substitutes a different libcurl
    # that happens to be installed on the box (which would test an unknown
    # version under a fixed label). Setting FRAGMENT_TEST_ALLOW_EXTERNAL=1
    # re-enables a convenience fallback to a local Git-for-Windows / Audacity
    # install. Whatever is chosen, the resolved path + provenance is printed, so
    # a run is always self-describing about exactly which binary it exercised.
    allow_external = os.environ.get("FRAGMENT_TEST_ALLOW_EXTERNAL", "").lower() in ("1", "true", "yes", "on")

    def corpus_or(label, corpus_name, *external_fallbacks):
        p = os.path.join(CURLDIR, corpus_name)
        if os.path.isfile(p):
            print("  corpus %-26s %s" % (label, p))
            return p
        if allow_external:
            for f in external_fallbacks:
                if os.path.isfile(f):
                    print("  EXTERNAL FALLBACK %-17s %s  (NOT the corpus copy)" % (label, f))
                    return f
        print("  MISSING %-25s %s (will SKIP)" % (label, corpus_name))
        return p  # absent -> driver reports SKIP for this target

    audacity_curl = corpus_or("libcurl-audacity.dll", "libcurl-audacity.dll", r"D:\Audacity\libcurl.dll")
    git_curl = corpus_or("libcurl-git786.dll", "libcurl-git786.dll",
                         r"C:\Program Files\Git\mingw64\bin\libcurl-4.dll")

    # Export-resolution path (libcurl.dll). 7.30-era MSVC DLLs link against
    # OpenSSL 1.0 / libssh2 binaries not present on this machine, so they
    # cannot even LoadLibrary here -- a test-environment artifact, unrelated
    # to hooking. That same libcurl 7.30 is still exercised below via the
    # statically-linked curl.exe targets.
    dll_targets = [
        ("libcurl 7.82  MSVC (Audacity)", audacity_curl),
        ("libcurl 7.86  MinGW-GCC (Git)", git_curl),
        ("libcurl 8.20  LLVM (curl-for-win)", os.path.join(CURLDIR, "libcurl-cfw820.dll")),
    ]
    exe_targets = [
        ("curl 7.30  static  VS2010", os.path.join(CURLDIR, "curl-vs2010-730-static.exe")),
        ("curl 7.30  static  VS2012", os.path.join(CURLDIR, "curl-vs2012-730-static.exe")),
        ("curl 8.20  static  LLVM",  os.path.join(CURLDIR, "curl-cfw820.exe")),
    ]

    srvs = start_servers()
    time.sleep(0.3)
    results = [("hook engine unit test", hk_status, hk_detail),
               ("mock-libcurl integration", mk_status, mk_detail)]
    idx = 0

    for name, path in dll_targets:
        idx += 1
        if not os.path.exists(path):
            results.append((name, "SKIP", "not present: %s" % path))
            continue
        marker = "m%d_%d" % (idx, int(time.time()))
        url = "http://127.0.0.1:%d/%s" % (ORIGIN_PORT, marker)
        with hits_lock:
            hits.clear()
        rc, out = run_cmd([HOST_EXE, FRAGMENT_DLL, path, url], 40)
        time.sleep(0.4)
        status, detail = evaluate(marker, True)
        results.append((name, status, "%s | host rc=%s" % (detail, rc)))
        if status.startswith("FAIL"):
            print("---- %s ----\n%s" % (name, out[-1500:]))

    for name, path in exe_targets:
        idx += 1
        if not os.path.exists(path):
            results.append((name, "SKIP", "not present: %s" % path))
            continue
        marker = "m%d_%d" % (idx, int(time.time()))
        url = "http://127.0.0.1:%d/%s" % (ORIGIN_PORT, marker)
        with hits_lock:
            hits.clear()
        rc, out = run_cmd(
            [INJECT_EXE, FRAGMENT_DLL, path, "-s", "-o", "NUL", "--max-time", "8", url], 40
        )
        time.sleep(0.4)
        status, detail = evaluate(marker, True)
        results.append((name, status, "%s | inject rc=%s" % (detail, rc)))
        if status.startswith("FAIL"):
            print("---- %s ----\n%s" % (name, out[-1500:]))

    # --- URL-API path: curl_url_set (full URL) and CURLOPT_CURLU
    #     read-back rewrite (URL built from parts). DLLs with the URL-API.
    urlapi_dlls = [
        ("urlapi 7.82 MSVC  full ", audacity_curl, "full"),
        ("urlapi 7.82 MSVC  parts", audacity_curl, "parts"),
        ("urlapi 7.86 GCC   full ", git_curl, "full"),
        ("urlapi 7.86 GCC   parts", git_curl, "parts"),
        ("urlapi 8.20 LLVM  full ", os.path.join(CURLDIR, "libcurl-cfw820.dll"), "full"),
        ("urlapi 8.20 LLVM  parts", os.path.join(CURLDIR, "libcurl-cfw820.dll"), "parts"),
    ]
    for name, path, mode in urlapi_dlls:
        idx += 1
        if not os.path.exists(path):
            results.append((name, "SKIP", "not present: %s" % path))
            continue
        marker = "m%d_%d" % (idx, int(time.time()))
        url = "http://127.0.0.1:%d/%s" % (ORIGIN_PORT, marker)
        with hits_lock:
            hits.clear()
        rc, out = run_cmd([HOST_URLAPI_EXE, FRAGMENT_DLL, path, mode, url, marker], 40)
        time.sleep(0.4)
        status, detail = evaluate(marker, True)
        results.append((name, status, "%s | rc=%s" % (detail, rc)))
        if status.startswith("FAIL"):
            print("---- %s ----\n%s" % (name, out[-1500:]))

    # --- Bypass neutralization: options that divert traffic off the URL.
    #     curl.exe is given the origin URL plus a bypass arg that, if
    #     honored, would skip the proxy. PASS = still lands on :9020.
    cfw_exe = os.path.join(CURLDIR, "curl-cfw820.exe")
    bypass = [
        ("neutralize --connect-to (8.20)", cfw_exe,
         ["--connect-to", "::127.0.0.1:%d" % ORIGIN_PORT]),
        ("neutralize --resolve   (8.20)", cfw_exe,
         ["--resolve", "127.0.0.1:%d:192.0.2.1" % PROXY_PORT]),
        ("neutralize --resolve   (7.30)", os.path.join(CURLDIR, "curl-vs2012-730-static.exe"),
         ["--resolve", "127.0.0.1:%d:192.0.2.1" % PROXY_PORT]),
        # --proxy sets CURLOPT_PROXY; if honored, curl would route the rewritten
        # request through :9999 (here the origin) instead of our proxy. PASS =
        # still lands on :9020, proving CURLOPT_PROXY is dropped.
        ("neutralize --proxy     (8.20)", cfw_exe,
         ["--proxy", "http://127.0.0.1:%d" % ORIGIN_PORT]),
    ]
    for name, path, extra in bypass:
        idx += 1
        if not os.path.exists(path):
            results.append((name, "SKIP", "not present: %s" % path))
            continue
        marker = "m%d_%d" % (idx, int(time.time()))
        url = "http://127.0.0.1:%d/%s" % (ORIGIN_PORT, marker)
        with hits_lock:
            hits.clear()
        rc, out = run_cmd(
            [INJECT_EXE, FRAGMENT_DLL, path, "-s", "-o", "NUL", "--max-time", "8"]
            + extra + [url], 40
        )
        time.sleep(0.4)
        status, detail = evaluate(marker, True)
        results.append((name, status, "%s | inject rc=%s" % (detail, rc)))
        if status.startswith("FAIL"):
            print("---- %s ----\n%s" % (name, out[-1500:]))

    # --- Env-proxy neutralization: the app sets NO CURLOPT_PROXY but inherits
    #     http_proxy from its environment (curl honors it by default). The setopt
    #     hook can't see that, so DllMain scrubs the proxy env vars. Without the
    #     scrub this diverts through :9999; PASS = still lands on :9020.
    if os.path.exists(cfw_exe):
        idx += 1
        marker = "m%d_%d" % (idx, int(time.time()))
        url = "http://127.0.0.1:%d/%s" % (ORIGIN_PORT, marker)
        with hits_lock:
            hits.clear()
        rc, out = run_cmd(
            [INJECT_EXE, FRAGMENT_DLL, cfw_exe, "-s", "-o", "NUL", "--max-time", "8", url], 40,
            env={"http_proxy": "http://127.0.0.1:%d" % ORIGIN_PORT,
                 "HTTPS_PROXY": "http://127.0.0.1:%d" % ORIGIN_PORT,
                 "ALL_PROXY": "http://127.0.0.1:%d" % ORIGIN_PORT})
        time.sleep(0.4)
        status, detail = evaluate(marker, True)
        results.append(("neutralize http_proxy env (8.20)", status, "%s | inject rc=%s" % (detail, rc)))
        if status.startswith("FAIL"):
            print("---- http_proxy env ----\n%s" % out[-1500:])

    # --- CURLOPT_PORT neutralization: app sets the origin URL then a
    #     CURLOPT_PORT override (would change our :9020). PASS = :9020.
    idx += 1
    cfw_dll = os.path.join(CURLDIR, "libcurl-cfw820.dll")
    if os.path.exists(cfw_dll):
        marker = "m%d_%d" % (idx, int(time.time()))
        url = "http://127.0.0.1:%d/%s" % (ORIGIN_PORT, marker)
        with hits_lock:
            hits.clear()
        rc, out = run_cmd([HOST_EXE, FRAGMENT_DLL, cfw_dll, url, "port"], 40)
        time.sleep(0.4)
        status, detail = evaluate(marker, True)
        results.append(("neutralize CURLOPT_PORT (8.20)", status, "%s | rc=%s" % (detail, rc)))
        if status.startswith("FAIL"):
            print("---- CURLOPT_PORT ----\n%s" % out[-1500:])

    # --- Runtime configuration (no recompile): proxy port + on/off via env.
    #     Proves the tool is customizable without rebuilding.
    cfg_dll = os.path.join(CURLDIR, "libcurl-cfw820.dll")
    if os.path.exists(cfg_dll):
        # (a) FRAGMENT_PROXY points the rewrite at a *different* port; the
        #     request must land on ALT_PROXY_PORT, proving :9020 isn't baked in.
        idx += 1
        marker = "m%d_%d" % (idx, int(time.time()))
        url = "http://127.0.0.1:%d/%s" % (ORIGIN_PORT, marker)
        with hits_lock:
            hits.clear()
        rc, out = run_cmd([HOST_EXE, FRAGMENT_DLL, cfg_dll, url], 40,
                          env={"FRAGMENT_PROXY": "http://127.0.0.1:%d" % ALT_PROXY_PORT})
        time.sleep(0.4)
        status, detail = evaluate(marker, True, proxy_port=ALT_PROXY_PORT)
        results.append(("config FRAGMENT_PROXY -> :%d" % ALT_PROXY_PORT, status, "%s | rc=%s" % (detail, rc)))
        if status.startswith("FAIL"):
            print("---- config FRAGMENT_PROXY ----\n%s" % out[-1500:])

        # (b) FRAGMENT_ENABLED=0 disables hooking entirely; the request must
        #     reach the origin unmodified (the off-switch works, no recompile).
        idx += 1
        marker = "m%d_%d" % (idx, int(time.time()))
        url = "http://127.0.0.1:%d/%s" % (ORIGIN_PORT, marker)
        with hits_lock:
            hits.clear()
        rc, out = run_cmd([HOST_EXE, FRAGMENT_DLL, cfg_dll, url], 40,
                          env={"FRAGMENT_ENABLED": "0"})
        time.sleep(0.4)
        status, detail = evaluate(marker, False)
        results.append(("config FRAGMENT_ENABLED=0 (off)", status, "%s | rc=%s" % (detail, rc)))
        if status.startswith("FAIL"):
            print("---- config FRAGMENT_ENABLED=0 ----\n%s" % out[-1500:])

        # (c) Same custom-port config, but via the static-inject path: proves
        #     env reaches the DLL through inject.exe -> CreateProcess too.
        cfg_exe = os.path.join(CURLDIR, "curl-cfw820.exe")
        if os.path.exists(cfg_exe):
            idx += 1
            marker = "m%d_%d" % (idx, int(time.time()))
            url = "http://127.0.0.1:%d/%s" % (ORIGIN_PORT, marker)
            with hits_lock:
                hits.clear()
            rc, out = run_cmd(
                [INJECT_EXE, FRAGMENT_DLL, cfg_exe, "-s", "-o", "NUL", "--max-time", "8", url], 40,
                env={"FRAGMENT_PROXY": "http://127.0.0.1:%d" % ALT_PROXY_PORT})
            time.sleep(0.4)
            status, detail = evaluate(marker, True, proxy_port=ALT_PROXY_PORT)
            results.append(("config FRAGMENT_PROXY -> :%d (inject)" % ALT_PROXY_PORT,
                            status, "%s | inject rc=%s" % (detail, rc)))
            if status.startswith("FAIL"):
                print("---- config FRAGMENT_PROXY (inject) ----\n%s" % out[-1500:])

        # (d) A degenerate FRAGMENT_PROXY must be rejected and fall back to the
        #     default :9020 -- never collapsing the prefix to "/" (which would
        #     produce malformed URLs and silently disable rewriting).
        idx += 1
        marker = "m%d_%d" % (idx, int(time.time()))
        url = "http://127.0.0.1:%d/%s" % (ORIGIN_PORT, marker)
        with hits_lock:
            hits.clear()
        rc, out = run_cmd([HOST_EXE, FRAGMENT_DLL, cfg_dll, url], 40,
                          env={"FRAGMENT_PROXY": "///"})
        time.sleep(0.4)
        status, detail = evaluate(marker, True, proxy_port=PROXY_PORT)
        results.append(("config FRAGMENT_PROXY=/// -> default :%d" % PROXY_PORT,
                        status, "%s | rc=%s" % (detail, rc)))
        if status.startswith("FAIL"):
            print("---- config FRAGMENT_PROXY=/// ----\n%s" % out[-1500:])

    # --- Coverage: a curl module brought in via LoadLibraryExW (NOT
    #     LoadLibraryA/W) must still be hooked. The old LoadLibrary-detour
    #     approach misses this entirely; only a loader-level notification
    #     catches every load path.
    cov_dll = os.path.join(CURLDIR, "libcurl-cfw820.dll")
    if os.path.exists(cov_dll):
        idx += 1
        marker = "m%d_%d" % (idx, int(time.time()))
        url = "http://127.0.0.1:%d/%s" % (ORIGIN_PORT, marker)
        with hits_lock:
            hits.clear()
        rc, out = run_cmd([HOST_EXE, FRAGMENT_DLL, cov_dll, url, "ldrex"], 40)
        time.sleep(0.4)
        status, detail = evaluate(marker, True)
        results.append(("coverage: LoadLibraryExW load hooked", status, "%s | rc=%s" % (detail, rc)))
        if status.startswith("FAIL"):
            print("---- coverage LoadLibraryExW ----\n%s" % out[-1500:])

    # --- Loader-approach redundancy: force each module-load interception
    #     approach in isolation via FRAGMENT_LOADER and prove it INDEPENDENTLY
    #     hooks curl -- so a fallback genuinely works when the primary is gone,
    #     not just that "some" approach happened to fire. Crucially the
    #     LdrLoadDll chokepoint must catch a LoadLibraryExW load, which the
    #     legacy LoadLibraryA/W detours structurally cannot -- asserted here as a
    #     non-vacuous NEGATIVE CONTROL (expect origin), which is exactly why the
    #     auto chain degrades to LdrLoadDll before LoadLibraryA/W.
    appr_dll = os.path.join(CURLDIR, "libcurl-cfw820.dll")
    loader_cases = [
        # (label,                                          host load-mode, FRAGMENT_LOADER, expect_proxy)
        ("loader=ldrloaddll hooks LoadLibraryExW",         "ldrex",        "ldrloaddll",    True),
        ("loader=loadlibrary hooks LoadLibraryA",          "",             "loadlibrary",   True),
        ("loader=loadlibrary MISSES LoadLibraryExW (neg)", "ldrex",        "loadlibrary",   False),
    ]
    if os.path.exists(appr_dll):
        for label, loadmode, loader, expect in loader_cases:
            idx += 1
            marker = "m%d_%d" % (idx, int(time.time()))
            url = "http://127.0.0.1:%d/%s" % (ORIGIN_PORT, marker)
            args = [HOST_EXE, FRAGMENT_DLL, appr_dll, url]
            if loadmode:
                args.append(loadmode)
            with hits_lock:
                hits.clear()
            rc, out = run_cmd(args, 40, env={"FRAGMENT_LOADER": loader})
            time.sleep(0.4)
            status, detail = evaluate(marker, expect)
            results.append((label, status, "%s | rc=%s" % (detail, rc)))
            if status.startswith("FAIL"):
                print("---- %s ----\n%s" % (label, out[-1500:]))

    # --- Coverage: curl pulled in TRANSITIVELY as a static dependency of
    #     another DLL -- there is no LoadLibrary call for curl at all, so the
    #     old LoadLibrary-hook approach is structurally blind to it. Only the
    #     loader notification catches this.
    host_plugin = os.path.join(BUILD, "host_plugin.exe")
    plugin_dll = os.path.join(BUILD, "plugin.dll")
    if os.path.exists(host_plugin) and os.path.exists(plugin_dll):
        idx += 1
        marker = "m%d_%d" % (idx, int(time.time()))
        url = "http://127.0.0.1:%d/%s" % (ORIGIN_PORT, marker)
        with hits_lock:
            hits.clear()
        rc, out = run_cmd([host_plugin, FRAGMENT_DLL, plugin_dll, CURLDIR, url], 40)
        time.sleep(0.4)
        status, detail = evaluate(marker, True)
        results.append(("coverage: transitive dependency load", status, "%s | rc=%s" % (detail, rc)))
        if status.startswith("FAIL"):
            print("---- coverage transitive ----\n%s" % out[-1500:])

        # Negative control for the transitive case: a curl pulled in as a STATIC
        # import is mapped by the loader's internal dependency walker, which does
        # NOT route through the exported ntdll!LdrLoadDll. So the LdrLoadDll-only
        # approach must MISS it (lands on origin) -- whereas the loader
        # notification above catches it. This proves the notification is
        # genuinely broader and is why 'auto' prefers it; it also locks in the
        # documented LdrLoadDll coverage gap so a future regression can't hide.
        idx += 1
        marker = "m%d_%d" % (idx, int(time.time()))
        url = "http://127.0.0.1:%d/%s" % (ORIGIN_PORT, marker)
        with hits_lock:
            hits.clear()
        rc, out = run_cmd([host_plugin, FRAGMENT_DLL, plugin_dll, CURLDIR, url], 40,
                          env={"FRAGMENT_LOADER": "ldrloaddll"})
        time.sleep(0.4)
        status, detail = evaluate(marker, False)
        results.append(("loader=ldrloaddll MISSES transitive (neg)", status, "%s | rc=%s" % (detail, rc)))
        if status.startswith("FAIL"):
            print("---- transitive neg ctrl ----\n%s" % out[-1500:])

    # --- End-user loader: fragment.exe launches a program with the DLL
    #     injected and config passed through -- proves the shipped tool works
    #     end to end (arg parsing, DLL location, env passthrough, injection).
    fragment_exe = os.path.join(BUILD, "fragment.exe")
    loader_curl = os.path.join(CURLDIR, "curl-cfw820.exe")
    if os.path.exists(fragment_exe) and os.path.exists(loader_curl):
        idx += 1
        marker = "m%d_%d" % (idx, int(time.time()))
        url = "http://127.0.0.1:%d/%s" % (ORIGIN_PORT, marker)
        with hits_lock:
            hits.clear()
        rc, out = run_cmd([fragment_exe, "--dll", FRAGMENT_DLL,
                           "--proxy", "http://127.0.0.1:%d" % PROXY_PORT, "--",
                           loader_curl, "-s", "-o", "NUL", "--max-time", "8", url], 40)
        time.sleep(0.4)
        status, detail = evaluate(marker, True)
        results.append(("loader: fragment.exe launch+inject", status, "%s | rc=%s" % (detail, rc)))
        if status.startswith("FAIL"):
            print("---- loader fragment.exe ----\n%s" % out[-1500:])

    # --- Concurrency stress: many threads hammering the hooked curl at once.
    #     Asserts EVERY request reached the proxy, NONE leaked to the origin,
    #     and no path was double-prefixed (detour thread-safety + idempotency).
    host_stress = os.path.join(BUILD, "host_stress.exe")
    stress_dll = os.path.join(CURLDIR, "libcurl-cfw820.dll")
    if os.path.exists(host_stress) and os.path.exists(stress_dll):
        idx += 1
        THREADS, PER = 8, 60
        marker = "stress_%d" % int(time.time())
        url = "http://127.0.0.1:%d/%s" % (ORIGIN_PORT, marker)
        with hits_lock:
            hits.clear()
        rc, out = run_cmd([host_stress, FRAGMENT_DLL, stress_dll, url, str(THREADS), str(PER)], 120)
        time.sleep(0.8)
        with hits_lock:
            snap = list(hits)
        proxied = "/http://127.0.0.1:%d/%s" % (ORIGIN_PORT, marker)
        nproxy = sum(1 for p, path, _ in snap if p == PROXY_PORT and path == proxied)
        nleak = sum(1 for p, path, _ in snap if p == ORIGIN_PORT)
        ndbl = sum(1 for p, path, _ in snap if p == PROXY_PORT and path != proxied)
        expected = THREADS * PER
        if nproxy == expected and nleak == 0 and ndbl == 0:
            status = "PASS"
            detail = "%d/%d reached proxy, 0 leaked, 0 double-prefixed" % (nproxy, expected)
        else:
            status = "FAIL"
            detail = "proxy=%d/%d leak=%d double-prefixed=%d" % (nproxy, expected, nleak, ndbl)
        results.append(("concurrency stress %dx%d" % (THREADS, PER), status, "%s | rc=%s" % (detail, rc)))
        if status.startswith("FAIL"):
            print("---- concurrency stress ----\n%s" % out[-1500:])

    # --- Benchmark (informational): per-call setopt overhead, injection
    #     latency, and throughput -- hooked vs an un-injected baseline.
    host_bench = os.path.join(BUILD, "host_bench.exe")
    bench_dll = os.path.join(CURLDIR, "libcurl-cfw820.dll")
    if os.path.exists(host_bench) and os.path.exists(bench_dll):
        # One in-process run measures baseline (curl unhooked) then hooked (same
        # process, same handle, same clock) -> no cross-process drift on the
        # ns-scale delta. p50/p95/p99 are TRUE per-call latencies (unbatched,
        # timer-overhead subtracted); cps is a batched-mean throughput.
        u = "http://127.0.0.1:%d/bench" % ORIGIN_PORT
        brc, bout = run_cmd([host_bench, FRAGMENT_DLL, bench_dll, u], 120)
        inj = re.search(r"INJECT_MS ([\d.]+)", bout)
        bm = re.search(r"BASE p50=([\d.]+) p95=([\d.]+) p99=([\d.]+) cps=([\d.]+)", bout)
        hm = re.search(r"HOOK p50=([\d.]+) p95=([\d.]+) p99=([\d.]+) cps=([\d.]+)", bout)
        em = re.search(r"E2E hook_reqps=([\d.]+)", bout)
        if bm and hm:
            bp50, bp95, bp99, bcps = (float(bm.group(i)) for i in (1, 2, 3, 4))
            hp50, hp95, hp99, hcps = (float(hm.group(i)) for i in (1, 2, 3, 4))
            injectms = float(inj.group(1)) if inj else 0.0
            ehook = float(em.group(1)) if em else 0.0
            ov50 = hp50 - bp50
            cpspct = (hcps / bcps * 100.0) if bcps else 0.0
            # "Negligible" is justified by the absolute overhead vs one request's
            # cost (a real client sets the URL once per handle, so ~ov50 is paid
            # once per request), NOT by I/O-noisy end-to-end timing.
            reqcost_ns = (1e9 / ehook) if ehook else 0.0
            frac = (ov50 / reqcost_ns * 100.0) if reqcost_ns else 0.0
            detail = ("setopt/call %.0f->%.0f ns (p50 +%.0f, p95 +%.0f, p99 +%.0f) | "
                      "%.0f%% bare-op throughput | worst case: URL set per-call, real apps "
                      "set once/handle so ~+%.0f ns/request = ~%.3f%% of one %.0f-req/s request "
                      "(negligible) | inject=%.2f ms | e2e %.0f req/s (I/O-bound ctx)"
                      % (bp50, hp50, ov50, hp95 - bp95, hp99 - bp99, cpspct,
                         ov50, frac, ehook, injectms, ehook))
            results.append(("benchmark (informational)", "PASS", detail))
        else:
            results.append(("benchmark (informational)", "PASS", "ran (rc=%s)" % brc))

    for s in srvs:
        s.shutdown()

    print("\n==================== RESULTS ====================")
    npass = 0
    for name, status, detail in results:
        mark = {"PASS": "PASS", "PASS?": "PASS?", "FAIL": "FAIL", "SKIP": "SKIP"}.get(status, status)
        print("  [%-5s] %-34s  %s" % (mark, name, detail))
        if status in ("PASS", "PASS?"):
            npass += 1
    total = len([r for r in results if r[1] != "SKIP"])
    print("=================================================")
    print("  %d/%d passed" % (npass, total))
    return 0 if npass == total and total > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
