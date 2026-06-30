#!/usr/bin/env python3
"""End-to-end test matrix for Fragment's WinHTTP backend.

Hermetic: needs NO third-party corpus (unlike the curl matrix), so it runs on
any box with Visual Studio. One command builds everything and runs it:

    python windows\\test\\run_winhttp.py [--debug]

Three servers, PASS/FAIL decided purely by which port+path saw the request:
  * 9020 = the proxy the DLL rewrites to
  * 9021 = an alternate proxy (proves FRAGMENT_PROXY is runtime-configurable)
  * 9999 = the origin the unmodified request would hit (must stay untouched
           unless rewriting is deliberately off)

A hooked  https://host/path  must arrive at :9020 as  GET /https://host/path
(plain HTTP -- the secure flag was stripped before the handshake), proving the
redirect lands before TLS, so certificate pinning is never engaged.
"""
import http.server
import os
import socketserver
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(ROOT, "build")
DLL = os.path.join(BUILD, "Fragment.dll")
HOST = os.path.join(BUILD, "host_winhttp.exe")
FRAGMENT_EXE = os.path.join(BUILD, "fragment.exe")

PROXY, ALT, ORIGIN = 9020, 9021, 9999
DEBUG = False

hits = []
lock = threading.Lock()


class H(http.server.BaseHTTPRequestHandler):
    def _rec(self):
        with lock:
            hits.append((self.server.server_address[1], self.command, self.path))
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    do_GET = _rec
    do_POST = _rec
    do_HEAD = _rec
    do_PUT = _rec

    def log_message(self, *a):
        pass


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 256


def servers():
    out = []
    for p in (PROXY, ALT, ORIGIN):
        s = S(("127.0.0.1", p), H)
        threading.Thread(target=s.serve_forever, daemon=True).start()
        out.append(s)
    return out


def henv(extra=None):
    e = {k: v for k, v in os.environ.items() if not k.upper().startswith("FRAGMENT_")}
    if DEBUG:
        e.setdefault("FRAGMENT_LOG_LEVEL", "debug")
    if extra:
        e.update(extra)
    return e


def run(args, env=None, timeout=40):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=henv(env))
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return -1, "TIMEOUT"
    except Exception as e:  # noqa: BLE001
        return -2, repr(e)


def build(script, *extra):
    rc, out = run(["cmd.exe", "/c", os.path.join(ROOT, script), *extra], timeout=600)
    ok = rc == 0
    print(("  build OK " if ok else "  BUILD FAILED ") + script)
    if not ok:
        print(out[-3000:])
    return ok


def url_of(scheme, host, port, path):
    default = 443 if scheme == "https" else 80
    hp = host if (port is None or port == default) else "%s:%d" % (host, port)
    return "%s://%s%s" % (scheme, hp, path or "/")


def expect_proxied(scheme, host, port, path):
    default = 443 if scheme == "https" else 80
    hp = host if (port is None or port == default) else "%s:%d" % (host, port)
    return "/%s://%s%s" % (scheme, hp, path or "/")


results = []


def check_proxy(label, port, path, verb, rc, out):
    with lock:
        snap = list(hits)
    for po, cmd, pa in snap:
        if po == port and pa == path and cmd == verb:
            results.append((label, "PASS", "-> :%d %s %s" % (po, cmd, pa)))
            return
    for po, cmd, pa in snap:
        if po == port and pa == path:
            results.append((label, "PASS?", "path ok but verb=%s (wanted %s)" % (cmd, verb)))
            return
    landed = ", ".join(":%d%s" % (po, pa) for po, _, pa in snap) or "nothing"
    results.append((label, "FAIL", "wanted :%d %s; saw %s | rc=%s" % (port, path, landed, rc)))
    if out:
        print("----", label, "----\n", out[-1200:])


def check_origin(label, path, rc, out):
    with lock:
        snap = list(hits)
    for po, cmd, pa in snap:
        if po == ORIGIN and pa == path:
            results.append((label, "PASS", "origin :%d%s (no rewrite)" % (po, pa)))
            return
    landed = ", ".join(":%d%s" % (po, pa) for po, _, pa in snap) or "nothing"
    results.append((label, "FAIL", "wanted origin %s; saw %s | rc=%s" % (path, landed, rc)))
    if out:
        print("----", label, "----\n", out[-1200:])


def selfload(label, scheme, host, port, path, mode="", extra=None, env=None, expect_port=PROXY):
    u = url_of(scheme, host, port, path)
    with lock:
        hits.clear()
    args = [HOST, DLL, u] + ([mode] if mode else []) + (extra or [])
    rc, out = run(args, env)
    time.sleep(0.3)
    verb = "POST" if mode == "post" else "GET"
    check_proxy(label, expect_port, expect_proxied(scheme, host, port, path), verb, rc, out)


def main():
    global DEBUG
    DEBUG = "--debug" in sys.argv
    cfg = "Debug" if DEBUG else "Release"

    print("== build DLL (%s) + test exes ==" % cfg)
    if not build("build.bat", cfg):
        return 2
    if not build(os.path.join("test", "build_test.bat")):
        return 2
    for f in (DLL, HOST):
        if not os.path.exists(f):
            print("missing build artifact:", f)
            return 2

    srvs = servers()
    time.sleep(0.3)

    # --- core redirect behaviour ------------------------------------------
    selfload("http basic", "http", "127.0.0.1", 9999, "/m1")
    selfload("https basic (pre-TLS, pinning bypass)", "https", "example.com", None, "/m2")
    selfload("https keeps :8443", "https", "example.com", 8443, "/m3")
    selfload("http keeps :8080", "http", "example.com", 8080, "/m4")
    selfload("https query preserved", "https", "example.com", None, "/a/b?x=1&y=2")
    selfload("https root path", "https", "example.com", None, "")
    selfload("https POST verb preserved", "https", "example.com", None, "/m7", "post")

    # --- divert-option neutralization -------------------------------------
    selfload("WinHttpOpen NAMED_PROXY neutralized", "https", "example.com", None, "/m8",
             "appproxy", ["127.0.0.1:%d" % ORIGIN])
    selfload("WinHttpSetOption(PROXY) neutralized", "https", "example.com", None, "/m9",
             "setoptproxy", ["127.0.0.1:%d" % ORIGIN])

    # --- load-order coverage: sweep (winhttp before the DLL) --------------
    selfload("sweep: winhttp before DLL", "https", "example.com", None, "/m10", "swept")

    # --- runtime config ---------------------------------------------------
    selfload("config FRAGMENT_PROXY -> :%d" % ALT, "https", "example.com", None, "/m11",
             env={"FRAGMENT_PROXY": "http://127.0.0.1:%d" % ALT}, expect_port=ALT)

    # off-switch: rewriting disabled -> request reaches the origin untouched
    with lock:
        hits.clear()
    rc, out = run([HOST, DLL, url_of("http", "127.0.0.1", 9999, "/m12")],
                  env={"FRAGMENT_ENABLED": "0"})
    time.sleep(0.3)
    check_origin("config FRAGMENT_ENABLED=0 (off)", "/m12", rc, out)

    # baseline harness sanity: no DLL at all -> origin
    with lock:
        hits.clear()
    rc, out = run([HOST, DLL, url_of("http", "127.0.0.1", 9999, "/m13"), "bare"])
    time.sleep(0.3)
    check_origin("baseline bare (no DLL)", "/m13", rc, out)

    # === audit-fix regressions (PR #1 review) ============================
    # fix #4: a proxy mount path in FRAGMENT_PROXY must be preserved, so the
    # WinHTTP object matches the curl backend's "<proxyPrefix><url>" exactly
    # (curl would send /inspect/https://host/path; WinHTTP must too).
    with lock:
        hits.clear()
    rc, out = run([HOST, DLL, url_of("https", "example.com", None, "/health")],
                  env={"FRAGMENT_PROXY": "http://127.0.0.1:%d/inspect" % PROXY})
    time.sleep(0.3)
    check_proxy("proxy mount path preserved", PROXY,
                "/inspect/https://example.com/health", "GET", rc, out)

    # fix #3: when the proxy host is unusable (host-less FRAGMENT_PROXY leaves
    # proxyHostW empty), the backend must be fully inert -- it must NOT strip
    # the app's own NAMED_PROXY. The app proxies via :ALT, so the request must
    # still reach :ALT (pre-fix it was forced NO_PROXY and reached nothing).
    with lock:
        hits.clear()
    rc, out = run([HOST, DLL, url_of("http", "example.com", None, "/inert"),
                   "appproxy", "127.0.0.1:%d" % ALT],
                  env={"FRAGMENT_PROXY": "http://:%d" % PROXY})
    time.sleep(0.3)
    with lock:
        snap = list(hits)
    n_alt = sum(1 for po, _, _ in snap if po == ALT)
    if n_alt >= 1:
        results.append(("unusable proxy host -> app proxy honored", "PASS",
                        "app NAMED_PROXY reached :%d" % ALT))
    else:
        landed = ", ".join(":%d%s" % (po, pa) for po, _, pa in snap) or "nothing"
        results.append(("unusable proxy host -> app proxy honored", "FAIL",
                        "wanted a hit on :%d; saw %s | rc=%s" % (ALT, landed, rc)))
        if out:
            print("---- unusable proxy host ----\n", out[-1200:])

    # fix #1 guard: closing ONLY the session handle each cycle (WinHTTP frees
    # the child connect/request handles implicitly) must still redirect every
    # request -- exercises cascade eviction of the hConnect->origin map.
    K = 8
    with lock:
        hits.clear()
    rc, out = run([HOST, DLL, url_of("https", "example.com", None, "/sess"),
                   "sessiononly", str(K)])
    time.sleep(0.4)
    want_s = expect_proxied("https", "example.com", None, "/sess")
    with lock:
        snap = list(hits)
    n_s = sum(1 for po, _, pa in snap if po == PROXY and pa == want_s)
    if n_s == K and rc == 0:
        results.append(("session-only close x%d" % K, "PASS", "%d/%d on proxy" % (n_s, K)))
    else:
        results.append(("session-only close x%d" % K, "FAIL",
                        "proxy=%d/%d | rc=%s" % (n_s, K, rc)))
        if out:
            print("---- session-only ----\n", out[-1200:])

    # --- shipped tool: fragment.exe launch + cross-process INJECT ---------
    if os.path.exists(FRAGMENT_EXE):
        with lock:
            hits.clear()
        rc, out = run([FRAGMENT_EXE, "--dll", DLL,
                       "--proxy", "http://127.0.0.1:%d" % PROXY,
                       "--log", "debug" if DEBUG else "off",
                       "--", HOST, DLL, url_of("https", "example.com", None, "/m14"), "bare"])
        time.sleep(0.4)
        check_proxy("fragment.exe launch+inject", PROXY,
                    expect_proxied("https", "example.com", None, "/m14"), "GET", rc, out)
    else:
        results.append(("fragment.exe launch+inject", "SKIP", "fragment.exe missing"))

    # --- concurrency: every request hooked, none leaked -------------------
    T, PER = 8, 60
    want = expect_proxied("https", "example.com", None, "/sm")
    with lock:
        hits.clear()
    rc, out = run([HOST, DLL, url_of("https", "example.com", None, "/sm"), "stress", str(T), str(PER)],
                  timeout=120)
    time.sleep(0.6)
    with lock:
        snap = list(hits)
    nproxy = sum(1 for po, _, pa in snap if po == PROXY and pa == want)
    nleak = sum(1 for po, _, pa in snap if po == ORIGIN)
    if nproxy == T * PER and nleak == 0:
        results.append(("concurrency %dx%d" % (T, PER), "PASS",
                        "%d/%d on proxy, 0 leaked" % (nproxy, T * PER)))
    else:
        results.append(("concurrency %dx%d" % (T, PER), "FAIL",
                        "proxy=%d/%d leak=%d | rc=%s" % (nproxy, T * PER, nleak, rc)))
        if out:
            print("---- concurrency ----\n", out[-1200:])

    for s in srvs:
        s.shutdown()

    print("\n==================== WinHTTP RESULTS ====================")
    npass = total = 0
    for name, st, detail in results:
        print("  [%-5s] %-36s %s" % (st, name, detail))
        if st != "SKIP":
            total += 1
        if st in ("PASS", "PASS?"):
            npass += 1
    print("========================================================")
    print("  %d/%d passed" % (npass, total))
    return 0 if npass == total and total > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
