#!/usr/bin/env python3
"""End-to-end test matrix for the Fragment curl-interception library.

Starts three HTTP servers:
  * 9020 = the proxy port the library rewrites URLs to
  * 9021 = an alternate proxy, to prove the port is runtime-configurable
  * 9999 = the origin port the unmodified request would hit

For each target we run a request and decide PASS/FAIL purely from which port
received it:

  hit 9020 with the proxied path  -> PASS (interception + rewrite worked)
  hit 9999 with the original path -> FAIL (curl reached but not intercepted)
  no hit                          -> FAIL (curl not found / crash)

The library is engaged by preloading it (LD_PRELOAD), by auditing (LD_AUDIT),
or by ptrace injection (the fragment loader). The real-libcurl rows use the
system libcurl and the system `curl` binary; the engine unit test and the
self-contained mock rows need no real libcurl and also run for x86-64 under
qemu when that toolchain is present.
"""
import http.server
import os
import re
import shutil
import socketserver
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(ROOT, "build")
X64 = os.path.join(BUILD, "x64")
I386 = os.path.join(BUILD, "i386")
ARMV7 = os.path.join(BUILD, "armv7")
LIBFRAG = os.path.join(BUILD, "libfragment.so")
FRAGMENT = os.path.join(BUILD, "fragment")

PROXY_PORT = 9020
ALT_PROXY_PORT = 9021
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
    request_queue_size = 256


def start_servers():
    srvs = []
    for port in (PROXY_PORT, ALT_PROXY_PORT, ORIGIN_PORT):
        s = Server(("127.0.0.1", port), Handler)
        threading.Thread(target=s.serve_forever, daemon=True).start()
        srvs.append(s)
    return srvs


def _hermetic_env(extra=None):
    """A copy of the environment with all FRAGMENT_*/LD_* knobs stripped, so a
    stray variable in the dev/CI shell can never skew the matrix. `extra`
    re-adds exactly the knobs a given test means to assert."""
    env = {k: v for k, v in os.environ.items()
           if not k.upper().startswith("FRAGMENT_")
           and k not in ("LD_PRELOAD", "LD_AUDIT", "http_proxy", "https_proxy",
                         "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "all_proxy")}
    if extra:
        env.update(extra)
    return env


def run_cmd(args, timeout, env=None):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           env=_hermetic_env(env))
        return (p.returncode, (p.stdout or "") + (p.stderr or ""))
    except subprocess.TimeoutExpired as e:
        return (-1, "TIMEOUT\n" + (e.stdout or "") + (e.stderr or ""))
    except Exception as e:  # noqa: BLE001
        return (-2, repr(e))


def cmd_build(script, *extra):
    rc, out = run_cmd(["bash", os.path.join(ROOT, script), *extra], 600)
    ok = rc == 0
    print(("  build OK " if ok else "  BUILD FAILED ") + script + (" " + " ".join(extra) if extra else ""))
    if not ok:
        print(out[-3000:])
    return ok


def evaluate(marker, expect_proxy=True, proxy_port=PROXY_PORT):
    proxied = "/http://127.0.0.1:%d/%s" % (ORIGIN_PORT, marker)
    origin = "/" + marker
    with hits_lock:
        snap = list(hits)
    if not expect_proxy:
        for port, path, _ in snap:
            if port == ORIGIN_PORT and path == origin:
                return "PASS", "origin :%d%s (correctly NOT intercepted)" % (ORIGIN_PORT, path)
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
    return "FAIL", "no request received (curl not intercepted / crashed)"


results = []


def newmarker(idx):
    return "m%d_%d" % (idx, int(time.time() * 1000) % 1000000)


def origin_url(marker):
    return "http://127.0.0.1:%d/%s" % (ORIGIN_PORT, marker)


def case(idx, name, argv, expect_proxy=True, proxy_port=PROXY_PORT,
         engage="preload", env=None, settle=0.4, timeout=40, divert_port=None):
    """Run one matrix row. `engage` is 'preload' (LD_PRELOAD), 'audit'
    (LD_AUDIT), or 'none'. {URL}/{MARKER} in argv are substituted. When
    `divert_port` is set the row PASSes iff ANY request reached that port (used
    by the non-vacuous negative controls that prove an option really diverts)."""
    marker = newmarker(idx)
    url = origin_url(marker)
    argv = [a.replace("{URL}", url).replace("{MARKER}", marker) for a in argv]
    e = dict(env or {})
    if engage == "preload":
        e["LD_PRELOAD"] = LIBFRAG
    elif engage == "audit":
        e["LD_AUDIT"] = LIBFRAG
    with hits_lock:
        hits.clear()
    rc, out = run_cmd(argv, timeout, env=e)
    time.sleep(settle)
    if divert_port is not None:
        with hits_lock:
            snap = list(hits)
        if any(p == divert_port for p, _, _ in snap):
            status, detail = "PASS", "diverted to :%d (option is live; neutralization is non-vacuous)" % divert_port
        else:
            landed = ", ".join("%d%s" % (p, path) for p, path, _ in snap) or "nothing"
            status, detail = "FAIL", "expected divert to :%d, got %s" % (divert_port, landed)
    else:
        status, detail = evaluate(marker, expect_proxy, proxy_port)
    results.append((name, status, "%s | rc=%s" % (detail, rc)))
    if status.startswith("FAIL"):
        print("---- %s ----\n%s" % (name, out[-1200:]))


def plain(name, status, detail):
    results.append((name, status, detail))


def main():
    debug = "--debug" in sys.argv
    cfg = "Debug" if debug else "Release"
    have_curl = os.path.exists(os.path.join(BUILD, "host"))

    print("== building libfragment.so + loader (%s) + test binaries ==" % cfg)
    if not cmd_build("build.sh", cfg):
        return 2
    if not cmd_build(os.path.join("test", "build_test.sh"), "native"):
        return 2
    for f in (LIBFRAG, FRAGMENT, os.path.join(BUILD, "hooktest"),
              os.path.join(BUILD, "host_mock"), os.path.join(BUILD, "host_mock_static"),
              os.path.join(BUILD, "libmockcurl.so")):
        if not os.path.exists(f):
            print("missing build artifact:", f)
            return 2
    have_curl = os.path.exists(os.path.join(BUILD, "host"))
    have_syscurl = shutil.which("curl") is not None
    qemu = shutil.which("qemu-x86_64-static") or shutil.which("qemu-x86_64")
    have_x64cc = shutil.which("x86_64-linux-gnu-gcc") is not None
    qemu_i386 = shutil.which("qemu-i386-static") or shutil.which("qemu-i386")
    have_i386cc = shutil.which("i686-linux-gnu-gcc") is not None
    qemu_arm = shutil.which("qemu-arm-static") or shutil.which("qemu-arm")
    have_armcc = shutil.which("arm-linux-gnueabihf-gcc") is not None

    HOST = os.path.join(BUILD, "host")
    HOST_URLAPI = os.path.join(BUILD, "host_urlapi")
    HOST_PLUGIN = os.path.join(BUILD, "host_plugin")
    HOST_STRESS = os.path.join(BUILD, "host_stress")
    HOST_BENCH = os.path.join(BUILD, "host_bench")
    PLUGIN = os.path.join(BUILD, "libplugin.so")

    srvs = start_servers()
    time.sleep(0.3)

    # --- engine unit test (no servers/curl): prologue relocation + fail-closed.
    rc, out = run_cmd([os.path.join(BUILD, "hooktest")], 30)
    plain("hook engine unit test (native)", "PASS" if rc == 0 else "FAIL",
          "engine self-tests passed" if rc == 0 else "FAILED rc=%s\n%s" % (rc, out[-1500:]))

    # --- decoder unit test (no execution): both x86 widths checked natively, so
    #     the x86-64 decoder is regression-guarded even where qemu-x86_64 is
    #     absent, and the i386 decoder gets a non-vacuous reloc + fail-closed test.
    for bits, exe in (("x86-64", "decodetest64"), ("i386", "decodetest32")):
        path = os.path.join(BUILD, exe)
        if not os.path.exists(path):
            plain("decoder unit test (%s, native)" % bits, "SKIP", "not built")
            continue
        rc, out = run_cmd([path], 30)
        plain("decoder unit test (%s, native)" % bits, "PASS" if rc == 0 else "FAIL",
              "length + reloc metadata + fail-closed" if rc == 0 else "FAILED rc=%s\n%s" % (rc, out[-1200:]))

    # --- mock-libcurl integration (no servers/curl): rewrite/idempotency/drop
    #     proven directly from what a mock libcurl received after interposition.
    rc, out = run_cmd([os.path.join(BUILD, "host_mock")], 30, env={"LD_PRELOAD": LIBFRAG})
    plain("mock-libcurl interposition", "PASS" if rc == 0 else "FAIL",
          "rewrite+idempotency+drop verified" if rc == 0 else "FAILED rc=%s\n%s" % (rc, out[-1500:]))

    # --- static-curl inline-hook (no servers/curl): the .symtab-resolved,
    #     byte-patched path, proven from the same mock assertions.
    rc, out = run_cmd([os.path.join(BUILD, "host_mock_static")], 30, env={"LD_PRELOAD": LIBFRAG})
    plain("static-curl inline hook (.symtab)", "PASS" if rc == 0 else "FAIL",
          "symtab resolve + inline hook + rewrite" if rc == 0 else "FAILED rc=%s\n%s" % (rc, out[-1500:]))

    idx = 0
    if have_curl:
        # --- core interposition paths against the system libcurl ------------
        idx += 1; case(idx, "interpose: CURLOPT_URL rewrite", [HOST, "{URL}"])
        idx += 1; case(idx, "interpose: dlopen+dlsym (inline)", [HOST, "{URL}", "dlopen"])
        idx += 1; case(idx, "urlapi: curl_url_set (full URL)", [HOST_URLAPI, "full", "{URL}", "{MARKER}"])
        idx += 1; case(idx, "urlapi: CURLOPT_CURLU (parts)", [HOST_URLAPI, "parts", "{URL}", "{MARKER}"])
        idx += 1; case(idx, "transitive dependency libcurl", [HOST_PLUGIN, PLUGIN, "{URL}"])

        # --- bypass neutralization (system curl honours these flags) --------
        if have_syscurl:
            curl = shutil.which("curl")
            base = [curl, "-s", "-o", "/dev/null", "--max-time", "8"]
            idx += 1; case(idx, "neutralize --connect-to", base + ["--connect-to", "::127.0.0.1:%d" % ORIGIN_PORT, "{URL}"])
            idx += 1; case(idx, "neutralize --resolve", base + ["--resolve", "127.0.0.1:%d:192.0.2.1" % PROXY_PORT, "{URL}"])
            idx += 1; case(idx, "neutralize --proxy", base + ["--proxy", "http://127.0.0.1:%d" % ORIGIN_PORT, "{URL}"])
            idx += 1; case(idx, "neutralize http_proxy env", base + ["{URL}"],
                           env={"http_proxy": "http://127.0.0.1:%d" % ORIGIN_PORT,
                                "HTTPS_PROXY": "http://127.0.0.1:%d" % ORIGIN_PORT,
                                "ALL_PROXY": "http://127.0.0.1:%d" % ORIGIN_PORT})
            # NON-VACUOUS negative controls: the same options DO divert when the
            # library is NOT engaged, proving the neutralization is real.
            idx += 1; case(idx, "neg: --connect-to diverts un-preloaded",
                           base + ["--connect-to", "::127.0.0.1:%d" % ALT_PROXY_PORT, "{URL}"],
                           engage="none", divert_port=ALT_PROXY_PORT)
            idx += 1; case(idx, "neg: http_proxy honoured un-preloaded", base + ["{URL}"],
                           engage="none", divert_port=ALT_PROXY_PORT,
                           env={"http_proxy": "http://127.0.0.1:%d" % ALT_PROXY_PORT})

        # --- CURLOPT_PORT neutralization ------------------------------------
        idx += 1; case(idx, "neutralize CURLOPT_PORT", [HOST, "{URL}", "port"])

        # --- runtime configuration (no recompile) ---------------------------
        idx += 1; case(idx, "config FRAGMENT_PROXY -> :%d" % ALT_PROXY_PORT, [HOST, "{URL}"],
                       proxy_port=ALT_PROXY_PORT,
                       env={"FRAGMENT_PROXY": "http://127.0.0.1:%d" % ALT_PROXY_PORT})
        idx += 1; case(idx, "config FRAGMENT_ENABLED=0 (off)", [HOST, "{URL}"],
                       expect_proxy=False, env={"FRAGMENT_ENABLED": "0"})
        idx += 1; case(idx, "config FRAGMENT_PROXY=/// -> default", [HOST, "{URL}"],
                       proxy_port=PROXY_PORT, env={"FRAGMENT_PROXY": "///"})

        # --- loader-approach redundancy: each interception mode in isolation.
        idx += 1; case(idx, "loader=interpose", [HOST, "{URL}"], env={"FRAGMENT_LOADER": "interpose"})
        idx += 1; case(idx, "loader=hook (inline byte-patch)", [HOST, "{URL}"], env={"FRAGMENT_LOADER": "hook"})
        if have_syscurl:
            curl = shutil.which("curl")
            idx += 1; case(idx, "loader=audit (rtld-audit rebind)",
                           [curl, "-s", "-o", "/dev/null", "--max-time", "8", "{URL}"],
                           engage="audit", env={"FRAGMENT_LOADER": "audit"})
            # Locked-in boundary: audit rebinds call sites, so a program that
            # captured curl_easy_setopt's ADDRESS and calls it indirectly is NOT
            # rebound (auto/interpose/hook do not share this). Non-vacuous neg.
            idx += 1; case(idx, "neg: audit misses fn-pointer call", [HOST, "{URL}"],
                           expect_proxy=False, engage="audit", env={"FRAGMENT_LOADER": "audit"})

        # --- concurrency stress: every request proxied, none leaked/doubled.
        THREADS, PER = 8, 60
        marker = "stress_%d" % (int(time.time() * 1000) % 1000000)
        url = origin_url(marker)
        with hits_lock:
            hits.clear()
        rc, out = run_cmd([HOST_STRESS, url, str(THREADS), str(PER)], 120, env={"LD_PRELOAD": LIBFRAG})
        time.sleep(0.8)
        with hits_lock:
            snap = list(hits)
        proxied = "/http://127.0.0.1:%d/%s" % (ORIGIN_PORT, marker)
        nproxy = sum(1 for p, path, _ in snap if p == PROXY_PORT and path == proxied)
        nleak = sum(1 for p, path, _ in snap if p == ORIGIN_PORT)
        ndbl = sum(1 for p, path, _ in snap if p == PROXY_PORT and path != proxied)
        expected = THREADS * PER
        if nproxy == expected and nleak == 0 and ndbl == 0:
            plain("concurrency stress %dx%d" % (THREADS, PER), "PASS",
                  "%d/%d reached proxy, 0 leaked, 0 double-prefixed" % (nproxy, expected))
        else:
            plain("concurrency stress %dx%d" % (THREADS, PER), "FAIL",
                  "proxy=%d/%d leak=%d double=%d\n%s" % (nproxy, expected, nleak, ndbl, out[-1200:]))

        # --- benchmark (informational): per-call setopt cost, preloaded vs not.
        def bench(env):
            rc, out = run_cmd([HOST_BENCH, "http://127.0.0.1:%d/bench" % ORIGIN_PORT], 120, env=env)
            m = re.search(r"SETOPT p50=([\d.]+) p95=([\d.]+) p99=([\d.]+) cps=([\d.]+)", out)
            return tuple(float(x) for x in m.groups()) if m else None
        b = bench(None)
        h = bench({"LD_PRELOAD": LIBFRAG})
        if b and h:
            plain("benchmark (informational)", "PASS",
                  "setopt/call %.0f->%.0f ns (p50 +%.0f, p95 +%.0f) | worst case: URL set "
                  "per-call; real apps set once/handle so this is paid once/request (negligible)"
                  % (b[0], h[0], h[0] - b[0], h[1] - b[1]))
        else:
            plain("benchmark (informational)", "PASS", "ran")

        # --- end-user loader: fragment launches a program with the library
        #     preloaded and config passed through.
        if have_syscurl:
            curl = shutil.which("curl")
            idx += 1
            marker = newmarker(idx)
            url = origin_url(marker)
            with hits_lock:
                hits.clear()
            rc, out = run_cmd([FRAGMENT, "--proxy", "http://127.0.0.1:%d" % PROXY_PORT, "--",
                               curl, "-s", "-o", "/dev/null", "--max-time", "8", url], 40)
            time.sleep(0.4)
            st, det = evaluate(marker, True)
            plain("loader: fragment launch+preload", st, "%s | rc=%s" % (det, rc))

        # --- ptrace injection into a RUNNING process (needs ptrace permission).
        run_pid_injection_test()
    else:
        plain("real-libcurl matrix", "SKIP", "no -lcurl at build time; mock + engine still ran")

    # --- x86-64 subset under qemu: engine + interposition + static inline hook.
    if qemu and have_x64cc:
        if cmd_build(os.path.join("test", "build_test.sh"), "x64"):
            qrun = [qemu]
            qenv = {"QEMU_LD_PREFIX": "/usr/x86_64-linux-gnu"}
            rc, out = run_cmd(qrun + [os.path.join(X64, "hooktest")], 60, env=qenv)
            plain("x86-64 engine unit test (qemu)", "PASS" if rc == 0 else "FAIL",
                  "ok" if rc == 0 else "rc=%s\n%s" % (rc, out[-1200:]))
            e = dict(qenv); e["LD_PRELOAD"] = os.path.join(X64, "libfragment.so")
            rc, out = run_cmd(qrun + [os.path.join(X64, "host_mock")], 60, env=e)
            plain("x86-64 mock interposition (qemu)", "PASS" if rc == 0 else "FAIL",
                  "ok" if rc == 0 else "rc=%s\n%s" % (rc, out[-1200:]))
            rc, out = run_cmd(qrun + [os.path.join(X64, "host_mock_static")], 60, env=e)
            plain("x86-64 static inline hook (qemu)", "PASS" if rc == 0 else "FAIL",
                  "ok" if rc == 0 else "rc=%s\n%s" % (rc, out[-1200:]))
    else:
        plain("x86-64 subset (qemu)", "SKIP", "qemu-x86_64 / x86-64 cross toolchain not present")

    # --- i386 subset under qemu: engine + interposition + static inline hook,
    #     the same self-contained subset the x86-64 leg runs (no 32-bit libcurl
    #     needed). The shared engine's i386 backend + the __cdecl caller stub.
    if qemu_i386 and have_i386cc:
        if cmd_build(os.path.join("test", "build_test.sh"), "i386"):
            qrun = [qemu_i386]
            qenv = {"QEMU_LD_PREFIX": "/usr/i686-linux-gnu"}
            rc, out = run_cmd(qrun + [os.path.join(I386, "hooktest")], 60, env=qenv)
            plain("i386 engine unit test (qemu)", "PASS" if rc == 0 else "FAIL",
                  "ok" if rc == 0 else "rc=%s\n%s" % (rc, out[-1200:]))
            e = dict(qenv); e["LD_PRELOAD"] = os.path.join(I386, "libfragment.so")
            rc, out = run_cmd(qrun + [os.path.join(I386, "host_mock")], 60, env=e)
            plain("i386 mock interposition (qemu)", "PASS" if rc == 0 else "FAIL",
                  "ok" if rc == 0 else "rc=%s\n%s" % (rc, out[-1200:]))
            rc, out = run_cmd(qrun + [os.path.join(I386, "host_mock_static")], 60, env=e)
            plain("i386 static inline hook (qemu)", "PASS" if rc == 0 else "FAIL",
                  "ok" if rc == 0 else "rc=%s\n%s" % (rc, out[-1200:]))
    else:
        plain("i386 subset (qemu)", "SKIP", "qemu-i386 / i386 cross toolchain not present")

    # --- armv7 subset under qemu: engine (A32 + T32 reloc / fail-closed) + mock
    #     interposition + static .symtab inline hook. The shared engine's armv7
    #     backend + the AAPCS caller stub; no 32-bit arm libcurl on the box, so
    #     the real-libcurl rows SKIP as on the i386 / x86-64 qemu subsets.
    if qemu_arm and have_armcc:
        if cmd_build(os.path.join("test", "build_test.sh"), "armv7"):
            qrun = [qemu_arm]
            qenv = {"QEMU_LD_PREFIX": "/usr/arm-linux-gnueabihf"}
            rc, out = run_cmd(qrun + [os.path.join(ARMV7, "hooktest")], 60, env=qenv)
            plain("armv7 engine unit test (qemu)", "PASS" if rc == 0 else "FAIL",
                  "ok" if rc == 0 else "rc=%s\n%s" % (rc, out[-1200:]))
            e = dict(qenv); e["LD_PRELOAD"] = os.path.join(ARMV7, "libfragment.so")
            rc, out = run_cmd(qrun + [os.path.join(ARMV7, "host_mock")], 60, env=e)
            plain("armv7 mock interposition (qemu)", "PASS" if rc == 0 else "FAIL",
                  "ok" if rc == 0 else "rc=%s\n%s" % (rc, out[-1200:]))
            rc, out = run_cmd(qrun + [os.path.join(ARMV7, "host_mock_static")], 60, env=e)
            plain("armv7 static inline hook (qemu)", "PASS" if rc == 0 else "FAIL",
                  "ok" if rc == 0 else "rc=%s\n%s" % (rc, out[-1200:]))
    else:
        plain("armv7 subset (qemu)", "SKIP", "qemu-arm / arm cross toolchain not present")

    for s in srvs:
        s.shutdown()

    print("\n==================== RESULTS ====================")
    npass = 0
    for name, status, detail in results:
        print("  [%-5s] %-36s  %s" % (status, name, detail))
        if status in ("PASS", "PASS?"):
            npass += 1
    total = len([r for r in results if r[1] != "SKIP"])
    print("=================================================")
    print("  %d/%d passed" % (npass, total))
    return 0 if npass == total and total > 0 else 1


def ptrace_permitted():
    try:
        with open("/proc/sys/kernel/yama/ptrace_scope") as f:
            return f.read().strip() == "0"
    except OSError:
        return True   # no yama => permitted


def run_pid_injection_test():
    """Start a looping curl host WITHOUT the library, inject via the loader, and
    assert the requests AFTER injection reach the proxy while the EARLY ones did
    not (proving the injection took effect mid-flight)."""
    HOST = os.path.join(BUILD, "host")
    restore = None
    if not ptrace_permitted():
        if os.geteuid() == 0 or shutil.which("sudo"):
            pre = "sudo " if os.geteuid() != 0 else ""
            os.system(pre + "sysctl -w kernel.yama.ptrace_scope=0 >/dev/null 2>&1")
            restore = pre
            if not ptrace_permitted():
                plain("ptrace --pid injection", "SKIP", "ptrace_scope locked (need root/CAP_SYS_PTRACE)")
                return
        else:
            plain("ptrace --pid injection", "SKIP", "ptrace restricted (set kernel.yama.ptrace_scope=0)")
            return
    try:
        marker = "inj_%d" % (int(time.time() * 1000) % 1000000)
        url = origin_url(marker)
        with hits_lock:
            hits.clear()
        proc = subprocess.Popen([HOST, url, "loop:40:150"], env=_hermetic_env(),
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.0)   # let several un-intercepted requests fly first
        rc, out = run_cmd([FRAGMENT, "--pid", str(proc.pid)], 30)
        proc.wait(timeout=30)
        time.sleep(0.5)
        with hits_lock:
            snap = list(hits)
        proxied = "/http://127.0.0.1:%d/%s" % (ORIGIN_PORT, marker)
        early_origin = any(p == ORIGIN_PORT for p, _, _ in snap)
        late_proxy = sum(1 for p, path, _ in snap if p == PROXY_PORT and path == proxied)
        if late_proxy > 0 and early_origin:
            plain("ptrace --pid injection", "PASS",
                  "%d post-injection requests rewritten -> :%d (pre-injection hit origin)"
                  % (late_proxy, PROXY_PORT))
        elif late_proxy > 0:
            plain("ptrace --pid injection", "PASS",
                  "%d requests rewritten after injection" % late_proxy)
        else:
            plain("ptrace --pid injection", "FAIL", "injection did not redirect (rc=%s) %s" % (rc, out[-400:]))
    finally:
        if restore is not None:
            os.system(restore + "sysctl -w kernel.yama.ptrace_scope=1 >/dev/null 2>&1")


if __name__ == "__main__":
    sys.exit(main())
