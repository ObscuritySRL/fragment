#!/usr/bin/env python3
"""Offline-validate every signature in main.c against REAL libcurl bytes,
so we know exactly which fallbacks are evidence-backed vs. only reasoned.

Linux port of the Windows test/verify_sigs.py. Same idea, but main.c carries
TWO arch-specific signature tables, so there are two stories to tell:

  * aarch64 -- validated here and now against the system
    /lib/<triple>/libcurl.so.4. We read the true curl_easy_setopt and
    curl_url_set prologues and show which signature index anchors each.
    As a bonus we also point out where the no-PAC fallbacks' instructions
    DO appear deeper in this PAC prologue: that proves the patterns are
    real aarch64 prologue bytes, even though (correctly) they do not anchor
    at the entry of this particular GCC+PAC build.
  * x86_64 -- validated only if an amd64 libcurl has been staged under
    test/curl/ (see test/curl/README.md; the `dpkg-deb -x` recipe). With
    none present we say so plainly: the x86-64 patterns are reasoned from
    real GCC/CET amd64 bytes captured elsewhere, but NOT re-validated in
    this run.

Run from test/:  python3 verify_sigs.py [../main.c]
"""
import glob
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import func_bytes  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
MAIN_C = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "main.c")
CORPUS = os.path.join(HERE, "curl")

EM_X86_64 = 62
EM_AARCH64 = 183
PAIR = re.compile(r'\{\s*"((?:\\x[0-9A-Fa-f]{2})+)"\s*,\s*"([x?]+)"\s*\}')

PROLOGUE = {
    "3f2303d5": "PAC      paciasp; sub sp",
    "5f2403d5": "BTI+PAC  bti c; paciasp",
    "ff0000d1": "no-PAC   sub sp,sp,#imm",
    "fd7b00a9": "no-PAC   stp x29,x30,[sp,#-imm]!",
    "f30f1efa": "CET      endbr64; push rbp",
    "554889e5": "no-CET   push rbp; mov rbp,rsp",
}


def describe(pat):
    return PROLOGUE.get(pat[:4].hex(), pat[:4].hex())


def regions():
    txt = open(MAIN_C, encoding="utf-8", errors="ignore").read()
    block = txt.split("#if defined(__x86_64__)", 1)[1].split("#endif", 1)[0]
    x86, arm = block.split("#else", 1)
    return {"x86_64": x86, "aarch64": arm}


def parse_table(region, table):
    body = region.split(table + "[]", 1)[1].split("};", 1)[0]
    out = []
    for m in PAIR.finditer(body):
        pat = bytes(int(b, 16) for b in re.findall(r"\\x([0-9A-Fa-f]{2})", m.group(1)))
        out.append((pat, m.group(2)))
    return out


def match(code, pat, mask, off=0):
    """Masked compare at a fixed offset -- the shared workhorse."""
    if code is None or len(code) < off + len(mask):
        return False
    return all(mask[i] != "x" or code[off + i] == pat[i] for i in range(len(mask)))


def find_at(code, pat, mask):
    """Lowest offset where the masked pattern occurs (FindPattern-style), or None."""
    for off in range(0, len(code) - len(mask) + 1):
        if match(code, pat, mask, off):
            return off
    return None


def elf_machine(path):
    try:
        head = open(path, "rb").read(20)
    except OSError:
        return None
    if head[:4] != b"\x7fELF":
        return None
    en = "<" if head[5] == 1 else ">"
    return struct.unpack_from(en + "H", head, 18)[0]


def find_system_libcurl(machine):
    seen = set()
    for g in ("/lib/*/libcurl.so.4*", "/usr/lib/*/libcurl.so.4*",
              "/lib/libcurl.so.4*", "/usr/lib/libcurl.so.4*"):
        for f in sorted(glob.glob(g)):
            real = os.path.realpath(f)
            if real in seen:
                continue
            seen.add(real)
            if elf_machine(real) == machine:
                return real
    return None


def find_corpus_libcurl(machine):
    """An amd64/whatever libcurl staged under test/curl/ (git-ignored)."""
    for g in ("libcurl*.so", "libcurl*.so.*"):
        for f in sorted(glob.glob(os.path.join(CORPUS, g))):
            if elf_machine(f) == machine:
                return f
    return None


def validate(lib, fn, sigs, want):
    """Print the real prologue, which sig anchors it, and OK/CHECK.

    `want` is the index we EXPECT to anchor this binary (the PAC/CET build).
    Mirrors the Windows verify_sigs `hit == [want] -> OK` framing.
    """
    code = func_bytes(lib, fn)
    if not code:
        print("  %-16s : not found in %s" % (fn, os.path.basename(lib)))
        return False
    hit = [i for i, (p, m) in enumerate(sigs) if match(code, p, m)]
    ok = hit == [want]
    print("  %-16s %s  matched=%s expect=[%d] -> %s"
          % (fn, code[:12].hex(), hit, want, "OK" if ok else "CHECK"))
    return ok


def main():
    reg = regions()

    print("=== aarch64: validated against the live system libcurl ===")
    lib = find_system_libcurl(EM_AARCH64)
    if not lib:
        print("  no aarch64 libcurl.so found on this system (unexpected here)")
    else:
        print("  libcurl: %s" % lib)
        setopt = parse_table(reg["aarch64"], "kSetoptSigs")
        urlset = parse_table(reg["aarch64"], "kUrlSetSigs")
        # The distro build is GCC + pointer-auth, i.e. signature index 0.
        validate(lib, "curl_easy_setopt", setopt, want=0)
        validate(lib, "curl_url_set", urlset, want=0)

        # Honest footnote: where the *other* setopt fallbacks live in this
        # very prologue. The no-PAC patterns are valid bytes that simply sit
        # past the paciasp, so they don't anchor the entry here; the BTI one
        # is absent because this binary wasn't built with branch-target ID.
        code = func_bytes(lib, "curl_easy_setopt")
        print("  setopt fallbacks vs this PAC prologue (%s ...):" % code[:8].hex())
        for i, (p, m) in enumerate(setopt):
            off = find_at(code, p, m)
            where = "anchors entry (+0)" if off == 0 else (
                "appears @+%d (real bytes, other build config)" % off
                if off is not None else "absent (other build config)")
            print("    sig[%d] %-30s %s" % (i, describe(p), where))

    print("=== x86_64: validated only if an amd64 libcurl is staged ===")
    x = find_corpus_libcurl(EM_X86_64)
    setopt = parse_table(reg["x86_64"], "kSetoptSigs")
    urlset = parse_table(reg["x86_64"], "kUrlSetSigs")
    if not x:
        print("  no amd64 libcurl under test/curl/ -> x86-64 signatures are")
        print("  reasoned from real GCC/CET amd64 bytes captured elsewhere,")
        print("  NOT validated in this run. See test/curl/README.md to stage one,")
        print("  then re-run to turn these into evidence-backed OK lines.")
        # Still show the patterns so the reader sees what would be checked.
        for i, (p, m) in enumerate(setopt):
            print("    setopt sig[%d] %s  (%s)" % (i, p.hex(), describe(p)))
        for i, (p, m) in enumerate(urlset):
            print("    url_set sig[%d] %s" % (i, p.hex()))
    else:
        print("  libcurl: %s" % x)
        # The Ubuntu/Debian amd64 build is GCC + CET (endbr64), i.e. index 0.
        validate(x, "curl_easy_setopt", setopt, want=0)
        validate(x, "curl_url_set", urlset, want=0)


if __name__ == "__main__":
    main()
