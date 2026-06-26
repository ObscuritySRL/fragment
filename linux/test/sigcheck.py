#!/usr/bin/env python3
"""Offline validation of the static-fallback signatures in main.c (Linux).

The kSetoptSigs / kUrlSetSigs tables in main.c are ARCH-SPECIFIC: there is
one set behind `#if defined(__x86_64__)` and another behind the `#else`
(__aarch64__). This tool pulls BOTH out and reports on them, so a build for
either architecture can be reasoned about from a single machine.

For the architecture we are actually running on (aarch64 on this box) we do
not have to take the comments in main.c on faith: we read the REAL
curl_easy_setopt / curl_url_set bytes out of the system libcurl.so and
confirm the masked patterns match the live function entry. For the OTHER
architecture we can only validate when a matching libcurl is supplied --
pass an x86-64 libcurl path as an extra arg and the x86-64 block gets the
same treatment; with none provided it is reported as "reasoned-only" (its
patterns are derived from real GCC/CET amd64 bytes, just not re-checked in
this run).

Usage: sigcheck.py <main.c> [extra-libcurl-paths ...]

The static signatures only matter for STATICALLY-linked curl; shared-lib
libcurl is resolved through .dynsym (see elf.py) and never touches these
tables. We still validate them against the shared lib because the prologue
a given compiler emits is the same whether curl is linked static or shared.
"""
import glob
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import func_bytes  # noqa: E402

EM_X86_64 = 62      # e_machine for x86-64
EM_AARCH64 = 183    # e_machine for AArch64
PAIR = re.compile(r'\{\s*"((?:\\x[0-9A-Fa-f]{2})+)"\s*,\s*"([x?]+)"\s*\}')

# A signature is "evidence" only against bytes from the right compiler/config.
# These short tags let us print WHY a given line matched or (correctly) did
# not, keyed off the first 4 pattern bytes -- decoupled from table ordering.
PROLOGUE = {
    "3f2303d5": "PAC          (paciasp; sub sp)",
    "5f2403d5": "BTI+PAC      (bti c; paciasp)",
    "ff0000d1": "no-PAC sub   (sub sp,sp,#imm)",
    "fd7b00a9": "no-PAC stp   (stp x29,x30,[sp,#-imm]!)",
    "f30f1efa": "CET          (endbr64; push rbp)",
    "554889e5": "no-CET       (push rbp; mov rbp,rsp)",
}


def describe(pat):
    return PROLOGUE.get(pat[:4].hex(), "?            (%s)" % pat[:4].hex())


def arch_regions(main_c):
    """Return {'x86_64': <text>, 'aarch64': <text>} for the two #if arms."""
    txt = open(main_c, encoding="utf-8", errors="ignore").read()
    block = txt.split("#if defined(__x86_64__)", 1)[1].split("#endif", 1)[0]
    x86, arm = block.split("#else", 1)
    return {"x86_64": x86, "aarch64": arm}


def parse_table(region, table):
    """Pull (pattern_bytes, mask) pairs out of one named table in one region."""
    body = region.split(table + "[]", 1)[1].split("};", 1)[0]
    out = []
    for m in PAIR.finditer(body):
        pat = bytes(int(b, 16) for b in re.findall(r"\\x([0-9A-Fa-f]{2})", m.group(1)))
        out.append((pat, m.group(2)))
    return out


def match(code, pat, mask, off=0):
    """Masked compare: 'x' bytes must equal, '?' bytes are wildcards."""
    if code is None or len(code) < off + len(mask):
        return False
    return all(mask[i] != "x" or code[off + i] == pat[i] for i in range(len(mask)))


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
    """First real (symlink-resolved) system libcurl.so.4 of the given arch."""
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


def check_function(lib, fn, sigs):
    """Validate one table's signatures against one real function's prologue.

    Returns True if at least one signature anchors the real entry (i.e. the
    table can locate this function in a static binary built this way).
    """
    code = func_bytes(lib, fn)
    if not code:
        print("    %-16s : symbol not found in %s" % (fn, os.path.basename(lib)))
        return False
    hit = [i for i, (p, m) in enumerate(sigs) if match(code, p, m)]
    print("    %-16s real entry: %s" % (fn, code[:12].hex()))
    for i, (p, m) in enumerate(sigs):
        if i in hit:
            status = "OK    matches this binary's entry"
        else:
            # Not a failure: this fallback describes a DIFFERENT build config
            # (this distro libcurl is the GCC+PAC build), so it correctly does
            # not anchor here. We surface that rather than crying FAIL.
            status = "--    other build config (not this binary)"
        print("        sig[%d] %-34s %s" % (i, describe(p), status))
    verdict = "OK" if hit else "FAIL"
    print("      -> matched %s  =>  %s" % (hit, verdict))
    return bool(hit)


def check_block(arch, region, lib):
    setopt = parse_table(region, "kSetoptSigs")
    urlset = parse_table(region, "kUrlSetSigs")
    print("== %-8s ==  (%d setopt sigs, %d url_set sigs)"
          % (arch, len(setopt), len(urlset)))
    if not lib:
        print("    no %s libcurl provided -> reasoned-only: patterns are"
              " derived from real" % arch)
        print("    %s bytes captured elsewhere, but not validated in this run."
              % arch)
        return True   # unverified is not the same as failed
    print("    libcurl: %s" % lib)
    ok = check_function(lib, "curl_easy_setopt", setopt)
    ok = check_function(lib, "curl_url_set", urlset) and ok
    return ok


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: sigcheck.py <main.c> [extra-libcurl-paths ...]")
    main_c = sys.argv[1]
    extra = sys.argv[2:]
    regions = arch_regions(main_c)

    # aarch64: validate against THIS box's system libcurl (or an override).
    arm = next((p for p in extra if elf_machine(p) == EM_AARCH64), None) \
        or find_system_libcurl(EM_AARCH64)
    # x86_64: only validate if an amd64 libcurl was handed to us.
    x86 = next((p for p in extra if elf_machine(p) == EM_X86_64), None) \
        or find_system_libcurl(EM_X86_64)

    ok = True
    ok = check_block("aarch64", regions["aarch64"], arm) and ok
    ok = check_block("x86_64", regions["x86_64"], x86) and ok
    print("\n%s" % ("ALL VALIDATED SIGNATURES OK" if ok else "SOME SIGNATURES FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
