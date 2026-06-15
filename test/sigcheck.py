#!/usr/bin/env python3
"""Offline validation of the static-fallback signatures in main.c.

For binaries where a given compiler's signature is the intended match,
read the real curl_easy_setopt bytes and confirm the masked pattern
matches. This proves the GCC/clang/old-MSVC signatures are correct even
where the live matrix happens to take the export path instead.
"""
import re
import sys

sys.path.insert(0, __file__.rsplit("\\", 1)[0] if "\\" in __file__ else ".")
from pe import exports  # noqa: E402


def parse_sigs(main_c):
    """Pull (pattern_bytes, mask) pairs out of the kSetoptSigs table."""
    txt = open(main_c, "r", encoding="utf-8", errors="ignore").read()
    tbl = txt.split("kSetoptSigs[]", 1)[1].split("};", 1)[0]
    out = []
    for m in re.finditer(r'\{\s*"((?:\\x[0-9A-Fa-f]{2})+)"\s*,\s*"([x?]+)"\s*\}', tbl):
        pat = bytes(int(b, 16) for b in re.findall(r"\\x([0-9A-Fa-f]{2})", m.group(1)))
        out.append((pat, m.group(2)))
    return out


def match(code, pat, mask):
    if len(code) < len(mask):
        return False
    for i, mk in enumerate(mask):
        if mk == "x" and code[i] != pat[i]:
            return False
    return True


def setopt_bytes(path):
    exp, f, rva2off = exports(path)
    if "curl_easy_setopt" not in exp:
        return None
    off = rva2off(exp["curl_easy_setopt"])
    return f[off:off + 64]


def main():
    main_c = sys.argv[1]
    sigs = parse_sigs(main_c)
    names = ["orig/newMSVC", "oldMSVC-7.30", "MinGW-GCC", "clang-CET", "clang-noCET"]
    print("parsed %d signatures from %s" % (len(sigs), main_c))

    # (label, file, index of the signature that should match)
    cases = [
        ("libcurl 7.86 MinGW-GCC", r"C:\Program Files\Git\mingw64\bin\libcurl-4.dll", 2),
        ("libcurl 8.20 clang", sys.argv[2], 3),
    ]
    ok = True
    for label, path, want in cases:
        code = setopt_bytes(path)
        if code is None:
            print("  %-26s : no export (skip)" % label)
            continue
        hit = [i for i, (p, m) in enumerate(sigs) if match(code, p, m)]
        good = want in hit
        ok &= good
        print("  %-26s : %s  matched=%s  (expected %s '%s')"
              % (label, "OK" if good else "FAIL",
                 [names[i] for i in hit], names[want], names[want]))
        print("      prologue: %s" % code[:32].hex())
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
