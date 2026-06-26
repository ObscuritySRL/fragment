#!/usr/bin/env python3
"""Offline-validate every signature in main.c against REAL libcurl bytes,
so we know exactly which fallbacks are evidence-backed vs. only reasoned.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe import exports


def parse_table(name):
    txt = open(os.path.join(os.path.dirname(__file__), "..", "main.c"),
               encoding="utf-8", errors="ignore").read()
    body = txt.split(name + "[]", 1)[1].split("};", 1)[0]
    pair = re.compile(r'\{\s*"((?:\\x[0-9A-Fa-f]{2})+)"\s*,\s*"([x?]+)"\s*\}')
    out = []
    for m in pair.finditer(body):
        pat = bytes(int(b, 16) for b in re.findall(r"\\x([0-9A-Fa-f]{2})", m.group(1)))
        out.append((pat, m.group(2)))
    return out


def match(code, pat, mask, off=0):
    if len(code) < off + len(mask):
        return False
    return all(mask[i] != "x" or code[off + i] == pat[i] for i in range(len(mask)))


def fbytes(path, name, n=64):
    if not os.path.exists(path):
        return None
    exp, f, rva2off = exports(path)
    if name not in exp:
        return b""
    o = rva2off(exp[name])
    return f[o:o + n]


GIT = r"C:\Program Files\Git\mingw64\bin\libcurl-4.dll"
AUD = r"D:\Audacity\libcurl.dll"
CFW = os.path.join(os.path.dirname(__file__), "curl", "libcurl-cfw820.dll")

setopt = parse_table("kSetoptSigs")
urlset = parse_table("kUrlSetSigs")
SN = ["orig/newMSVC", "oldMSVC730", "MinGW-GCC", "clang-CET", "clang-noCET"]
UN = ["MinGW-GCC", "clang-CET"]

print("=== curl_easy_setopt sigs vs real function bodies ===")
for label, path, want in [("GCC  Git 7.86", GIT, 2), ("clang cfw 8.20", CFW, 3)]:
    c = fbytes(path, "curl_easy_setopt")
    hit = [i for i, (p, m) in enumerate(setopt) if match(c, p, m)]
    print("  %-16s %s  matched=%s expect=%s -> %s"
          % (label, c[:14].hex(), [SN[i] for i in hit], SN[want],
             "OK" if hit == [want] else "CHECK"))
c = fbytes(CFW, "curl_easy_setopt")
print("  clang-noCET at +4 (skip endbr64): %s" % match(c, *setopt[4], off=4))

print("=== curl_url_set sigs vs real function bodies ===")
for label, path, want in [("GCC  Git 7.86", GIT, 0), ("clang cfw 8.20", CFW, 1)]:
    c = fbytes(path, "curl_url_set")
    hit = [i for i, (p, m) in enumerate(urlset) if match(c, p, m)]
    print("  %-16s %s  matched=%s expect=%s -> %s"
          % (label, c[:14].hex(), [UN[i] for i in hit], UN[want],
             "OK" if hit == [want] else "CHECK"))
c = fbytes(AUD, "curl_url_set")
print("  Audacity 7.82  %s  (E9 = ILT thunk -> export+FollowThunks path)" % c[:6].hex())
