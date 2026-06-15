#!/usr/bin/env python3
"""Tiny PE inspector: dump the first bytes of an exported function.

Usage: pe.py <pefile> [exportname ...]
Prints, for each export, its RVA and first 48 code bytes (file image).
Used to study real curl_easy_setopt prologues across compilers.
"""
import struct
import sys


def load(path):
    f = open(path, "rb").read()
    e = struct.unpack_from("<I", f, 0x3C)[0]
    assert f[e:e + 4] == b"PE\0\0", "not a PE"
    nsec = struct.unpack_from("<H", f, e + 6)[0]
    opt = e + 24
    magic = struct.unpack_from("<H", f, opt)[0]
    is64 = magic == 0x20B
    dd = opt + (112 if is64 else 96)
    exp_rva, exp_sz = struct.unpack_from("<II", f, dd)
    so = e + 24 + struct.unpack_from("<H", f, e + 20)[0]
    secs = []
    for i in range(nsec):
        b = so + 40 * i
        vr = struct.unpack_from("<I", f, b + 12)[0]
        vs = struct.unpack_from("<I", f, b + 8)[0]
        pr = struct.unpack_from("<I", f, b + 20)[0]
        ps = struct.unpack_from("<I", f, b + 16)[0]
        secs.append((vr, max(vs, ps), pr))

    def rva2off(r):
        for vr, sz, pr in secs:
            if vr <= r < vr + sz:
                return pr + (r - vr)
        return None

    return f, is64, exp_rva, rva2off


def exports(path):
    f, is64, exp_rva, rva2off = load(path)
    if exp_rva == 0:
        return {}, f, rva2off
    o = rva2off(exp_rva)
    nfun, nname = struct.unpack_from("<II", f, o + 20)
    a_fun = struct.unpack_from("<I", f, o + 28)[0]
    a_nam = struct.unpack_from("<I", f, o + 32)[0]
    a_ord = struct.unpack_from("<I", f, o + 36)[0]
    of, on, oo = rva2off(a_fun), rva2off(a_nam), rva2off(a_ord)
    out = {}
    for i in range(nname):
        nrva = struct.unpack_from("<I", f, on + 4 * i)[0]
        no = rva2off(nrva)
        nm = f[no:f.index(b"\0", no)].decode("latin1")
        ordi = struct.unpack_from("<H", f, oo + 2 * i)[0]
        frva = struct.unpack_from("<I", f, of + 4 * ordi)[0]
        out[nm] = frva
    return out, f, rva2off


def main():
    path = sys.argv[1]
    wanted = sys.argv[2:] or ["curl_easy_setopt"]
    exp, f, rva2off = exports(path)
    print("# %s  (%d exports)" % (path, len(exp)))
    for nm in wanted:
        if nm not in exp:
            print("  %-22s NOT EXPORTED" % nm)
            continue
        rva = exp[nm]
        off = rva2off(rva)
        code = f[off:off + 48]
        print("  %-22s rva=0x%06x  %s" % (nm, rva, code.hex()))


if __name__ == "__main__":
    main()
