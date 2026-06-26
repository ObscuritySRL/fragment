#!/usr/bin/env python3
"""Tiny ELF inspector: dump the first bytes of a defined function symbol.

Usage: elf.py <elffile> [symbolname ...]   (default symbol: curl_easy_setopt)

Prints, for each requested symbol, its virtual address and the first 48
code bytes as they sit in the file image. Used to study real
curl_easy_setopt / curl_url_set prologues the same way the Windows side
uses test/pe.py -- pure-Python parsing with `struct`, no external modules,
so it runs on a bare box with nothing but the stdlib.

This is the ELF analog of test/pe.py. It understands plain 64-bit ELF
objects (ET_REL / ET_EXEC / ET_DYN, ELFCLASS64), so it works on a shared
libcurl.so AND on a single relocatable member of the static archive. It
deliberately does NOT crack open `ar` archives (.a) itself: pull a member
out with `ar x libcurl.a libcurl_la-setopt.o` first, then point elf.py at
the extracted `.o`.

Symbol resolution details that actually matter here:
  * We read BOTH .dynsym (the dynamic-linker table, the only one present in
    a stripped shared object) and .symtab (the full table, present in
    unstripped objects / .o files) and merge them. The distro
    libcurl.so.4 is stripped, so only .dynsym carries curl_easy_setopt.
  * Versioned symbols: in libcurl.so the string in .dynstr is just
    "curl_easy_setopt" -- the "@@CURL_OPENSSL_4" suffix that `nm` prints
    lives in the separate .gnu.version_d machinery, which we don't need to
    parse. But some objects DO embed "name@version" right in the string
    table, so we match on the part before '@' to cover both spellings.
  * We only accept a DEFINED symbol (st_shndx != SHN_UNDEF). An imported /
    undefined entry has no bytes in this file to show.
  * The file offset of the bytes is computed from the symbol's OWN section
    (st_shndx): file_off = sh_offset + (st_value - sh_addr). That one
    formula covers both worlds -- in a shared/exec object st_value is a
    vaddr and sh_addr is its load address, while in a relocatable .o
    sh_addr is 0 and st_value is already the in-section offset. For
    libcurl.so the executable segment happens to be identity-mapped
    (offset == vaddr), but we never assume that. Symbols with a special
    st_shndx (SHN_ABS / SHN_COMMON / ...) fall back to an address-range
    lookup over the loadable sections.
"""
import struct
import sys

SHN_UNDEF = 0      # "no section": an undefined / imported symbol
SHT_SYMTAB = 2
SHT_NOBITS = 8     # e.g. .bss -- occupies vaddr space but no file bytes
SHT_DYNSYM = 11


def load(path):
    """Parse the ELF64 header + section table.

    Returns (data, endian, sections, secname) where `sections` is a list of
    dicts and `secname(s)` resolves a section's name for readable errors.
    """
    data = open(path, "rb").read()
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file: %s" % path)
    if data[4] != 2:
        raise ValueError("only 64-bit ELF (ELFCLASS64) is supported: %s" % path)
    en = "<" if data[5] == 1 else ">"          # EI_DATA: 1 = little, 2 = big

    e_shoff = struct.unpack_from(en + "Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from(en + "H", data, 0x3A)[0]
    e_shnum = struct.unpack_from(en + "H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from(en + "H", data, 0x3E)[0]

    secs = []
    for i in range(e_shnum):
        b = e_shoff + i * e_shentsize
        (sh_name, sh_type, sh_flags, sh_addr, sh_off, sh_size,
         sh_link, sh_info, sh_align, sh_entsize) = \
            struct.unpack_from(en + "IIQQQQIIQQ", data, b)
        secs.append(dict(name=sh_name, type=sh_type, addr=sh_addr, off=sh_off,
                         size=sh_size, link=sh_link, entsize=sh_entsize))

    shstr_off = secs[e_shstrndx]["off"] if e_shnum else 0

    def cstr(base, idx):
        end = data.index(b"\0", base + idx)
        return data[base + idx:end].decode("latin1")

    def secname(s):
        return cstr(shstr_off, s["name"])

    return data, en, secs, secname


def vaddr2off(secs):
    """Build a vaddr -> file-offset mapper from the section table.

    Only sections that are actually present in the file image are usable:
    they have a nonzero load address and real bytes (not NOBITS / .bss).
    """
    loaded = [s for s in secs
              if s["addr"] and s["size"] and s["type"] != SHT_NOBITS]

    def f(v):
        for s in loaded:
            if s["addr"] <= v < s["addr"] + s["size"]:
                return s["off"] + (v - s["addr"])
        return None

    return f


def sym_offset(secs, st_shndx, st_value, addrmap):
    """File offset of a defined symbol, or None if it has no file bytes.

    Prefer the symbol's own section (st_shndx) -- correct for both
    relocatable and executable/shared objects. Special section indices
    (>= SHN_LORESERVE) fall back to the address-range map.
    """
    if 0 < st_shndx < len(secs) and st_shndx < 0xFF00:
        sec = secs[st_shndx]
        if sec["type"] == SHT_NOBITS:
            return None                           # lives in .bss: no bytes
        return sec["off"] + (st_value - sec["addr"])
    return addrmap(st_value)


def symbols(path):
    """Return ({base_name: (vaddr, file_offset)} for DEFINED symbols, data).

    .dynsym and .symtab agree on a symbol's value, so when both define a
    name we keep the first seen; the bytes are identical either way.
    """
    data, en, secs, _ = load(path)
    addrmap = vaddr2off(secs)
    syms = {}
    for s in secs:
        if s["type"] not in (SHT_SYMTAB, SHT_DYNSYM) or not s["entsize"]:
            continue
        strtab = secs[s["link"]]["off"]
        for j in range(s["size"] // s["entsize"]):
            sb = s["off"] + j * s["entsize"]
            st_name, st_info, st_other, st_shndx, st_value, st_size = \
                struct.unpack_from(en + "IBBHQQ", data, sb)
            if st_shndx == SHN_UNDEF or not st_name:
                continue                          # undefined / unnamed: skip
            end = data.index(b"\0", strtab + st_name)
            raw = data[strtab + st_name:end].decode("latin1")
            base = raw.split("@", 1)[0]           # strip "@@VER" if embedded
            off = sym_offset(secs, st_shndx, st_value, addrmap)
            syms.setdefault(base, (st_value, off))
    return syms, data


def func_bytes(path, name, n=64):
    """First `n` file-image bytes of a defined symbol, or None if absent.

    Shared with sigcheck.py / verify_sigs.py via `from elf import func_bytes`.
    """
    syms, data = symbols(path)
    base = name.split("@", 1)[0]
    if base not in syms:
        return None
    _, off = syms[base]
    if off is None:
        return None
    return data[off:off + n]


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: elf.py <elffile> [symbolname ...]")
    path = sys.argv[1]
    wanted = sys.argv[2:] or ["curl_easy_setopt"]
    syms, data = symbols(path)
    print("# %s  (%d defined symbols)" % (path, len(syms)))
    for nm in wanted:
        base = nm.split("@", 1)[0]
        if base not in syms:
            print("  %-22s NOT DEFINED" % nm)
            continue
        v, off = syms[base]
        if off is None:
            print("  %-22s vaddr=0x%06x  (no file bytes -- .bss?)" % (nm, v))
            continue
        code = data[off:off + 48]
        print("  %-22s vaddr=0x%06x  %s" % (nm, v, code.hex()))


if __name__ == "__main__":
    main()
