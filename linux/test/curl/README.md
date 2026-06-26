# libcurl test corpus (not committed)

These real-world libcurl builds broaden the **offline signature validation**
(`test/verify_sigs.py` and `test/sigcheck.py`): they let those tools check the
static-fallback prologue signatures in `main.c` against actual compiled
`curl_easy_setopt` / `curl_url_set` bodies from more than one compiler and
architecture. They are third-party binaries and are intentionally git-ignored
(see `.gitignore`: `/test/curl/*.so`, `/test/curl/*.so.*`, `/test/curl/curl-*`).

You usually do **not** need this directory. The end-to-end matrix in
`test/run.py` drives the **system** libcurl (`/lib/<triple>/libcurl.so.4`) and
the **system** `curl` binary directly, plus a self-contained mock; it never
reads `test/curl/`. This corpus exists solely to feed the offline validators,
so a fresh checkout with an empty `test/curl/` is fine -- the aarch64 row is
validated against the libcurl already installed on the box, and the x86-64 row
simply reports "reasoned-only / not validated in this run" until you stage one.

Reproduce locally on Linux:

| File                     | libcurl | Compiler            | Source |
|--------------------------|---------|---------------------|--------|
| (system, not in this dir)| 8.5.0   | GCC 13, AArch64 PAC | the distro shared lib already at `/lib/aarch64-linux-gnu/libcurl.so.4` -- `verify_sigs.py` reads it in place, nothing to copy |
| (system, not in this dir)| 8.5.0   | GCC 13, AArch64     | the distro static archive at `/usr/lib/aarch64-linux-gnu/libcurl.a` (member `libcurl_la-setopt.o`); extract with `ar x libcurl.a libcurl_la-setopt.o` then `elf.py libcurl_la-setopt.o` -- this is the real static-link path the signatures exist for |
| `libcurl-x86_64.so`      | 8.5.0   | GCC 13, x86-64 CET  | from the Ubuntu `libcurl4t64` **amd64** `.deb` (see below) -- gives an x86-64 body to validate the `#if defined(__x86_64__)` signatures on a non-amd64 box |

The distro shared/static libs above need no download: substitute your own
triple if it differs (`gcc -dumpmachine`, e.g. `x86_64-linux-gnu` on amd64).

To get an x86-64 libcurl on a non-amd64 box (so the x86-64 `#if` block becomes
evidence-backed rather than reasoned-only), pull the amd64 `.deb` straight from
the Ubuntu pool and unpack it -- no `dpkg -i`, no cross-install, just the bytes:

```sh
# 24.04 "noble"; bump the version to whatever the pool currently carries
URL=http://archive.ubuntu.com/ubuntu/pool/main/c/curl
wget "$URL/libcurl4t64_8.5.0-2ubuntu10.9_amd64.deb" -O /tmp/libcurl-amd64.deb
dpkg-deb -x /tmp/libcurl-amd64.deb /tmp/libcurl-amd64
cp /tmp/libcurl-amd64/usr/lib/x86_64-linux-gnu/libcurl.so.4.* \
   test/curl/libcurl-x86_64.so
```

(`archive.ubuntu.com` mirrors the same tree; ports.ubuntu.com is the arm64 one.
Any libcurl `.so` of the desired arch works -- the validators pick a file up by
reading its ELF `e_machine`, not by its name, so the filename is just a label.)

With the file in place, re-run from `test/`:

```sh
python3 verify_sigs.py ../main.c     # x86-64 lines flip from reasoned-only to OK
python3 sigcheck.py  ../main.c       # or: sigcheck.py ../main.c curl/libcurl-x86_64.so
```

These third-party binaries are intentionally **not committed** (see the title):
a fresh checkout has none of them, the validators report the missing arch as
"reasoned-only", and staging the file above turns that row into an
evidence-backed `OK`. The aarch64 signatures are always validated, because the
running system already provides an aarch64 libcurl.

The corpus, taken together with the live system libcurl, lets the validators
cover both architectures `main.c` builds for (x86-64 System V with CET/endbr64,
and AArch64 with pointer authentication) and both link paths the signatures
guard: the shared-object path (resolved via `.dynsym`, signatures unused) and
the static-link path (no dynamic symbol, signatures scanned).
