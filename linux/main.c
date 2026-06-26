#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <link.h>
#include "log.h"
#include "config.h"
#include "curl.h"
#include "util.h"
#include "../common/version.h"

// Build "<proxyPrefix><orig>" (default http://127.0.0.1:9020/<orig>, but the
// prefix is runtime-configurable). Returns NULL when no rewrite is needed
// (orig NULL/empty, or ALREADY carrying the configured prefix) or on OOM.
// Idempotent, so re-set URLs and the setopt<->url_set interplay never
// double-prefix. Free the result with free().
static char* BuildProxiedUrl(const char* orig) {
    if (!orig || !*orig) return NULL;
    if (strncmp(orig, gCfg.proxyPrefix, gCfg.proxyPrefixLen) == 0) return NULL;

    size_t n = strlen(orig);
    char* out = (char*) malloc(gCfg.proxyPrefixLen + n + 1);
    if (!out) return NULL;
    memcpy(out, gCfg.proxyPrefix, gCfg.proxyPrefixLen);
    memcpy(out + gCfg.proxyPrefixLen, orig, n + 1);
    return out;
}

// The shared rewrite core, used by BOTH the symbol-interposition path and the
// inline-hook detour, so the two never diverge. Covers every way a program sets
// the destination through the easy interface:
//   CURLOPT_URL        - rewrite the string URL
//   CURLOPT_CURLU      - rewrite the parsed URL handle in place
//   CURLOPT_RESOLVE    - drop (a DNS pin would divert off our proxy)
//   CURLOPT_CONNECT_TO - drop (connect-to would divert off our proxy)
//   CURLOPT_UNIX_SOCKET_PATH / CURLOPT_ABSTRACT_UNIX_SOCKET
//                      - drop (a Unix socket would replace the TCP path to :9020)
//   CURLOPT_PROXY      - force "" = direct (an upstream proxy would carry our
//   CURLOPT_PRE_PROXY    rewritten request off-box; "" also beats the env proxy)
//   CURLOPT_PORT       - drop (a port override would change our :9020)
// Returns the value to forward to the real setopt. When *toFree is set the
// caller frees it AFTER forwarding (the rewritten URL string).
static void* FragmentSetoptValue(void* curl, CURLoption option, void* arg,
                                 CurlUrlGetFn urlGet, CurlUrlSetFn urlSet, CurlFreeFn urlFree,
                                 char** toFree) {
    *toFree = NULL;
    if (option == CURLOPT_URL) {
        const char* origUrl = (const char*) arg;
        LogDebug("[setopt] CURLOPT_URL handle=%p url=%s\n", curl, origUrl ? origUrl : "(null)");
        char* newUrl = BuildProxiedUrl(origUrl);
        if (newUrl) { *toFree = newUrl; return newUrl; }
        return arg;
    } else if (option == CURLOPT_CURLU) {
        // A parsed URL handle. Read the assembled URL, rewrite it, and write it
        // back into the same handle (the app keeps using it).
        void* uh = arg;
        if (uh && urlGet && urlSet && urlFree) {
            char* cur = NULL;
            if (urlGet(uh, CURLUPART_URL, &cur, 0) == 0 && cur) {
                char* proxied = BuildProxiedUrl(cur);
                if (proxied) {
                    LogDebug("[setopt] CURLOPT_CURLU rewrite: %s\n", cur);
                    if (urlSet(uh, CURLUPART_URL, proxied, 0) != 0)
                        LogWarn("[setopt] curl_url_set rewrite failed; request may bypass the proxy\n");
                    free(proxied);
                }
                urlFree(cur);
            }
        }
        return arg;
    } else if (option == CURLOPT_RESOLVE || option == CURLOPT_CONNECT_TO ||
               option == CURLOPT_UNIX_SOCKET_PATH ||
               option == CURLOPT_ABSTRACT_UNIX_SOCKET) {
        // NULL clears a RESOLVE/CONNECT_TO list, and disables the Unix-socket
        // options -> curl uses normal TCP to our 127.0.0.1:9020 instead of a
        // local socket that would divert off-proxy.
        LogDebug("[setopt] dropping option %d (would divert traffic off-proxy)\n", option);
        return NULL;
    } else if (option == CURLOPT_PROXY || option == CURLOPT_PRE_PROXY) {
        // Forward "" (NOT NULL). Per libcurl, an empty proxy string forces a
        // DIRECT connection AND suppresses the http_proxy/all_proxy environment
        // variables -- whereas NULL is curl's default that FALLS BACK to those
        // env vars, which would re-enable the off-proxy divert.
        LogDebug("[setopt] forcing direct for proxy option %d (was off-proxy)\n", option);
        return (void*) "";
    } else if (option == CURLOPT_PORT) {
        LogDebug("[setopt] dropping CURLOPT_PORT (would override the proxy port)\n");
        return (void*) 0;
    }
    return arg;
}

/* Forward declarations of our own interposed exports, so we can take their
 * addresses (to tell "the real libcurl symbol" from "our shadow"). */
CURLcode  curl_easy_setopt(void* curl, CURLoption option, ...);
CURLUcode curl_url_set(void* handle, CURLUPart what, const char* part, unsigned int flags);

/* ---- shared runtime state ---------------------------------------------- */
// gRewrite: the interposers rewrite (AUTO/INTERPOSE). When 0 (disabled, or the
// HOOK/AUDIT modes, where the inline hook or the auditor does the rewriting)
// the interposers are inert pass-throughs, so exactly one layer ever rewrites.
static int gRewrite     = 0;
static int gHookDlopen  = 0;   // dlopen interposer installs inline hooks (AUTO/HOOK)
static volatile int gCurlHooked = 0;   // curl has been inline-hooked; stop re-scanning

// The real libcurl URL-API, resolved past our own interposers via RTLD_NEXT.
static CurlSetoptFn gRealSetopt = NULL;
static CurlUrlSetFn gRealUrlSet = NULL;
static CurlUrlGetFn gRealUrlGet = NULL;
static CurlFreeFn   gRealUrlFree = NULL;

// Resolve the REAL libcurl symbol, skipping our own interposer. RTLD_NEXT works
// when we are PRELOADed (we sit ahead of libcurl); when we are INJECTED into a
// running process we are a late, local dlopen with no successor, so RTLD_NEXT
// returns nothing and RTLD_DEFAULT (the global scope) finds the genuine
// libcurl. `ours` guards against resolving back to our own export.
static void* RealSym(const char* name, void* ours) {
    void* r = dlsym(RTLD_NEXT, name);
    if (r && r != ours) return r;
    r = dlsym(RTLD_DEFAULT, name);
    if (r && r != ours) return r;
    return NULL;
}

static void EnsureRealUrlApi(void) {
    if (!gRealUrlGet)  gRealUrlGet  = (CurlUrlGetFn) RealSym("curl_url_get", NULL);
    if (!gRealUrlSet)  gRealUrlSet  = (CurlUrlSetFn) RealSym("curl_url_set", (void*)&curl_url_set);
    if (!gRealUrlFree) gRealUrlFree = (CurlFreeFn)   RealSym("curl_free", NULL);
}

/* ======================================================================== */
/* Symbol interposition: the portable, primary interception. Our exported
 * curl_easy_setopt/curl_url_set shadow libcurl's for every program that calls
 * them through the dynamic symbol table -- a direct link, a transitive
 * dependency, or a dlopen with default scope -- on both x86-64 and aarch64,
 * with no machine code. An unversioned definition here satisfies a versioned
 * reference (curl_easy_setopt@CURL_OPENSSL_4), so it interposes every libcurl.
 */
__attribute__((visibility("default")))
CURLcode curl_easy_setopt(void* curl, CURLoption option, ...) {
    if (!gRealSetopt) gRealSetopt = (CurlSetoptFn) RealSym("curl_easy_setopt", (void*)&curl_easy_setopt);

    va_list ap;
    va_start(ap, option);
    void* arg = va_arg(ap, void*);       /* the single GP-word option value */
    va_end(ap);

    // Call the real curl_easy_setopt. It is variadic, so cast to a variadic
    // prototype (sets the vector-arg count to 0 per the ABI) and pass the one
    // value. `viaTrampoline` forwards past an incidental inline hook on the
    // same function (only relevant when both a dlopen inline-hook and PLT
    // interposition cover one handle).
    void* real = (void*) gRealSetopt;
    if (!real) return (CURLcode) -1;

    if (!gRewrite) {
        // Inert: pass through untouched (disabled / HOOK / AUDIT). In HOOK mode
        // `real` is itself inline-hooked, so the hook does the rewriting.
        return ((CURLcode(*)(void*, CURLoption, ...)) real)(curl, option, arg);
    }

    EnsureRealUrlApi();
    char* toFree = NULL;
    void* fwd = FragmentSetoptValue(curl, option, arg, gRealUrlGet, gRealUrlSet, gRealUrlFree, &toFree);

    void* tramp = FrTrampolineFor(real);
    void* callee = tramp ? tramp : real;
    CURLcode rc = ((CURLcode(*)(void*, CURLoption, ...)) callee)(curl, option, fwd);

    if (toFree) free(toFree);
    return rc;
}

__attribute__((visibility("default")))
CURLUcode curl_url_set(void* handle, CURLUPart what, const char* part, unsigned int flags) {
    if (!gRealUrlSet) gRealUrlSet = (CurlUrlSetFn) RealSym("curl_url_set", (void*)&curl_url_set);
    CurlUrlSetFn real = gRealUrlSet;
    if (!real) return (CURLUcode) -1;

    if (!gRewrite)
        return real(handle, what, part, flags);

    char* proxied = NULL;
    if (what == CURLUPART_URL && part) {
        proxied = BuildProxiedUrl(part);
        if (proxied) { LogDebug("[url_set] rewrite: %s\n", part); part = proxied; }
    }
    void* tramp = FrTrampolineFor((void*) real);
    CurlUrlSetFn callee = tramp ? (CurlUrlSetFn) tramp : real;
    CURLUcode rc = callee(handle, what, part, flags);
    if (proxied) free(proxied);
    return rc;
}

/* ======================================================================== */
/* Inline-hook path: reaches what interposition structurally cannot -- a
 * statically-linked curl (no dynamic symbol, the app calls its own internal
 * function), and the forced HOOK mode used to drive the engine against a
 * dynamic libcurl. `original` MUST be first: InstallHook writes the trampoline
 * into &ctx->original and GenerateCaller injects &ctx as the detour's first
 * argument, so &ctx->original == (void**)ctx.
 */
typedef struct {
    void*        original;
    CurlUrlGetFn urlGet;
    CurlUrlSetFn urlSet;
    CurlFreeFn   urlFree;
} CurlSetoptCtx;

typedef struct { void* original; } CurlUrlSetCtx;

CURLcode CurlSetoptDetourWithInstance(CurlSetoptCtx* ctx, void* curl, CURLoption option, void* arg) {
    char* toFree = NULL;
    void* fwd = FragmentSetoptValue(curl, option, arg, ctx->urlGet, ctx->urlSet, ctx->urlFree, &toFree);
    CURLcode rc = ((CURLcode(*)(void*, CURLoption, ...)) ctx->original)(curl, option, fwd);
    if (toFree) free(toFree);
    return rc;
}

CURLUcode CurlUrlSetDetour(CurlUrlSetCtx* ctx, void* handle, CURLUPart what, const char* part, unsigned int flags) {
    char* proxied = NULL;
    if (what == CURLUPART_URL && part) {
        proxied = BuildProxiedUrl(part);
        if (proxied) { LogDebug("[url_set] rewrite: %s\n", part); part = proxied; }
    }
    CURLUcode rc = ((CurlUrlSetFn) ctx->original)(handle, what, part, flags);
    if (proxied) free(proxied);
    return rc;
}

// Prologue signatures, one per compiler family, derived from real libcurl
// binaries. Only used for STATICALLY-linked curl, where there is no dynamic
// symbol to resolve. Shared-library libcurl never needs these (interposition
// or, in HOOK mode, RTLD_NEXT resolves it). The variable stack-frame immediate
// is masked, so a signature matches across frame sizes.
typedef struct { const char* pattern; const char* mask; } CurlSig;

#if defined(__x86_64__)
// Evidence-backed against GCC-built libcurl 8.5 (System V, CET/endbr64). The
// only variable byte in the window is the low byte of the stack-frame imm32,
// which is masked. CET-disabled builds drop the leading endbr64.
static const CurlSig kSetoptSigs[] = {
    // endbr64; push rbp; mov rbp,rsp; sub $frame,rsp
    { "\xf3\x0f\x1e\xfa\x55\x48\x89\xe5\x48\x81\xec\x00", "xxxxxxxxxxx?" },
    { "\x55\x48\x89\xe5\x48\x81\xec\x00",                 "xxxxxxx?"     },
};
static const CurlSig kUrlSetSigs[] = {
    // endbr64; push rbp; mov rbp,rsp; push r15; push r14
    { "\xf3\x0f\x1e\xfa\x55\x48\x89\xe5\x41\x57\x41\x56", "xxxxxxxxxxxx" },
    { "\x55\x48\x89\xe5\x41\x57\x41\x56",                 "xxxxxxxx"     },
};
#elif defined(__i386__)
// Best-effort, frame-pointer __cdecl prologues (CET endbr32 variant + plain), to
// be evidence-refined against a stripped i386 libcurl. A frameless build
// (-fomit-frame-pointer) is resolved by .symtab instead; this scan only matters
// for a stripped static curl, exactly as on the 64-bit ports.
static const CurlSig kSetoptSigs[] = {
    // endbr32; push ebp; mov ebp,esp
    { "\xf3\x0f\x1e\xfb\x55\x89\xe5", "xxxxxxx" },
    { "\x55\x89\xe5",                 "xxx"     },
};
static const CurlSig kUrlSetSigs[] = {
    // endbr32; push ebp; mov ebp,esp; push edi; push esi
    { "\xf3\x0f\x1e\xfb\x55\x89\xe5\x57\x56", "xxxxxxxxx" },
    { "\x55\x89\xe5\x57\x56",                 "xxxxx"     },
};
#else /* __aarch64__ */
static const CurlSig kSetoptSigs[] = {
    // GCC/Clang with pointer auth (the distro default): paciasp; sub sp,sp,#imm.
    { "\x3f\x23\x03\xd5\xff\x00\x00\xd1", "xxxxx??x" },
    // BTI + PAC: bti c; paciasp ...  (bti c = 5f 24 03 d5)
    { "\x5f\x24\x03\xd5\x3f\x23\x03\xd5", "xxxxxxxx" },
    // No pointer auth: sub sp,sp,#imm  or  stp x29,x30,[sp,#-imm]!
    { "\xff\x00\x00\xd1",                 "x??x"     },
    { "\xfd\x7b\x00\xa9",                 "xx?x"     },
};
static const CurlSig kUrlSetSigs[] = {
    { "\x3f\x23\x03\xd5\xff\x00\x00\xd1", "xxxxx??x" },
    { "\x5f\x24\x03\xd5\x3f\x23\x03\xd5", "xxxxxxxx" },
    { "\xff\x00\x00\xd1",                 "x??x"     },
};
#endif
#define kSetoptSigCount (sizeof(kSetoptSigs) / sizeof(kSetoptSigs[0]))
#define kUrlSetSigCount (sizeof(kUrlSetSigs) / sizeof(kUrlSetSigs[0]))

// Serialize resolve+dedup+install so concurrent dlopen interposers never
// double-hook a target. Recursive for the same reason hook.h's lock is.
static pthread_mutex_t gHookLock = PTHREAD_MUTEX_INITIALIZER;
static volatile int    gHookLockReady = 0;
static void HookLockInit(void) {
    static volatile int once = 0;
    int expected = 0;
    if (__atomic_compare_exchange_n(&once, &expected, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        pthread_mutexattr_t a;
        pthread_mutexattr_init(&a);
        pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&gHookLock, &a);
        pthread_mutexattr_destroy(&a);
        __atomic_store_n(&gHookLockReady, 1, __ATOMIC_RELEASE);
    }
}

// Install the inline hooks on already-resolved curl function addresses. setopt
// is required; urlSet is optional. The URL-API used to rewrite a CURLU is
// resolved in the same scope as setopt (RTLD_NEXT / dlsym on the owning lib).
static void HookCurlAt(void* setopt, void* urlSet, void* uget, void* uset, void* ufree, const char* how) {
    if (gHookLockReady) pthread_mutex_lock(&gHookLock);

    if (setopt && !FrIsHooked(setopt)) {
        CurlSetoptCtx* ctx = (CurlSetoptCtx*) FrHeapAlloc(sizeof(CurlSetoptCtx));
        if (ctx) {
            ctx->urlGet  = (CurlUrlGetFn) uget;
            ctx->urlSet  = (CurlUrlSetFn) uset;
            ctx->urlFree = (CurlFreeFn)   ufree;
            LogInfo("[hook] curl_easy_setopt via %s @ %p\n", how, setopt);
            void* stub = (void*) GenerateCaller(ctx, (void*) &CurlSetoptDetourWithInstance);
            if (!stub || !CreateAndEnableHook("curl_easy_setopt", setopt, stub, &ctx->original))
                FrHeapFree(ctx);
        }
    }
    if (urlSet && !FrIsHooked(urlSet)) {
        CurlUrlSetCtx* ctx = (CurlUrlSetCtx*) FrHeapAlloc(sizeof(CurlUrlSetCtx));
        if (ctx) {
            LogInfo("[hook] curl_url_set via %s @ %p\n", how, urlSet);
            void* stub = (void*) GenerateUrlSetCaller(ctx, (void*) &CurlUrlSetDetour);
            if (!stub || !CreateAndEnableHook("curl_url_set", urlSet, stub, &ctx->original))
                FrHeapFree(ctx);
        }
    }

    if (gHookLockReady) pthread_mutex_unlock(&gHookLock);
}

/* ---- resolving curl in the loaded modules ------------------------------ */
// Find curl's functions across the loaded objects by reading each object's
// on-disk symbol table -- .dynsym for a shared libcurl, .symtab for a
// statically-linked one -- with a prologue-signature scan as a stripped-binary
// fallback for setopt/url_set. Reading the symbol table is immune to symbol
// interposition, so it resolves the GENUINE libcurl whether Fragment was
// preloaded or injected (where a dlsym would resolve back to our own shadow).
typedef struct { void* setopt; void* urlSet; void* urlGet; void* urlFree; } CurlSyms;

// The object's path (for the main program, /proc/self/exe), or NULL to skip:
// only the main program and objects whose soname contains "curl" qualify.
static const char* CurlObjPath(struct dl_phdr_info* info, char* self, size_t cap) {
    if (!(info->dlpi_name && info->dlpi_name[0])) {        // main program
        ssize_t n = readlink("/proc/self/exe", self, cap - 1);
        if (n <= 0) return NULL;
        self[n] = 0;
        return self;
    }
    return strstr(info->dlpi_name, "curl") ? info->dlpi_name : NULL;
}

// Pass 1: exact symbol-table resolution (.dynsym of a shared libcurl, .symtab
// of a static one). Runs across EVERY object before any signature scan, so the
// genuine definition in libcurl.so is always preferred over a same-named string
// that merely appears (as a PLT import) in another module.
static int CurlSymCb(struct dl_phdr_info* info, size_t sz, void* data) {
    (void) sz;
    CurlSyms* s = (CurlSyms*) data;
    char self[4096];
    const char* path = CurlObjPath(info, self, sizeof(self));
    if (!path) return 0;
    uintptr_t bias = info->dlpi_addr;
    if (!s->setopt)  s->setopt  = ElfFindSym(path, bias, "curl_easy_setopt");
    if (!s->urlSet)  s->urlSet  = ElfFindSym(path, bias, "curl_url_set");
    if (!s->urlGet)  s->urlGet  = ElfFindSym(path, bias, "curl_url_get");
    if (!s->urlFree) s->urlFree = ElfFindSym(path, bias, "curl_free");
    return 0;
}

// Pass 2 (only when pass 1 found nothing): a best-effort prologue-signature scan
// over a curl-bearing object's executable segments, for a STRIPPED static curl.
// Gated on the symbol name appearing in loaded memory. (When the name lives only
// in a stripped symbol table it is absent from loaded memory, so this stays
// silent rather than guessing -- a documented residual gap. The two-pass split
// is what stops it from false-matching a dynamic host that merely imports curl.)
static int CurlSigCb(struct dl_phdr_info* info, size_t sz, void* data) {
    (void) sz;
    CurlSyms* s = (CurlSyms*) data;
    char self[4096];
    const char* path = CurlObjPath(info, self, sizeof(self));
    if (!path) return 0;
    uintptr_t bias = info->dlpi_addr;
    for (int i = 0; (!s->setopt || !s->urlSet) && i < info->dlpi_phnum; i++) {
        const ElfW(Phdr)* ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD || !(ph->p_flags & PF_X)) continue;
        const uint8_t* base = (const uint8_t*) (bias + ph->p_vaddr);
        size_t size = ph->p_memsz;
        if (!s->setopt && ModuleContainsAscii(base, size, "curl_easy_setopt"))
            for (size_t k = 0; k < kSetoptSigCount && !s->setopt; k++)
                s->setopt = FindPattern(base, size, kSetoptSigs[k].pattern, kSetoptSigs[k].mask);
        if (!s->urlSet && ModuleContainsAscii(base, size, "curl_url_set"))
            for (size_t k = 0; k < kUrlSetSigCount && !s->urlSet; k++)
                s->urlSet = FindPattern(base, size, kUrlSetSigs[k].pattern, kUrlSetSigs[k].mask);
    }
    return 0;
}

// Resolve and inline-hook the curl in this process (shared or static). Used by
// AUTO (to also cover an injected process, whose call sites were bound before
// we arrived) and HOOK (forced). `how` is a log label. Returns 1 if hooked.
static int HookLoadedCurl(const char* how) {
    CurlSyms s = {0};
    dl_iterate_phdr(CurlSymCb, &s);                 // exact symbols first, everywhere
    if (!s.setopt || !s.urlSet)
        dl_iterate_phdr(CurlSigCb, &s);             // signature fallback only if still missing
    if (!s.setopt && !s.urlSet) {
        LogInfo("[Fragment] no curl found to inline-hook\n");
        return 0;
    }
    HookCurlAt(s.setopt, s.urlSet, s.urlGet, s.urlSet, s.urlFree, how);
    if (s.setopt) gCurlHooked = 1;
    return 1;
}

/* ---- dlopen interposer (the LdrLoadDll chokepoint analog) -------------- */
// Catches a curl module brought in by a later dlopen so a statically-embedded
// curl in a runtime plugin is still swept, and a dynamic curl an app reaches
// only through dlsym pointers is inline-hooked at its real address.
typedef void* (*dlopen_fn)(const char*, int);

__attribute__((visibility("default")))
void* dlopen(const char* file, int mode) {
    static dlopen_fn real = NULL;
    if (!real) real = (dlopen_fn) RealSym("dlopen", (void*) &dlopen);
    void* h = real ? real(file, mode) : NULL;
    // A dlopen may have just brought curl into the process (a libcurl, or a
    // plugin that links or embeds it). If curl is not already hooked, resolve
    // and inline-hook it now from the loaded modules.
    if (h && gHookDlopen && !gCurlHooked) {
        LogDebug("[dlopen] %s loaded; checking for curl\n", file ? file : "(null)");
        HookLoadedCurl("dlopen");
    }
    return h;
}

/* ======================================================================== */
/* rtld-audit layer (AUDIT mode). When Fragment is loaded as an auditor
 * (LD_AUDIT), la_symbind64 sees every symbol binding in the program and can
 * redirect curl_easy_setopt / curl_url_set to our audit detours -- the
 * lowest-level interception, the Linux twin of the Windows loader-notification.
 * The auditor runs in its own link-map namespace and BEFORE ordinary
 * constructors, so it initialises config itself and never relies on the
 * preload copy's state. (The injector sets LD_AUDIT WITHOUT LD_PRELOAD for this
 * mode, so the binding la_symbind64 sees is the genuine libcurl, not a shadow.)
 */
static int          gAuditReady = 0;
// One real-pointer set per process: Fragment assumes a single libcurl image
// under audit (the common case). A second, independently-loaded libcurl would
// overwrite these -- a documented edge of audit mode; the inline-hook modes,
// which carry a per-hook context, do not share it.
static CurlSetoptFn gAuditRealSetopt = NULL;
static CurlUrlSetFn gAuditRealUrlSet = NULL;
static CurlUrlGetFn gAuditRealUrlGet = NULL;
static CurlFreeFn   gAuditRealFree   = NULL;

// Resolve the URL-API (for a CURLOPT_CURLU rewrite) from the SAME libcurl that
// owns the captured setopt, by reading that object's .dynsym from disk
// (dladdr -> path + base -> ElfFindSym). A plain dlsym is blind here: the
// auditor lives in its own link-map namespace and cannot see the target's
// libcurl through RTLD_NEXT/RTLD_DEFAULT.
static void AuditEnsureUrlApi(void) {
    if (gAuditRealUrlGet || !gAuditRealSetopt) return;
    Dl_info di;
    if (dladdr((void*) gAuditRealSetopt, &di) && di.dli_fname && di.dli_fbase) {
        uintptr_t bias = (uintptr_t) di.dli_fbase;
        gAuditRealUrlGet = (CurlUrlGetFn) ElfFindSym(di.dli_fname, bias, "curl_url_get");
        if (!gAuditRealUrlSet)
            gAuditRealUrlSet = (CurlUrlSetFn) ElfFindSym(di.dli_fname, bias, "curl_url_set");
        gAuditRealFree = (CurlFreeFn) ElfFindSym(di.dli_fname, bias, "curl_free");
    }
}

static CURLcode AuditSetopt(void* curl, CURLoption option, ...) {
    va_list ap; va_start(ap, option);
    void* arg = va_arg(ap, void*); va_end(ap);
    AuditEnsureUrlApi();
    char* toFree = NULL;
    void* fwd = FragmentSetoptValue(curl, option, arg, gAuditRealUrlGet, gAuditRealUrlSet, gAuditRealFree, &toFree);
    CURLcode rc = ((CURLcode(*)(void*, CURLoption, ...)) gAuditRealSetopt)(curl, option, fwd);
    if (toFree) free(toFree);
    return rc;
}
static CURLUcode AuditUrlSet(void* handle, CURLUPart what, const char* part, unsigned int flags) {
    char* proxied = NULL;
    if (what == CURLUPART_URL && part) { proxied = BuildProxiedUrl(part); if (proxied) part = proxied; }
    CURLUcode rc = gAuditRealUrlSet(handle, what, part, flags);
    if (proxied) free(proxied);
    return rc;
}

__attribute__((visibility("default")))
unsigned int la_version(unsigned int v) {
    if (!gAuditReady) {
        ConfigInit();
        // Scrub the proxy env here too (only when enabled): as an auditor we run
        // before the target's own constructors, so libcurl has not yet read
        // http_proxy. When disabled, leave the environment untouched.
        if (gCfg.enabled) {
            static const char* const vars[] = {
                "http_proxy","HTTP_PROXY","https_proxy","HTTPS_PROXY",
                "all_proxy","ALL_PROXY","ftp_proxy","FTP_PROXY","no_proxy","NO_PROXY",
            };
            for (size_t i = 0; i < sizeof(vars)/sizeof(vars[0]); i++) unsetenv(vars[i]);
        }
        gAuditReady = 1;
        LogInfo("[Fragment] rtld-audit active; enabled=%d proxy=%s\n", gCfg.enabled, gCfg.proxyPrefix);
    }
    return v ? v : LAV_CURRENT;
}

__attribute__((visibility("default")))
unsigned int la_objopen(struct link_map* map, Lmid_t lmid, uintptr_t* cookie) {
    (void) lmid; (void) cookie;
    LogDebug("[audit] la_objopen %s\n", map && map->l_name && map->l_name[0] ? map->l_name : "(exe)");
    return LA_FLG_BINDTO | LA_FLG_BINDFROM;   // see every bind to/from every object
}

__attribute__((visibility("default")))
uintptr_t la_symbind64(Elf64_Sym* sym, unsigned int ndx, uintptr_t* refcook,
                       uintptr_t* defcook, unsigned int* flags, const char* symname) {
    (void) ndx; (void) refcook; (void) defcook; (void) flags;
    if (symname && !strncmp(symname, "curl_", 5)) LogDebug("[audit] symbind %s\n", symname);
    if (gCfg.enabled && symname) {
        if (!strcmp(symname, "curl_easy_setopt")) {
            gAuditRealSetopt = (CurlSetoptFn) (uintptr_t) sym->st_value;
            LogInfo("[audit] rebinding curl_easy_setopt @ %p\n", (void*) (uintptr_t) sym->st_value);
            return (uintptr_t) &AuditSetopt;
        }
        if (!strcmp(symname, "curl_url_set")) {
            gAuditRealUrlSet = (CurlUrlSetFn) (uintptr_t) sym->st_value;
            LogInfo("[audit] rebinding curl_url_set @ %p\n", (void*) (uintptr_t) sym->st_value);
            return (uintptr_t) &AuditUrlSet;
        }
    }
    return sym->st_value;
}

/* ---- proxy-env scrub --------------------------------------------------- */
// The interposers only see proxies an app sets THROUGH the API; an app that
// never calls setopt(CURLOPT_PROXY) but inherits http_proxy/all_proxy from its
// environment would still route our rewritten request off-box. curl reads these
// at perform time, and we run before the target's first request, so clearing
// them here forces the direct path to 127.0.0.1:9020.
static void ScrubProxyEnv(void) {
    static const char* const vars[] = {
        "http_proxy",  "HTTP_PROXY",  "https_proxy", "HTTPS_PROXY",
        "all_proxy",   "ALL_PROXY",   "ftp_proxy",   "FTP_PROXY",
        "no_proxy",    "NO_PROXY",
    };
    for (size_t i = 0; i < sizeof(vars) / sizeof(vars[0]); ++i)
        unsetenv(vars[i]);
}

/* ---- module entry: the constructor (the DllMain analog) ---------------- */
// Runs when the preloaded .so is initialised, before the target's main(). For
// dynamic curl, interposition is already in force by the time we run (the
// loader bound the program's curl_* references to our exports at relocation
// time), so the constructor's remaining jobs are: read config, scrub the proxy
// env, and -- per the selected mode -- arrange the inline-hook layers.
__attribute__((constructor))
static void FragmentInit(void) {
    ConfigInit();
    LogInfo("[Fragment] %s attach pid=%d enabled=%d proxy=%s mode=%d\n",
            FRAGMENT_VERSION, (int) getpid(), gCfg.enabled, gCfg.proxyPrefix, gCfg.loaderMode);
    if (!gCfg.enabled) {
        LogInfo("[Fragment] disabled via environment; not rewriting\n");
        return;
    }

    ScrubProxyEnv();
    HookEngineInit();
    HookLockInit();

    switch (gCfg.loaderMode) {
        case FRAG_LOADER_INTERPOSE:
            gRewrite = 1; gHookDlopen = 0;
            LogInfo("[Fragment] approach: symbol interposition (dynamic / dlopen / transitive curl)\n");
            break;
        case FRAG_LOADER_HOOK:
            gRewrite = 0; gHookDlopen = 1;
            LogInfo("[Fragment] approach: forced inline byte-patch hooking\n");
            HookLoadedCurl("forced");
            break;
        case FRAG_LOADER_AUDIT:
            // If we somehow got here as a PRELOAD (not just an auditor), stay
            // inert so the auditor copy is the sole rewriter. The injector
            // normally sets LD_AUDIT alone for this mode.
            gRewrite = 0; gHookDlopen = 0;
            LogInfo("[Fragment] approach: rtld-audit (rewriting handled by the auditor copy)\n");
            break;
        case FRAG_LOADER_AUTO:
        default: {
            // Interposition covers the PRELOADed case (we shadow libcurl ahead
            // in the global scope). To ALSO cover an INJECTED process -- whose
            // curl call sites were bound before we arrived, bypassing
            // interposition -- inline-hook the EXACT real dynamic curl too,
            // resolved by symbol (never a fuzzy signature, so we cannot
            // mis-hook). When preloaded that hook is dormant: the interposer
            // forwards through the trampoline, not the patched entry. A purely
            // static curl has no dynamic symbol, so it falls to the
            // .symtab/signature sweep instead.
            gRewrite = 1;
            gHookDlopen = 1;
            LogInfo("[Fragment] approach: interposition + inline hook of the loaded curl\n");
            HookLoadedCurl("real");
            break;
        }
    }
}
