#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <psapi.h>
#include "log.h"
#include "config.h"
#include "curl.h"
#include "util.h"
#include "../common/version.h"

// Build "<proxyPrefix><orig>" (default http://127.0.0.1:9020/<orig>, but the
// prefix is runtime-configurable). Returns NULL when no rewrite is needed
// (orig NULL/empty, or ALREADY carrying the configured prefix) or on OOM.
// Idempotent, so re-set URLs and the setopt<->url_set hook interplay never
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

#include "../common/url_rewrite.h"

// Per-hook context. `original` MUST be first: InstallHook writes the
// trampoline into *ppOriginal (== &ctx->original) and GenerateCaller injects
// &ctx as the detour's first argument, so &ctx->original == (void**)ctx. The
// url* members are the SAME libcurl module's URL-API, used to rewrite a CURLU.
typedef struct {
    LPVOID       original;
    CurlUrlGetFn urlGet;
    CurlUrlSetFn urlSet;
    CurlFreeFn   urlFree;
} CurlSetoptCtx;

typedef struct { LPVOID original; CurlUrlGetFn urlGet; CurlFreeFn urlFree; } CurlUrlSetCtx;

// curl_easy_setopt detour. Covers every way a program sets the
// destination through the easy interface:
//   CURLOPT_URL        - rewrite the string URL
//   CURLOPT_CURLU      - rewrite the parsed URL handle in place
//   CURLOPT_RESOLVE    - drop (a DNS pin would divert off our proxy)
//   CURLOPT_CONNECT_TO - drop (connect-to would divert off our proxy)
//   CURLOPT_UNIX_SOCKET_PATH / CURLOPT_ABSTRACT_UNIX_SOCKET
//                      - drop (a Unix socket would replace the TCP path to :9020)
//   CURLOPT_PROXY      - force "" = direct (an upstream proxy would carry our
//   CURLOPT_PRE_PROXY    rewritten request off-box; "" also beats the env proxy)
//   CURLOPT_PORT       - drop (a port override would change our :9020)
CURLcode CurlSetoptDetourWithInstance(CurlSetoptCtx* ctx, LPVOID curl, CURLoption option, va_list param) {
#if defined(_M_IX86) || defined(__i386__)
    // The i386 stub supplies the original vararg address, not just its low word.
    if (option >= 30000 && option < 40000) {
        int64_t value;
        memcpy(&value, param, sizeof(value));
        return ((CurlSetoptFn)ctx->original)(curl, option, value);
    }
    memcpy(&param, param, sizeof(param));
#endif
    char* newUrl = NULL;

    if (option == CURLOPT_URL) {
        // GenerateCaller forwards the first vararg by value, so for
        // CURLOPT_URL `param` *is* the original URL pointer.
        // curl_easy_setopt(h, CURLOPT_URL, NULL) is valid (resets it).
        char* origUrl = (char*) param;
        LogDebug("[setopt] CURLOPT_URL handle=0x%p url=%s\n", curl, origUrl ? origUrl : "(null)");
        newUrl = BuildProxiedUrl(origUrl);
        if (newUrl) param = (va_list) newUrl;
    } else if (option == CURLOPT_CURLU) {
        // A parsed URL handle. Read the assembled URL, rewrite it, and
        // write it back into the same handle (the app keeps using it).
        void* uh = (void*) param;
        if (uh && ctx->urlGet && ctx->urlSet && ctx->urlFree) {
            char* cur = NULL;
            if (ctx->urlGet(uh, CURLUPART_URL, &cur, 0) == 0 && cur) {
                char* proxied = BuildProxiedUrl(cur);
                if (proxied) {
                    LogDebug("[setopt] CURLOPT_CURLU rewrite: %s\n", cur);
                    if (ctx->urlSet(uh, CURLUPART_URL, proxied, 0) != 0)
                        LogWarn("[setopt] curl_url_set rewrite failed; request may bypass the proxy\n");
                    free(proxied);
                }
                ctx->urlFree(cur);
            }
        } else if (uh) {
            LogWarn("[setopt] CURLOPT_CURLU cannot be rewritten: URL API exports unavailable\n");
        }
    } else if (option == CURLOPT_RESOLVE || option == CURLOPT_CONNECT_TO ||
               option == CURLOPT_UNIX_SOCKET_PATH ||
               option == CURLOPT_ABSTRACT_UNIX_SOCKET) {
        // Forwarding NULL clears a RESOLVE/CONNECT_TO list, and for the Unix-
        // socket options NULL disables them -> curl uses normal TCP to our
        // 127.0.0.1:9020 instead of a local socket that would divert off-proxy.
        LogDebug("[setopt] dropping option %d (would divert traffic off-proxy)\n", option);
        param = (va_list) NULL;
    } else if (option == CURLOPT_PROXY || option == CURLOPT_PRE_PROXY) {
        // String options: forward "" (NOT NULL). Per libcurl, an empty proxy
        // string forces a DIRECT connection AND suppresses the http_proxy/
        // all_proxy environment variables -- whereas NULL is curl's default that
        // FALLS BACK to those env vars, which would re-enable the off-proxy
        // divert. The "" literal has static storage, so forwarding it is safe.
        LogDebug("[setopt] forcing direct for proxy option %d (was off-proxy)\n", option);
        param = (va_list) "";
    } else if (option == CURLOPT_PORT) {
        LogDebug("[setopt] dropping CURLOPT_PORT (would override the proxy port)\n");
        param = (va_list) 0;
    }

    CURLcode result = ((CurlSetoptFn) ctx->original)(curl, option, param);

    if (newUrl) {
        free(newUrl);
    }

    return result;
}

// Apply full URLs, relative references, and component mutations to the origin
// representation, then rebuild the proxy URL. No address-keyed CURLU cache.
CURLUcode CurlUrlSetDetour(CurlUrlSetCtx* ctx, void* handle, CURLUPart what, const char* part, unsigned int flags) {
    return FragmentUrlSet(handle, what, part, flags, (CurlUrlSetFn)ctx->original,
                          ctx->urlGet, ctx->urlFree);
}

// Prologue signatures, one per compiler family, derived from real
// libcurl binaries. Only used for STATICALLY-linked curl, where there is
// no export table to resolve. Shared-library libcurl never needs these.
typedef struct { const char* pattern; const char* mask; } CurlSig;

#if defined(_M_X64) || defined(__x86_64__)
static const CurlSig kSetoptSigs[] = {
    // Newer MSVC (the project's original signature).
    { "\x48\x89\x00\x00\x00\x48\x89\x00\x00\x00\x48\x89\x00\x00\x00\x57\x48\x83\xEC\x00\x33\xED\x49\x8B\x00\x48\x8B\x00\x81\xFA",
      "xx???xx???xx???xxxx?xxxx?xx?xx" },
    // Old MSVC (VS2010/VS2012, libcurl 7.30-era): spill edx/r8/r9, sub rsp,
    // test rcx,rcx / jne / lea eax,[rcx+0x2b] NULL-handle guard.
    { "\x89\x54\x24\x10\x4C\x89\x44\x24\x18\x4C\x89\x4C\x24\x20\x48\x83\xEC\x00\x48\x85\xC9\x75\x08\x8D\x41\x2B\x48\x83\xC4\x00\xC3",
      "xxxxxxxxxxxxxxxxx?xxxxxxxxxxx?x" },
    // MinGW-GCC: push rbx; sub rsp; mov rbx,[rip+x] (stack canary);
    // spill r8/r9; mov rax,[rbx]; xor eax,eax; test rcx,rcx.
    { "\x53\x48\x83\xEC\x00\x48\x8B\x1D\x00\x00\x00\x00\x4C\x89\x44\x24\x00\x4C\x89\x4C\x24\x00\x48\x8B\x03\x48\x89\x44\x24\x00\x31\xC0\x48\x85\xC9",
      "xxxx?xxx????xxxx?xxxx?xxxxxxx?xxxxx" },
    // curl-for-win 8.20.0_1. The old short clang prefix also matched
    // curl_share_setopt in 8.22; retain the observed argument setup here.
    { "\xF3\x0F\x1E\xFA\x55\x56\x57\x48\x83\xEC\x30\x48\x8D\x6C\x24\x30\x4C\x89\x45\x30\x4C\x89\x4D\x38\xB8\x2B\x00\x00\x00\x48\x85\xC9\x74\x2E\x89\xD6\x4C\x8D\x45\x30\x4C\x89\x45\xF8\x48\x89\xCF",
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
    // curl-for-win 8.22.0_1, clang 23: exact exported body also occurs once
    // in the matching static curl.exe. Keep the symbol-name gate unchanged.
    { "\xF3\x0F\x1E\xFA\x55\x56\x57\x53\x48\x83\xEC\x28\x48\x8D\x6C\x24\x20\x4C\x89\x45\x40\x4C\x89\x4D\x48\xB8\x2B\x00\x00\x00\x48\x85\xC9\x0F\x84\xA1\x00\x00\x00\x81\x39\xAD\xDB\xDE\xC0\x0F\x85\x95",
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
};
#elif defined(_M_IX86) || defined(__i386__)
// Best-effort 32-bit __cdecl frame prologues (MSVC hotpatch `mov edi,edi` + the
// plain frame-pointer entry, MinGW's `89 E5` form, and the CET endbr32 variant),
// to be evidence-refined against a stripped x86 libcurl. A shared-library build
// resolves by export, so these matter only for a statically-linked x86 program.
static const CurlSig kSetoptSigs[] = {
    { "\x8B\xFF\x55\x8B\xEC",         "xxxxx"   },   // mov edi,edi; push ebp; mov ebp,esp
    { "\x55\x8B\xEC",                 "xxx"     },   // push ebp; mov ebp,esp  (MSVC)
    { "\x55\x89\xE5",                 "xxx"     },   // push ebp; mov ebp,esp  (MinGW)
    { "\xF3\x0F\x1E\xFB\x55\x8B\xEC", "xxxxxxx" },   // endbr32; push ebp; mov ebp,esp
};
#elif defined(_M_ARM64) || defined(__aarch64__)
// Best-effort AArch64 frame-setup prologues (the PAC and non-PAC
// `stp x29,x30,[sp,#-N]!` forms and a `sub sp` + stp form), to be evidence-
// refined against a stripped ARM64 libcurl. The immediate fields are masked. A
// shared-library build resolves by export, so these matter only for a
// statically-linked ARM64 program.
static const CurlSig kSetoptSigs[] = {
    { "\x7F\x23\x03\xD5\xFD\x7B\x00\xA9", "xxxxxx?x" },   // pacibsp; stp x29,x30,[sp,#-N]!
    { "\xFD\x7B\x00\xA9\xFD\x03\x00\x91", "xx?xxxxx" },   // stp x29,x30,[sp,#-N]!; mov x29,sp
    { "\xFF\x00\x00\xD1\xFD\x7B\x00\xA9", "x??xxx?x" },   // sub sp,sp,#N; stp x29,x30,[sp,#M]
};
#endif
#define kSetoptSigCount (sizeof(kSetoptSigs) / sizeof(kSetoptSigs[0]))

// curl_url_set prologues (statically-linked URL-API fallback). DLL
// builds resolve it by export, so these only matter for the rare
// statically-linked program that builds URLs via the curl_url API.
#if defined(_M_X64) || defined(__x86_64__)
static const CurlSig kUrlSetSigs[] = {
    // MinGW-GCC: push r15..r12/rbp/rdi/rsi/rbx; sub rsp,imm32;
    // mov rbx,rcx; mov rcx,[rip+canary]; mov esi,edx; mov rbp,r8.
    { "\x41\x57\x41\x56\x41\x55\x41\x54\x55\x57\x56\x53\x48\x81\xEC\x00\x00\x00\x00\x48\x89\xCB\x48\x8B\x0D\x00\x00\x00\x00\x89\xD6\x4C\x89\xC5\x44\x89\xCF",
      "xxxxxxxxxxxxxxx????xxxxxx????xxxxxxxx" },
    // Clang/LLVM with CET endbr64; push rbp/r15..r12/rsi/rdi/rbx;
    // sub rsp,imm32; lea rbp,[rsp+disp32]; test rcx,rcx; je.
    { "\xF3\x0F\x1E\xFA\x55\x41\x57\x41\x56\x41\x55\x41\x54\x56\x57\x53\x48\x81\xEC\x00\x00\x00\x00\x48\x8D\xAC\x24\x00\x00\x00\x00\x48\x85\xC9\x74\x00\x4D\x89\xC6\x89\xD3\x48\x89\xCE\x4D\x85\xC0",
      "xxxxxxxxxxxxxxxxxxx????xxxx????xxxx?xxxxxxxxxxx" },
    // curl-for-win 8.22.0_1, clang 23, smaller stack frame.
    { "\xF3\x0F\x1E\xFA\x55\x41\x57\x41\x56\x41\x55\x41\x54\x56\x57\x53\x48\x83\xEC\x78\x48\x8D\x6C\x24\x70\x48\x85\xC9\x74\x75\x4D\x89\xC4\x41\x89\xD5\x48\x89\xCE\x4D\x85\xC0\x74\x71\x45\x89\xCF\x4C",
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
};
#elif defined(_M_IX86) || defined(__i386__)
// curl_url_set frame prologues for a statically-linked x86 program (best-effort;
// DLL builds resolve it by export).
static const CurlSig kUrlSetSigs[] = {
    { "\x8B\xFF\x55\x8B\xEC",         "xxxxx"   },   // mov edi,edi; push ebp; mov ebp,esp
    { "\x55\x8B\xEC",                 "xxx"     },   // push ebp; mov ebp,esp  (MSVC)
    { "\x55\x89\xE5",                 "xxx"     },   // push ebp; mov ebp,esp  (MinGW)
    { "\xF3\x0F\x1E\xFB\x55\x8B\xEC", "xxxxxxx" },   // endbr32; push ebp; mov ebp,esp
};
#elif defined(_M_ARM64) || defined(__aarch64__)
// curl_url_set frame prologues for a statically-linked ARM64 program (best-
// effort, same frame-setup forms as above; DLL builds resolve it by export).
static const CurlSig kUrlSetSigs[] = {
    { "\x7F\x23\x03\xD5\xFD\x7B\x00\xA9", "xxxxxx?x" },   // pacibsp; stp x29,x30,[sp,#-N]!
    { "\xFD\x7B\x00\xA9\xFD\x03\x00\x91", "xx?xxxxx" },   // stp x29,x30,[sp,#-N]!; mov x29,sp
    { "\xFF\x00\x00\xD1\xFD\x7B\x00\xA9", "x??xxx?x" },   // sub sp,sp,#N; stp x29,x30,[sp,#M]
};
#endif
#define kUrlSetSigCount (sizeof(kUrlSetSigs) / sizeof(kUrlSetSigs[0]))

// Follow incremental-link / IAT jump thunks (E9/EB/FF25) to the real
// function body, so we hook the actual prologue rather than a 5-byte
// stub. MSVC debug/incremental builds export such thunks.
static LPVOID FollowThunks(LPVOID p) {
    for (int i = 0; i < 16 && p; ++i) {
        PBYTE b = (PBYTE) p;
        if (b[0] == 0xE9) { p = b + 5 + *(int*)(b + 1); continue; }
        if (b[0] == 0xEB) { p = b + 2 + *(signed char*)(b + 1); continue; }
        if (b[0] == 0xFF && b[1] == 0x25) {
            void** slot = (void**)(b + 6 + *(int*)(b + 2));
            if (!slot || !*slot) break;
            p = *slot; continue;
        }
        break;
    }
    return p;
}

// Resolve a libcurl function: export table first (works for EVERY
// shared-library version/compiler/bitness, no signatures), then a
// best-effort prologue scan for statically-linked curl, gated on the
// module actually containing the symbol name so we never false-match.
static LPVOID ResolveCurlFn(HMODULE module, PBYTE base, SIZE_T size, const char* name,
                            const CurlSig* sigs, size_t nsigs,
                            const char** how) {
    LPVOID target = (LPVOID) GetProcAddress(module, name);
    *how = "export";
    // Embedded curl can live in any module, regardless of its filename.
    // Require the function-name marker before trying the signature fallback.
    if (!target && ModuleContainsAscii(base, size, name)) {
        for (size_t i = 0; i < nsigs; ++i) {
            LPVOID candidate = FindPattern(base, size, sigs[i].pattern, sigs[i].mask);
            if (candidate && target && candidate != target) {
                LogWarn("[hook] ambiguous signatures for %s; leaving unhooked\n", name);
                return NULL;
            }
            if (candidate) target = candidate;
        }
        *how = "signature";
    }
    return target ? FollowThunks(target) : NULL;
}

// Serializes the resolve+dedup+install sequence so concurrent load
// notifications (or fallback LoadLibrary detours) never double-hook a target.
// MUST remain a CRITICAL_SECTION (recursive): the LdrLoadDll detour can re-enter
// HookCurl on the SAME thread under the loader lock (e.g. a hooked module's
// DllMain triggers another LoadLibrary), and recursive acquisition is what keeps
// that safe. A non-recursive lock (SRWLOCK) here would self-deadlock.
static CRITICAL_SECTION gHookLock;
static volatile LONG    gHookLockReady = 0;
// First call is single-threaded (DllMain). Publish ready AFTER the section is
// constructed so a later concurrent HookCurl never enters an uninitialized CS.
static void HookLockInit(void) {
    static volatile LONG once = 0;
    if (InterlockedCompareExchange(&once, 1, 0) == 0) {
        InitializeCriticalSection(&gHookLock);
        InterlockedExchange(&gHookLockReady, 1);
    }
}

// The WinHTTP backend reuses gHookLock / gHookLockReady (defined just above) to
// serialize its resolve+dedup+install against the curl backend's shared hook
// registry, so it is included here rather than at the top of the file.
#include "winhttp.h"
#include "capture.h"
#include "schannel.h"
#include "openssl_capture.h"
#include "network.h"

void HookCurl(HMODULE module) {
    if (!module) return;

    // Everything below is callable from a loader-notification callback (under
    // the loader lock), so we avoid psapi entirely: image size comes from the
    // PE headers and the name from kernel32's GetModuleFileNameA.
    PBYTE  base = (PBYTE) module;
    SIZE_T size = ModuleImageSize(module);
    if (!size) return;                       // not a valid mapped PE image

    char path[MAX_PATH] = {0};
    GetModuleFileNameA(module, path, MAX_PATH);
    const char* moduleName = path;
    for (const char* p = path; *p; ++p)
        if (*p == '\\' || *p == '/') moduleName = p + 1;

    const char* how;

    if (gHookLockReady) EnterCriticalSection(&gHookLock);

    // --- curl_easy_setopt: rewrites CURLOPT_URL/CURLU; neutralizes the divert
    //     options (RESOLVE/CONNECT_TO/UNIX_SOCKET/PROXY/PRE_PROXY/PORT)
    LPVOID setopt = ResolveCurlFn(module, base, size, "curl_easy_setopt",
                                  kSetoptSigs, kSetoptSigCount, &how);
    if (setopt && !FrIsHooked(setopt)) {
        CurlSetoptCtx* ctx = (CurlSetoptCtx*) FrHeapAlloc(sizeof(CurlSetoptCtx));
        if (ctx) {
            // The URL-API lives in the SAME libcurl module; needed to
            // rewrite a CURLU object passed via CURLOPT_CURLU.
            ctx->urlGet  = (CurlUrlGetFn) (void*) GetProcAddress(module, "curl_url_get");
            ctx->urlSet  = (CurlUrlSetFn) (void*) GetProcAddress(module, "curl_url_set");
            ctx->urlFree = (CurlFreeFn)   (void*) GetProcAddress(module, "curl_free");
            LogInfo("[hook] curl_easy_setopt via %s in %s @ 0x%p\n", how, moduleName, setopt);
            LPVOID stub = GenerateCaller(ctx, &CurlSetoptDetourWithInstance);
            // On success InstallHook records the hook in the teardown registry,
            // which is also the dedup source (FrIsHooked) -- nothing more to track.
            if (!stub || !CreateAndEnableHook(moduleName, setopt, stub, &ctx->original)) {
                if (stub) VirtualFree(stub, 0, MEM_RELEASE);
                FrHeapFree(ctx);
            }
        }
    }

    // --- curl_url_set: covers URLs built/mutated via the curl_url API
    LPVOID urlset = ResolveCurlFn(module, base, size, "curl_url_set",
                                  kUrlSetSigs, kUrlSetSigCount, &how);
    if (urlset && !FrIsHooked(urlset)) {
        CurlUrlSetCtx* ctx = (CurlUrlSetCtx*) FrHeapAlloc(sizeof(CurlUrlSetCtx));
        if (ctx) {
            ctx->urlGet = (CurlUrlGetFn)(void*)GetProcAddress(module, "curl_url_get");
            ctx->urlFree = (CurlFreeFn)(void*)GetProcAddress(module, "curl_free");
            LogInfo("[hook] curl_url_set via %s in %s @ 0x%p\n", how, moduleName, urlset);
            LPVOID stub = GenerateUrlSetCaller(ctx, &CurlUrlSetDetour);
            if (!stub || !CreateAndEnableHook(moduleName, urlset, stub, &ctx->original)) {
                if (stub) VirtualFree(stub, 0, MEM_RELEASE);
                FrHeapFree(ctx);
            }
        }
    }

    if (gHookLockReady) LeaveCriticalSection(&gHookLock);
}

// Run every per-module backend over a freshly observed module. New backends
// (HTTP redirection or optional TLS/socket observation) use this fan-out,
// which every module-load path below and the already-mapped sweep invoke.
static void HookModule(HMODULE module) {
    if (gCfg.observe) {
        HookSchannel(module);
        HookOpenSsl(module);
        HookNetwork(module);
    } else {
        HookCurl(module);
        HookWinHttp(module);
    }
}

typedef HMODULE(*LoadLibraryAFn)(LPCSTR lpLibFileName);
LoadLibraryAFn LoadLibraryAOriginal = 0;

HMODULE LoadLibraryADetour(LPCSTR lpLibFileName) {
    HMODULE result = LoadLibraryAOriginal(lpLibFileName);

    if (gLogLevel >= FRAG_LOG_DEBUG && result) {
        char nm[MAX_PATH] = {0};
        GetModuleBaseNameA(GetCurrentProcess(), result, nm, MAX_PATH);
        LogDebug("[LoadLibraryA] loaded %s\n", nm);
    }

    HookModule(result);

    return result;
}

typedef HMODULE(*LoadLibraryWFn)(LPCWSTR lpLibFileName);
LoadLibraryWFn LoadLibraryWOriginal = 0;

HMODULE LoadLibraryWDetour(LPCWSTR lpLibFileName) {
    HMODULE result = LoadLibraryWOriginal(lpLibFileName);

    if (gLogLevel >= FRAG_LOG_DEBUG && result) {
        char nm[MAX_PATH] = {0};
        GetModuleBaseNameA(GetCurrentProcess(), result, nm, MAX_PATH);
        LogDebug("[LoadLibraryW] loaded %s\n", nm);
    }

    HookModule(result);

    return result;
}

// --- Loader notification: the single chokepoint that catches EVERY module
// load path -- LoadLibrary, LoadLibraryEx, LoadPackagedLibrary, delay-load,
// and transitive dependency loads -- because they all funnel through ntdll's
// loader, which fires this callback for each mapped image. Hooking
// LoadLibraryA/W only ever saw those two entry points. Available since Vista;
// we fall back to the LoadLibrary detours only if it is unavailable.
typedef struct { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } FR_USTR;
typedef struct {
    ULONG    Flags;
    const FR_USTR* FullDllName;
    const FR_USTR* BaseDllName;
    PVOID    DllBase;
    ULONG    SizeOfImage;
} FR_LDR_NOTIFICATION_DATA;          // LOADED and UNLOADED arms share this layout
typedef VOID (CALLBACK *FR_LDR_NOTIFY_FN)(ULONG, const FR_LDR_NOTIFICATION_DATA*, PVOID);
typedef LONG (NTAPI *FR_LdrRegisterFn)(ULONG, FR_LDR_NOTIFY_FN, PVOID, PVOID*);

#define FR_LDR_DLL_NOTIFICATION_REASON_LOADED 1
#define FR_LDR_DLL_NOTIFICATION_REASON_UNLOADED 2

static PVOID gLdrCookie = NULL;

static VOID CALLBACK DllLoadNotification(ULONG reason,
                                         const FR_LDR_NOTIFICATION_DATA* data,
                                         PVOID context) {
    (void) context;
    if (!data || !data->DllBase) return;
    if (reason == FR_LDR_DLL_NOTIFICATION_REASON_UNLOADED) {
        EnterCriticalSection(&gHookLock);
        FrForgetModule(data->DllBase, data->SizeOfImage);
        WhModuleUnloaded((HMODULE)data->DllBase);
        SchannelModuleUnloaded((HMODULE)data->DllBase);
        OpenSslModuleUnloaded((HMODULE)data->DllBase);
        NetworkModuleUnloaded((HMODULE)data->DllBase);
        LeaveCriticalSection(&gHookLock);
    } else if (reason == FR_LDR_DLL_NOTIFICATION_REASON_LOADED &&
               (gCfg.loaderMode == FRAG_LOADER_AUTO || gCfg.loaderMode == FRAG_LOADER_NOTIFY))
        HookModule((HMODULE) data->DllBase);
}

static BOOL RegisterLoaderNotification(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return FALSE;
    FR_LdrRegisterFn reg =
        (FR_LdrRegisterFn) (void*) GetProcAddress(ntdll, "LdrRegisterDllNotification");
    if (!reg) return FALSE;
    return reg(0, &DllLoadNotification, NULL, &gLdrCookie) == 0; // 0 == STATUS_SUCCESS
}

// --- Second interception approach: hook ntdll!LdrLoadDll, the single internal
// chokepoint that LoadLibraryA/W, LoadLibraryEx*, LoadPackagedLibrary and the
// delay-load helper ALL funnel through. One hook here therefore catches every
// dynamic load -- including LoadLibraryEx, which the legacy LoadLibraryA/W
// detours miss. (It does not see modules the loader maps as static imports
// during process init, but those predate our injection; the already-mapped
// sweep in DllMain covers a curl that is already present.) Used when the
// loader notification is unavailable, or forced via FRAGMENT_LOADER=ldrloaddll.
//
// Like the notification callback, the detour runs under the loader lock, so it
// only uses loader-lock-safe primitives (HookCurl is built to that contract:
// private-heap allocation, no LoadLibrary, no psapi).
//   NTSTATUS NTAPI LdrLoadDll(PWSTR Path, PULONG Flags, PUNICODE_STRING Name, PVOID* Handle)
typedef LONG (NTAPI *FR_LdrLoadDllFn)(PWSTR, PULONG, PVOID, PVOID*);
static FR_LdrLoadDllFn LdrLoadDllOriginal = 0;

static LONG NTAPI LdrLoadDllDetour(PWSTR path, PULONG flags, PVOID name, PVOID* handle) {
    LONG status = LdrLoadDllOriginal(path, flags, name, handle);
    // NTSTATUS >= 0 is success/informational; *handle is the loaded module.
    if (status >= 0 && handle && *handle)
        HookModule((HMODULE) *handle);
    return status;
}

// MUST be called from DllMain (i.e. while the loader lock is held), and only
// there. LdrLoadDll's prologue is long enough to take the engine's byte-wise
// (non-atomic) patch path, so a thread executing its first bytes during the
// patch could read a torn instruction. The loader lock closes that window:
// every other entry into LdrLoadDll must first acquire the same lock we hold,
// so none can be mid-prologue while we patch. Installing this hook off the
// DllMain thread would reopen the race -- don't.
static BOOL HookLdrLoadDll(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return FALSE;
    LPVOID target = (LPVOID) GetProcAddress(ntdll, "LdrLoadDll");
    if (!target) return FALSE;
    return CreateAndEnableHook("LdrLoadDll", target, &LdrLoadDllDetour,
                               (LPVOID*) &LdrLoadDllOriginal);
}

// Clear the proxy environment variables libcurl honors by default. The
// curl_easy_setopt hook only sees proxies an app sets THROUGH the API; an app
// that never calls setopt(CURLOPT_PROXY) but inherits http_proxy/all_proxy from
// its environment would still route our rewritten request off-box. curl reads
// these at perform time, and we run before the target's first request, so
// clearing them here forces the direct path to 127.0.0.1:9020. Both cases are
// cleared since curl checks several (and, for some, upper- and lower-case).
static void ScrubProxyEnv(void) {
    static const char* const vars[] = {
        "http_proxy",  "HTTP_PROXY",  "https_proxy", "HTTPS_PROXY",
        "all_proxy",   "ALL_PROXY",   "ftp_proxy",   "FTP_PROXY",
        "no_proxy",    "NO_PROXY",
    };
    for (size_t i = 0; i < sizeof(vars) / sizeof(vars[0]); ++i)
        SetEnvironmentVariableA(vars[i], NULL);
}

BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD reason, LPVOID lpvReserved) {
    if (reason != DLL_PROCESS_ATTACH) return TRUE;

    DisableThreadLibraryCalls(hinstDLL);
    ConfigInit();
    LogInfo("[Fragment] %s attach pid=%lu enabled=%d mode=%s\n",
            FRAGMENT_VERSION, GetCurrentProcessId(), (int)gCfg.enabled,
            gCfg.observe ? "observe" : "redirect");
    if (!gCfg.observe) LogInfo("[Fragment] proxy=%s\n", gCfg.proxyPrefix);
    if (!gCfg.enabled) {
        LogInfo("[Fragment] disabled via environment; not hooking\n");
        return TRUE;
    }
    if (!gCfg.valid) return FALSE;
    if (gCfg.observe && !CaptureInit(gCfg.captureFileW)) return FALSE;

    // Neutralize env-var proxies up front (the setopt hook can't see them).
    if (!gCfg.observe) ScrubProxyEnv();

    HookEngineInit();
    HookLockInit();
    if (gCfg.observe) SchannelInit();
    if (gCfg.observe) OpenSslInit();
    if (gCfg.observe) NetworkInit();

    // Pin ourselves so a stray FreeLibrary cannot unmap the DLL while our
    // loader-notification callback is still registered (a dangling callback
    // pointer would crash the next load).
    {
        HMODULE self = NULL;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                           (LPCWSTR) &DllLoadNotification, &self);
    }

    // --- Install future-load interception, layering independent approaches so
    // no single mechanism being unavailable can blind us. The whole of DllMain
    // runs under the loader lock, so no concurrent load can COMPLETE while we
    // set up; any overlap between approaches is collapsed by the dedup
    // (FrIsHooked). FRAGMENT_LOADER forces a specific approach; the default
    // (auto) tries them top-down in order of coverage and uses what installs.
    int  mode    = gCfg.loaderMode;
    BOOL notify  = FALSE;   // 1) LdrRegisterDllNotification: all load paths
    BOOL ldrHook = FALSE;   // 2) LdrLoadDll chokepoint: LoadLibrary A/W/Ex+delay
    BOOL llHook  = FALSE;   // 3) LoadLibraryA/W detours: legacy last resort

    // Even forced loader modes need unload bookkeeping. Loaded-image discovery
    // remains gated in the callback so those modes retain their coverage.
    BOOL lifecycleNotify = RegisterLoaderNotification();
    if (mode == FRAG_LOADER_AUTO || mode == FRAG_LOADER_NOTIFY) {
        notify = lifecycleNotify;
        if (notify) LogInfo("[Fragment] approach: loader notification (covers all load paths)\n");
        else        LogWarn("[Fragment] LdrRegisterDllNotification unavailable\n");
    }

    if (mode == FRAG_LOADER_LDRLOADDLL || (mode == FRAG_LOADER_AUTO && !notify)) {
        ldrHook = HookLdrLoadDll();
        if (ldrHook) LogInfo("[Fragment] approach: LdrLoadDll chokepoint (LoadLibrary A/W/Ex + delay-load)\n");
        else         LogWarn("[Fragment] LdrLoadDll hook unavailable\n");
    }

    if (mode == FRAG_LOADER_LOADLIBRARY || (mode == FRAG_LOADER_AUTO && !notify && !ldrHook)) {
        BOOL a = CreateAndEnableHook("LoadLibraryA", &LoadLibraryA, &LoadLibraryADetour, (LPVOID *) &LoadLibraryAOriginal);
        BOOL w = CreateAndEnableHook("LoadLibraryW", &LoadLibraryW, &LoadLibraryWDetour, (LPVOID *) &LoadLibraryWOriginal);
        if (!a) LogError("[Fragment] LoadLibraryA hook failed\n");
        if (!w) LogError("[Fragment] LoadLibraryW hook failed\n");
        llHook = a || w;
        if (llHook) LogInfo("[Fragment] approach: LoadLibraryA/W detours (legacy; misses LoadLibraryEx)\n");
    }

    if (!notify && !ldrHook && !llHook)
        LogError("[Fragment] no dynamic-load interception engaged; only already-mapped modules will be inspected\n");

    // THEN sweep already-mapped modules (covers a curl loaded before us), with a
    // dynamically sized buffer so a large host's module list is never truncated.
    // Interception is in place first, and the loader lock is held throughout, so
    // a module loading concurrently with this sweep cannot slip through the gap.
    HANDLE hProcess = GetCurrentProcess();
    DWORD cbNeeded = 0;
    EnumProcessModules(hProcess, NULL, 0, &cbNeeded);
    if (cbNeeded) {
        HMODULE* mods = (HMODULE*) FrHeapAlloc(cbNeeded);
        if (mods && EnumProcessModules(hProcess, mods, cbNeeded, &cbNeeded)) {
            DWORD count = cbNeeded / sizeof(HMODULE);
            for (DWORD i = 0; i < count; i++) {
                if (mods[i] == hinstDLL) continue;   // skip ourselves
                HookModule(mods[i]);
            }
        }
        FrHeapFree(mods);
    }

    return TRUE;
}
