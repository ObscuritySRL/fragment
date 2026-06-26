/*
 * Fragment loader -- injects the libcurl-rewriting DLL into a target process,
 * either by launching a new program or by attaching to a running PID, and
 * passes configuration through to the target via the environment.
 *
 *   fragment [options] -- <program> [args...]   launch the program & inject
 *   fragment [options] --pid <pid>              inject into a running process
 *
 * The loader is x64. It injects Fragment.dll into native x64 targets and the
 * 32-bit Fragment32.dll into 32-bit (WOW64) targets, picking the right module
 * by the target's bitness. Build: part of the CMake project (fragment.exe).
 */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../common/version.h"
#include "../wow64.h"

static void usage(void) {
    fprintf(stderr,
        "Fragment loader -- redirect a program's libcurl traffic through a proxy.\n\n"
        "Usage:\n"
        "  fragment [options] -- <program> [args...]   launch & inject\n"
        "  fragment [options] --pid <pid>              inject into a running process\n\n"
        "Options:\n"
        "  --dll <path>      DLL to inject (default: Fragment.dll, or Fragment32.dll\n"
        "                    for a 32-bit target, next to fragment.exe)\n"
        "  --proxy <url>     proxy base, e.g. http://127.0.0.1:9020  (FRAGMENT_PROXY)\n"
        "  --host <host>     proxy host                              (FRAGMENT_PROXY_HOST)\n"
        "  --port <port>     proxy port                             (FRAGMENT_PROXY_PORT)\n"
        "  --log <level>     off|error|warn|info|debug              (FRAGMENT_LOG_LEVEL)\n"
        "  --log-file <p>    write diagnostics to a file            (FRAGMENT_LOG_FILE)\n"
        "  --loader <how>    auto|notify|ldrloaddll|loadlibrary     (FRAGMENT_LOADER)\n"
        "  --off             inject but leave rewriting disabled    (FRAGMENT_ENABLED=0)\n"
        "  -h, --help        show this help\n"
        "  -V, --version     print the Fragment version\n\n"
        "Note: --proxy/--host/--port/--log* configure LAUNCHED targets (they are passed\n"
        "via the inherited environment). For --pid, set those environment variables\n"
        "before the target starts, or system-wide.\n");
}

/* Which Fragment.dll a target needs follows its bitness: a 32-bit (WOW64)
 * target loads only the 32-bit Fragment32.dll, a native x64 target the x64
 * Fragment.dll. Returns 1 if the target is a native x64 process, 0 if it is
 * 32-bit. */
static int target_is_x64(HANDLE hProc) {
    typedef BOOL (WINAPI *Wow64_2)(HANDLE, USHORT*, USHORT*);
    Wow64_2 fn = (Wow64_2)(void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsWow64Process2");
    if (fn) {
        USHORT proc = 0, native = 0;
        if (fn(hProc, &proc, &native))
            return proc == IMAGE_FILE_MACHINE_UNKNOWN;   /* not WOW64 => native x64 */
    }
    BOOL wow = FALSE;
    if (IsWow64Process(hProc, &wow)) return !wow;        /* on x64 Windows, !WOW64 => x64 */
    return 1;                                            /* undetermined: allow */
}

/* Read `n` bytes at remote address `base+rva` in the process behind `ctx`; the
 * PeReader the export walk drives over a live WOW64 image. */
struct RemoteImage { HANDLE proc; ULONG_PTR base; };
static int read_remote(void* ctx, DWORD rva, void* dst, DWORD n) {
    struct RemoteImage* img = (struct RemoteImage*) ctx;
    SIZE_T got = 0;
    return ReadProcessMemory(img->proc, (LPCVOID)(img->base + rva), dst, n, &got) && got == n;
}

/* Base of the target's 32-bit kernel32.dll. A snapshot taken with
 * TH32CS_SNAPMODULE32 lists the WOW64 (32-bit) modules of the target even from
 * this 64-bit process; 0 if it is not present yet. */
static ULONG_PTR wow64_kernel32(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32 me = { sizeof(me) };
    ULONG_PTR base = 0;
    if (Module32First(snap, &me)) {
        do {
            if (!_stricmp(me.szModule, "kernel32.dll")) { base = (ULONG_PTR) me.modBaseAddr; break; }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return base;
}

/* Address of LoadLibraryA as the remote thread must see it. For a native x64
 * target that is just our own kernel32 (the image is shared at one base); for a
 * 32-bit (WOW64) target our 64-bit LoadLibraryA is the wrong image, so we walk
 * the target's own 32-bit kernel32 exports. 0 (and thus no injection) on any
 * failure -- never a guessed address. */
static ULONG_PTR remote_loadlibrarya(HANDLE hProc, int wow64) {
    if (!wow64)
        return (ULONG_PTR) GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    struct RemoteImage img = { hProc, wow64_kernel32(GetProcessId(hProc)) };
    if (!img.base) return 0;
    DWORD rva = Pe32ExportRva(read_remote, &img, "LoadLibraryA");
    return rva ? img.base + rva : 0;
}

/* Inject dllPath into an already-opened process; `wow64` selects how the remote
 * LoadLibraryA is resolved. Returns 1 on apparent success. */
static int inject_into(HANDLE hProc, const char* dllPath, int wow64) {
    ULONG_PTR llp = remote_loadlibrarya(hProc, wow64);
    if (!llp) {
        fprintf(stderr, "[fragment] could not resolve %sLoadLibraryA in the target\n",
                wow64 ? "the WOW64 " : "");
        return 0;
    }
    SIZE_T n = strlen(dllPath) + 1;
    void* rem = VirtualAllocEx(hProc, NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rem) { fprintf(stderr, "[fragment] VirtualAllocEx failed %lu\n", GetLastError()); return 0; }
    if (!WriteProcessMemory(hProc, rem, dllPath, n, NULL)) {
        fprintf(stderr, "[fragment] WriteProcessMemory failed %lu\n", GetLastError());
        VirtualFreeEx(hProc, rem, 0, MEM_RELEASE);
        return 0;
    }
    LPTHREAD_START_ROUTINE ll = (LPTHREAD_START_ROUTINE) llp;
    HANDLE th = CreateRemoteThread(hProc, NULL, 0, ll, rem, 0, NULL);
    if (!th) {
        fprintf(stderr, "[fragment] CreateRemoteThread failed %lu\n", GetLastError());
        VirtualFreeEx(hProc, rem, 0, MEM_RELEASE);
        return 0;
    }
    DWORD loaded = 0;
    if (WaitForSingleObject(th, 15000) == WAIT_OBJECT_0) {
        GetExitCodeThread(th, &loaded);             /* low 32 bits of the HMODULE */
        VirtualFreeEx(hProc, rem, 0, MEM_RELEASE);  /* safe: remote thread finished */
    } else {
        /* A slow DllMain is still running LoadLibraryA -- do NOT free the path
         * buffer out from under it (that would crash the target). Leak it. */
        fprintf(stderr, "[fragment] injection thread did not finish in time\n");
    }
    CloseHandle(th);
    return loaded != 0;
}

/* Resolve the DLL to inject. With no --dll, default to the bitness-appropriate
 * module next to fragment.exe: Fragment.dll for an x64 target, Fragment32.dll
 * for a 32-bit (WOW64) target. Returns an absolute path in `buf`, or NULL (with
 * a message) if the file is absent. */
static const char* resolve_dll(const char* userDll, int wow64, char* buf, DWORD cap) {
    const char* name = wow64 ? "Fragment32.dll" : "Fragment.dll";
    char tmp[MAX_PATH];
    const char* dll = userDll;
    if (!dll) {
        GetModuleFileNameA(NULL, tmp, MAX_PATH);
        char* s = strrchr(tmp, '\\');
        if (s) s[1] = 0; else tmp[0] = 0;
        strncat(tmp, name, sizeof(tmp) - strlen(tmp) - 1);
        dll = tmp;
    }
    if (!GetFullPathNameA(dll, cap, buf, NULL)) return NULL;
    if (GetFileAttributesA(buf) == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "[fragment] %s not found at: %s\n", name, buf);
        return NULL;
    }
    return buf;
}

int main(int argc, char** argv) {
    const char *dll = NULL, *proxy = NULL, *host = NULL, *port = NULL, *log = NULL, *logfile = NULL, *loader = NULL;
    int off = 0, launchIdx = -1;
    DWORD pid = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--")) { launchIdx = i + 1; break; }
        else if (!strcmp(argv[i], "--pid") && i + 1 < argc) pid = (DWORD)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--dll") && i + 1 < argc) dll = argv[++i];
        else if (!strcmp(argv[i], "--proxy") && i + 1 < argc) proxy = argv[++i];
        else if (!strcmp(argv[i], "--host") && i + 1 < argc) host = argv[++i];
        else if (!strcmp(argv[i], "--port") && i + 1 < argc) port = argv[++i];
        else if (!strcmp(argv[i], "--log") && i + 1 < argc) log = argv[++i];
        else if (!strcmp(argv[i], "--log-file") && i + 1 < argc) logfile = argv[++i];
        else if (!strcmp(argv[i], "--loader") && i + 1 < argc) loader = argv[++i];
        else if (!strcmp(argv[i], "--off")) off = 1;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { usage(); return 0; }
        else if (!strcmp(argv[i], "-V") || !strcmp(argv[i], "--version")) { printf("fragment %s\n", FRAGMENT_VERSION); return 0; }
        else { fprintf(stderr, "[fragment] unknown option: %s\n", argv[i]); usage(); return 2; }
    }
    if (pid == 0 && launchIdx < 0) { usage(); return 2; }
    if (pid != 0 && launchIdx >= 0) { fprintf(stderr, "[fragment] choose either --pid or -- <program>, not both\n"); return 2; }
    if (launchIdx >= 0 && launchIdx >= argc) { fprintf(stderr, "[fragment] '--' must be followed by a program\n"); return 2; }

    /* The DLL is resolved AFTER the target is opened and its bitness is known,
     * so the default picks Fragment.dll vs Fragment32.dll to match the target. */
    char dllbuf[MAX_PATH];
    const char* path;

    /* Configuration is passed to LAUNCHED targets via the inherited env. */
    if (proxy)   SetEnvironmentVariableA("FRAGMENT_PROXY", proxy);
    if (host)    SetEnvironmentVariableA("FRAGMENT_PROXY_HOST", host);
    if (port)    SetEnvironmentVariableA("FRAGMENT_PROXY_PORT", port);
    if (log)     SetEnvironmentVariableA("FRAGMENT_LOG_LEVEL", log);
    if (logfile) SetEnvironmentVariableA("FRAGMENT_LOG_FILE", logfile);
    if (loader)  SetEnvironmentVariableA("FRAGMENT_LOADER", loader);
    if (off)     SetEnvironmentVariableA("FRAGMENT_ENABLED", "0");

    if (launchIdx >= 0) {
        char cmd[8192];
        cmd[0] = 0;
        for (int j = launchIdx; j < argc; j++) {
            if (j > launchIdx) strncat(cmd, " ", sizeof(cmd) - strlen(cmd) - 1);
            int q = strchr(argv[j], ' ') != NULL;
            if (q) strncat(cmd, "\"", sizeof(cmd) - strlen(cmd) - 1);
            strncat(cmd, argv[j], sizeof(cmd) - strlen(cmd) - 1);
            if (q) strncat(cmd, "\"", sizeof(cmd) - strlen(cmd) - 1);
        }
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            fprintf(stderr, "[fragment] CreateProcess failed %lu\n", GetLastError());
            return 4;
        }
        int wow = !target_is_x64(pi.hProcess);
        path = resolve_dll(dll, wow, dllbuf, sizeof(dllbuf));
        if (!path) {
            TerminateProcess(pi.hProcess, 1);   /* never leave a wedged suspended child */
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return 3;
        }
        int ok = inject_into(pi.hProcess, path, wow);
        ResumeThread(pi.hThread);    /* resume regardless, so we never wedge the target */
        if (ok) printf("[fragment] injected into pid %lu\n", pi.dwProcessId);
        else    fprintf(stderr, "[fragment] injection failed; target runs un-proxied\n");
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD ec = 0;
        GetExitCodeProcess(pi.hProcess, &ec);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return ok ? (int)ec : 5;
    } else {
        HANDLE hProc = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
        if (!hProc) { fprintf(stderr, "[fragment] OpenProcess(%lu) failed %lu\n", pid, GetLastError()); return 4; }
        int wow = !target_is_x64(hProc);
        path = resolve_dll(dll, wow, dllbuf, sizeof(dllbuf));
        if (!path) { CloseHandle(hProc); return 3; }
        int ok = inject_into(hProc, path, wow);
        CloseHandle(hProc);
        if (!ok) { fprintf(stderr, "[fragment] injection into pid %lu failed\n", pid); return 5; }
        printf("[fragment] injected into pid %lu\n", pid);
        return 0;
    }
}
