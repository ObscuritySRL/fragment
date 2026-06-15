/*
 * Fragment loader -- injects the libcurl-rewriting DLL into a target process,
 * either by launching a new program or by attaching to a running PID, and
 * passes configuration through to the target via the environment.
 *
 *   fragment [options] -- <program> [args...]   launch the program & inject
 *   fragment [options] --pid <pid>              inject into a running process
 *
 * x86-64 only (the DLL is x64). Build: part of the CMake project (fragment.exe).
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(void) {
    fprintf(stderr,
        "Fragment loader -- redirect a program's libcurl traffic through a proxy.\n\n"
        "Usage:\n"
        "  fragment [options] -- <program> [args...]   launch & inject\n"
        "  fragment [options] --pid <pid>              inject into a running process\n\n"
        "Options:\n"
        "  --dll <path>      Fragment.dll location (default: next to fragment.exe)\n"
        "  --proxy <url>     proxy base, e.g. http://127.0.0.1:9020  (FRAGMENT_PROXY)\n"
        "  --host <host>     proxy host                              (FRAGMENT_PROXY_HOST)\n"
        "  --port <port>     proxy port                             (FRAGMENT_PROXY_PORT)\n"
        "  --log <level>     off|error|warn|info|debug              (FRAGMENT_LOG_LEVEL)\n"
        "  --log-file <p>    write diagnostics to a file            (FRAGMENT_LOG_FILE)\n"
        "  --loader <how>    auto|notify|ldrloaddll|loadlibrary     (FRAGMENT_LOADER)\n"
        "  --off             inject but leave rewriting disabled    (FRAGMENT_ENABLED=0)\n"
        "  -h, --help        show this help\n\n"
        "Note: --proxy/--host/--port/--log* configure LAUNCHED targets (they are passed\n"
        "via the inherited environment). For --pid, set those environment variables\n"
        "before the target starts, or system-wide.\n");
}

/* Fragment.dll is x64; injecting it into a 32-bit (WOW64) target cannot work.
 * Returns 1 if the target is a native x64 process, 0 if it is 32-bit. */
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

/* Inject dllPath into an already-opened process. Returns 1 on apparent success. */
static int inject_into(HANDLE hProc, const char* dllPath) {
    SIZE_T n = strlen(dllPath) + 1;
    void* rem = VirtualAllocEx(hProc, NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rem) { fprintf(stderr, "[fragment] VirtualAllocEx failed %lu\n", GetLastError()); return 0; }
    if (!WriteProcessMemory(hProc, rem, dllPath, n, NULL)) {
        fprintf(stderr, "[fragment] WriteProcessMemory failed %lu\n", GetLastError());
        VirtualFreeEx(hProc, rem, 0, MEM_RELEASE);
        return 0;
    }
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE ll = (LPTHREAD_START_ROUTINE)(void*)GetProcAddress(k32, "LoadLibraryA");
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
        else { fprintf(stderr, "[fragment] unknown option: %s\n", argv[i]); usage(); return 2; }
    }
    if (pid == 0 && launchIdx < 0) { usage(); return 2; }
    if (pid != 0 && launchIdx >= 0) { fprintf(stderr, "[fragment] choose either --pid or -- <program>, not both\n"); return 2; }
    if (launchIdx >= 0 && launchIdx >= argc) { fprintf(stderr, "[fragment] '--' must be followed by a program\n"); return 2; }

    /* Resolve the DLL path: default to Fragment.dll next to this exe. */
    char dllbuf[MAX_PATH], dllabs[MAX_PATH];
    if (!dll) {
        GetModuleFileNameA(NULL, dllbuf, MAX_PATH);
        char* s = strrchr(dllbuf, '\\');
        if (s) s[1] = 0;
        strncat(dllbuf, "Fragment.dll", sizeof(dllbuf) - strlen(dllbuf) - 1);
        dll = dllbuf;
    }
    if (GetFullPathNameA(dll, MAX_PATH, dllabs, NULL)) dll = dllabs;
    if (GetFileAttributesA(dll) == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "[fragment] Fragment.dll not found at: %s\n", dll);
        return 3;
    }

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
        int ok = inject_into(pi.hProcess, dll);
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
        int ok = inject_into(hProc, dll);
        CloseHandle(hProc);
        if (!ok) { fprintf(stderr, "[fragment] injection into pid %lu failed\n", pid); return 5; }
        printf("[fragment] injected into pid %lu\n", pid);
        return 0;
    }
}
