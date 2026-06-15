/* Minimal CreateProcess + remote-LoadLibrary injector, for testing the
 * statically-linked-curl (no exports) path.
 *
 *   inject <Fragment.dll> <target.exe> [args...]
 *
 * Starts the target SUSPENDED, injects the DLL via a remote LoadLibraryA
 * thread (so DllMain runs and installs hooks before the target's main()
 * proceeds), then resumes and waits for it to finish.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: inject <Fragment.dll> <target.exe> [args...]\n");
        return 2;
    }

    char dll[MAX_PATH];
    if (!GetFullPathNameA(argv[1], MAX_PATH, dll, NULL)) {
        fprintf(stderr, "[inject] GetFullPathName failed %lu\n", GetLastError());
        return 3;
    }

    char cmd[8192];
    cmd[0] = 0;
    for (int i = 2; i < argc; i++) {
        if (i > 2) strcat(cmd, " ");
        strcat(cmd, "\"");
        strcat(cmd, argv[i]);
        strcat(cmd, "\"");
    }

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "[inject] CreateProcess failed %lu\n", GetLastError());
        return 3;
    }

    SIZE_T n = strlen(dll) + 1;
    void *rem = VirtualAllocEx(pi.hProcess, NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rem || !WriteProcessMemory(pi.hProcess, rem, dll, n, NULL)) {
        fprintf(stderr, "[inject] write remote memory failed %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 4;
    }

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE ll = (LPTHREAD_START_ROUTINE)(void*)GetProcAddress(k32, "LoadLibraryA");
    HANDLE th = CreateRemoteThread(pi.hProcess, NULL, 0, ll, rem, 0, NULL);
    if (!th) {
        fprintf(stderr, "[inject] CreateRemoteThread failed %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 4;
    }
    WaitForSingleObject(th, 15000);
    DWORD remoteModule = 0;
    GetExitCodeThread(th, &remoteModule);   /* low 32 bits of injected HMODULE */
    CloseHandle(th);

    ResumeThread(pi.hThread);
    DWORD waited = WaitForSingleObject(pi.hProcess, 15000);
    DWORD ec = 0;
    GetExitCodeProcess(pi.hProcess, &ec);
    if (waited != WAIT_OBJECT_0) TerminateProcess(pi.hProcess, 0);

    printf("[inject] remoteLoadLibrary=0x%lx targetExit=%lu\n", remoteModule, ec);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return remoteModule ? 0 : 5;
}
