/*
 * Fragment loader -- redirects a target process's libcurl traffic through a
 * proxy by getting libfragment.so into it, either by launching a new program
 * with the library preloaded or by injecting into a running PID, and passes
 * configuration through to launched targets via the environment.
 *
 *   fragment [options] -- <program> [args...]   launch the program & preload
 *   fragment [options] --pid <pid>              inject into a running process
 *
 * x86-64 / aarch64 (the library is built for the host arch). Build: part of the
 * CMake project / build.sh (the `fragment` binary).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <signal.h>
#include <elf.h>
#include "../../common/version.h"

static void usage(void) {
    fprintf(stderr,
        "Fragment loader -- redirect a program's libcurl traffic through a proxy.\n\n"
        "Usage:\n"
        "  fragment [options] -- <program> [args...]   launch & preload\n"
        "  fragment [options] --pid <pid>              inject into a running process\n\n"
        "Options:\n"
        "  --so <path>       libfragment.so location (default: next to fragment)\n"
        "  --proxy <url>     proxy base, e.g. http://127.0.0.1:9020  (FRAGMENT_PROXY)\n"
        "  --host <host>     proxy host                              (FRAGMENT_PROXY_HOST)\n"
        "  --port <port>     proxy port                             (FRAGMENT_PROXY_PORT)\n"
        "  --log <level>     off|error|warn|info|debug              (FRAGMENT_LOG_LEVEL)\n"
        "  --log-file <p>    write diagnostics to a file            (FRAGMENT_LOG_FILE)\n"
        "  --loader <how>    auto|interpose|audit|hook              (FRAGMENT_LOADER)\n"
        "  --off             load but leave rewriting disabled      (FRAGMENT_ENABLED=0)\n"
        "  -h, --help        show this help\n"
        "  -V, --version     print the Fragment version\n\n"
        "Note: --proxy/--host/--port/--log*/--loader configure LAUNCHED targets (they are\n"
        "passed via the inherited environment). For --pid, set those environment variables\n"
        "before the target starts, or system-wide -- an injected library reads the target's\n"
        "own environment. 'audit' is a launch-only mode (it needs LD_AUDIT set at startup).\n");
}

/* Lowest base address of a mapping whose path contains `needle`, for `pid`
 * ("self" via /proc/self/maps when pid == 0). Returns 0 if not found. */
static unsigned long object_base(int pid, unsigned long want_ino) {
    if (!want_ino) return 0;
    char path[64];
    if (pid) snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    else     snprintf(path, sizeof(path), "/proc/self/maps");
    FILE* f = fopen(path, "r");
    if (!f) return 0;
    char line[1024];
    unsigned long best = 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned long s, e, off, ino;
        char perms[8], dev[16];
        if (sscanf(line, "%lx-%lx %7s %lx %15s %lu", &s, &e, perms, &off, dev, &ino) != 6) continue;
        if (ino == want_ino && (!best || s < best)) best = s;   /* lowest mapping of this file */
    }
    fclose(f);
    return best;
}

#if defined(__x86_64__) || defined(__aarch64__)
/* Inject `soPath` into a stopped (ptrace-attached) process by making it call
 * dlopen(soPath, RTLD_NOW). The target's dlopen address is computed from the
 * load offset of the object dlopen actually lives in -- libc.so.6 on glibc
 * >= 2.34, libdl.so.2 before it -- found in both processes by file IDENTITY
 * (inode), so a different libc build (where the offset would differ) is refused
 * rather than jumped into. The path string is written to the target's stack,
 * and the call returns to address 0 so the resulting fault hands control back to
 * us; we then read the handle and restore. */
static int inject_pid(int pid, const char* soPath) {
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) { fprintf(stderr, "[fragment] PTRACE_ATTACH(%d) failed: %s\n", pid, strerror(errno)); return 0; }
    int st;
    waitpid(pid, &st, 0);

    int ok = 0;

    /* Find the object dlopen lives in (dli_fbase = its load base in us), then
     * the SAME file in the target by inode. dlopen's offset within that object
     * is identical across processes only if it is the same file -- so matching
     * by inode both locates the right object and guards against a mismatched
     * libc. */
    void* selfDlopen = dlsym(RTLD_DEFAULT, "dlopen");
    Dl_info di;
    if (!selfDlopen || !dladdr(selfDlopen, &di) || !di.dli_fname || !di.dli_fbase) {
        fprintf(stderr, "[fragment] could not locate dlopen (static libc?)\n");
        goto detach;
    }
    struct stat dlst;
    if (stat(di.dli_fname, &dlst) != 0) {
        fprintf(stderr, "[fragment] stat(%s) failed: %s\n", di.dli_fname, strerror(errno));
        goto detach;
    }
    unsigned long tgtBase = object_base(pid, (unsigned long) dlst.st_ino);
    if (!tgtBase) {
        fprintf(stderr, "[fragment] target does not map %s (static or different libc); refusing\n", di.dli_fname);
        goto detach;
    }
    unsigned long dlopenAddr = (unsigned long) selfDlopen - (unsigned long) di.dli_fbase + tgtBase;

    struct user_regs_struct regs, saved;
    struct iovec iov = { &regs, sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, pid, (void*) NT_PRSTATUS, &iov) < 0) { fprintf(stderr, "[fragment] GETREGSET failed: %s\n", strerror(errno)); goto detach; }
    saved = regs;

    /* Write the path string into the target stack, well below the current SP. */
    char full[PATH_MAX];
    if (!realpath(soPath, full)) { strncpy(full, soPath, sizeof(full) - 1); full[sizeof(full) - 1] = 0; }
    size_t slen = strlen(full) + 1;

#if defined(__x86_64__)
    unsigned long sp = saved.rsp;
#else
    unsigned long sp = saved.sp;
#endif
    unsigned long strAddr = (sp - 1024 - slen) & ~0xFUL;
    struct iovec local = { full, slen };
    struct iovec remote = { (void*) strAddr, slen };
    if (process_vm_writev(pid, &local, 1, &remote, 1, 0) != (ssize_t) slen) {
        fprintf(stderr, "[fragment] writing path into target failed: %s\n", strerror(errno));
        goto detach;
    }

#if defined(__x86_64__)
    unsigned long callSp = (strAddr - 256) & ~0xFUL;
    callSp -= 8;                                  /* make rsp%16==8 on entry */
    unsigned long zero = 0;
    struct iovec lz = { &zero, 8 }, rz = { (void*) callSp, 8 };
    process_vm_writev(pid, &lz, 1, &rz, 1, 0);    /* return address = 0 -> fault */
    regs.rdi = strAddr;        /* path  */
    regs.rsi = 2;              /* RTLD_NOW */
    regs.rsp = callSp;
    regs.rip = dlopenAddr;
#else
    unsigned long callSp = (strAddr - 256) & ~0xFUL;
    regs.regs[0] = strAddr;    /* x0 = path  */
    regs.regs[1] = 2;          /* x1 = RTLD_NOW */
    regs.regs[30] = 0;         /* lr = 0 -> fault on return */
    regs.sp = callSp;
    regs.pc = dlopenAddr;
#endif
    if (ptrace(PTRACE_SETREGSET, pid, (void*) NT_PRSTATUS, &iov) < 0) { fprintf(stderr, "[fragment] SETREGSET failed: %s\n", strerror(errno)); goto detach; }

    /* Run until the call returns to 0 and faults back to us. Any OTHER signal
     * the target receives mid-dlopen is re-delivered and we keep waiting, so we
     * never abandon the call half-done (which could leave the target stopped
     * while holding the loader lock). */
    if (ptrace(PTRACE_CONT, pid, 0, 0) < 0) { fprintf(stderr, "[fragment] CONT failed: %s\n", strerror(errno)); goto detach; }

    struct user_regs_struct after;
    struct iovec ia = { &after, sizeof(after) };
    for (;;) {
        if (waitpid(pid, &st, 0) < 0) { if (errno == EINTR) continue; goto detach; }
        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            fprintf(stderr, "[fragment] target exited during injection\n");
            return 0;                         /* gone -- nothing to restore/detach */
        }
        if (!WIFSTOPPED(st)) continue;
        int sig = WSTOPSIG(st);
        if (sig == SIGSEGV && ptrace(PTRACE_GETREGSET, pid, (void*) NT_PRSTATUS, &ia) == 0) {
#if defined(__x86_64__)
            unsigned long pc = after.rip, handle = after.rax;
#else
            unsigned long pc = after.pc, handle = after.regs[0];
#endif
            if (pc == 0) {                    /* our return-to-0 completion fault */
                ok = handle != 0;
                if (!ok) fprintf(stderr, "[fragment] dlopen in target returned NULL (library not loaded)\n");
                break;
            }
        }
        ptrace(PTRACE_CONT, pid, 0, sig);     /* unrelated signal: deliver and resume */
    }

    /* Restore the original registers so the target resumes cleanly. */
    iov.iov_base = &saved;
    ptrace(PTRACE_SETREGSET, pid, (void*) NT_PRSTATUS, &iov);

detach:
    ptrace(PTRACE_DETACH, pid, 0, 0);
    return ok;
}
#else
static int inject_pid(int pid, const char* soPath) {
    (void) pid; (void) soPath;
    fprintf(stderr, "[fragment] --pid injection is implemented for x86-64 / aarch64 only\n");
    return 0;
}
#endif

int main(int argc, char** argv) {
    const char *so = NULL, *proxy = NULL, *host = NULL, *port = NULL, *log = NULL, *logfile = NULL, *loader = NULL;
    int off = 0, launchIdx = -1, pid = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--")) { launchIdx = i + 1; break; }
        else if (!strcmp(argv[i], "--pid") && i + 1 < argc) pid = (int) strtol(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--so") && i + 1 < argc) so = argv[++i];
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

    /* Resolve the library path: default to libfragment.so next to this binary. */
    char sobuf[PATH_MAX + 32], soabs[PATH_MAX];   /* room for "<dir>/libfragment.so" */
    if (!so) {
        char self[PATH_MAX];
        ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
        if (n > 0) {
            self[n] = 0;
            char* slash = strrchr(self, '/');
            if (slash) *slash = 0;
            snprintf(sobuf, sizeof(sobuf), "%s/libfragment.so", self);
            so = sobuf;
        } else {
            so = "libfragment.so";
        }
    }
    if (realpath(so, soabs)) so = soabs;
    struct stat stbuf;
    if (stat(so, &stbuf) != 0) {
        fprintf(stderr, "[fragment] libfragment.so not found at: %s\n", so);
        return 3;
    }

    int auditMode = loader && (!strcmp(loader, "audit") || !strcmp(loader, "rtld"));

    /* Configuration is passed to LAUNCHED targets via the inherited env. */
    if (proxy)   setenv("FRAGMENT_PROXY", proxy, 1);
    if (host)    setenv("FRAGMENT_PROXY_HOST", host, 1);
    if (port)    setenv("FRAGMENT_PROXY_PORT", port, 1);
    if (log)     setenv("FRAGMENT_LOG_LEVEL", log, 1);
    if (logfile) setenv("FRAGMENT_LOG_FILE", logfile, 1);
    if (loader)  setenv("FRAGMENT_LOADER", loader, 1);
    if (off)     setenv("FRAGMENT_ENABLED", "0", 1);

    if (launchIdx >= 0) {
        /* Prepend our library to the right loader variable: LD_AUDIT for the
         * audit mode (so the bindings the auditor sees are the genuine libcurl,
         * not a preload shadow), LD_PRELOAD otherwise. */
        const char* var = auditMode ? "LD_AUDIT" : "LD_PRELOAD";
        const char* cur = getenv(var);
        char val[PATH_MAX * 2];
        if (cur && *cur) snprintf(val, sizeof(val), "%s:%s", so, cur);
        else             snprintf(val, sizeof(val), "%s", so);
        setenv(var, val, 1);

        execvp(argv[launchIdx], &argv[launchIdx]);
        fprintf(stderr, "[fragment] exec '%s' failed: %s\n", argv[launchIdx], strerror(errno));
        return 4;
    } else {
        if (auditMode)
            fprintf(stderr, "[fragment] note: 'audit' needs LD_AUDIT at startup; an injected library uses inline hooking instead\n");
        if (inject_pid(pid, so)) {
            printf("[fragment] injected into pid %d\n", pid);
            return 0;
        }
        fprintf(stderr, "[fragment] injection into pid %d failed\n", pid);
        return 5;
    }
}
