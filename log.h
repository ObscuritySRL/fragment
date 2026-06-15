#pragma once

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>

/*
 * Runtime, leveled, thread-safe diagnostics.
 *
 * Unlike a DEBUG-only build that printf()s to a hardcoded path, this logger
 * works in Release: the severity threshold and the destination are chosen
 * once at load time from the environment (see config.h). When the level is
 * OFF the hot path costs a single comparison, so leaving log points in
 * shipping code is essentially free.
 */

enum {
    FRAG_LOG_OFF = 0,
    FRAG_LOG_ERROR,
    FRAG_LOG_WARN,
    FRAG_LOG_INFO,
    FRAG_LOG_DEBUG
};

static volatile LONG    gLogLevel = FRAG_LOG_OFF;
static FILE*            gLogFile  = NULL;   /* NULL sink => OutputDebugStringA */
static CRITICAL_SECTION gLogLock;
static volatile LONG    gLogReady = 0;

/* Open the chosen sink. `file` may be NULL/empty (=> debugger output via
 * OutputDebugStringA, visible in DebugView). `console` allocates a console
 * and tees stdout there, handy for GUI hosts with no console. Call once. */
static void LogOpen(int level, const char* file, BOOL console) {
    InitializeCriticalSection(&gLogLock);

    if (console) {
        AllocConsole();
        FILE* tmp = NULL;
        freopen_s(&tmp, "CONOUT$", "w", stdout);
    }
    if (file && *file) {
        gLogFile = fopen(file, "a");        /* append: runs accumulate */
        if (!gLogFile && console) gLogFile = stdout;
    } else if (console) {
        gLogFile = stdout;
    }

    gLogLevel = level;
    /* Publish readiness LAST (release): a concurrent writer must never see
     * gLogReady before the lock and sink are fully constructed. */
    InterlockedExchange(&gLogReady, 1);
}

/* Flush and close the sink. Like HookEngineShutdown, intentionally not wired
 * into DllMain (the module pins itself, so there is no DLL_PROCESS_DETACH); each
 * LogWrite already fflushes, so no diagnostics are lost at process exit. Kept
 * for completeness / embedders. */
static void LogClose(void) {
    if (!gLogReady) return;
    InterlockedExchange(&gLogReady, 0);     /* stop new writers entering */
    EnterCriticalSection(&gLogLock);
    if (gLogFile && gLogFile != stdout) fclose(gLogFile);
    gLogFile = NULL;
    LeaveCriticalSection(&gLogLock);
    DeleteCriticalSection(&gLogLock);
}

static void LogWrite(int level, const char* fmt, ...) {
    if (level > gLogLevel) return;          /* OFF => one comparison, no work */

    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);  /* always NUL-terminates */
    va_end(ap);

    if (!gLogReady) { OutputDebugStringA(buf); return; }
    EnterCriticalSection(&gLogLock);
    if (gLogFile) {
        fputs(buf, gLogFile);
        fflush(gLogFile);
    } else {
        OutputDebugStringA(buf);
    }
    LeaveCriticalSection(&gLogLock);
}

#define LogError(...) LogWrite(FRAG_LOG_ERROR, __VA_ARGS__)
#define LogWarn(...)  LogWrite(FRAG_LOG_WARN,  __VA_ARGS__)
#define LogInfo(...)  LogWrite(FRAG_LOG_INFO,  __VA_ARGS__)
#define LogDebug(...) LogWrite(FRAG_LOG_DEBUG, __VA_ARGS__)
