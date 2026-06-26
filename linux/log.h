#pragma once

#include <pthread.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/*
 * Runtime, leveled, thread-safe diagnostics.
 *
 * Unlike a DEBUG-only build that printf()s to a hardcoded path, this logger
 * works in Release: the severity threshold and the destination are chosen
 * once at load time from the environment (see config.h). When the level is
 * OFF the hot path costs a single comparison, so leaving log points in
 * shipping code is essentially free.
 *
 * The default sink is stderr -- the Linux analogue of the Windows build's
 * OutputDebugString: out of band from the target's own stdout, and silent
 * unless someone is watching (and in Release the level defaults to OFF, so
 * nothing is written at all unless logging is explicitly requested).
 */

enum {
    FRAG_LOG_OFF = 0,
    FRAG_LOG_ERROR,
    FRAG_LOG_WARN,
    FRAG_LOG_INFO,
    FRAG_LOG_DEBUG
};

static volatile int     gLogLevel = FRAG_LOG_OFF;
static FILE*            gLogFile  = NULL;   /* NULL sink => stderr */
static int             gLogTee   = 0;      /* also echo to stderr when a file is set */
static pthread_mutex_t gLogLock  = PTHREAD_MUTEX_INITIALIZER;
static volatile int     gLogReady = 0;

/* Open the chosen sink. `file` may be NULL/empty (=> stderr). `console` forces
 * an stderr tee even when a file is set (handy when a wrapper has redirected
 * the target's stderr to a log of its own and you still want it on the tty).
 * Call once. */
static void LogOpen(int level, const char* file, int console) {
    if (file && *file) {
        gLogFile = fopen(file, "a");        /* append: runs accumulate */
        gLogTee  = console;                 /* tee file -> stderr when asked */
    } else {
        gLogFile = NULL;                    /* stderr */
    }

    gLogLevel = level;
    /* Publish readiness LAST (release): a concurrent writer must never see
     * gLogReady before the sink is fully constructed. */
    __atomic_store_n(&gLogReady, 1, __ATOMIC_RELEASE);
}

/* Flush and close the sink. Like HookEngineShutdown, intentionally not wired
 * into the destructor (the module pins itself, so it is never unloaded); each
 * LogWrite already fflushes, so no diagnostics are lost at process exit. Kept
 * for completeness / embedders. */
static void LogClose(void) {
    if (!gLogReady) return;
    __atomic_store_n(&gLogReady, 0, __ATOMIC_RELEASE);  /* stop new writers entering */
    pthread_mutex_lock(&gLogLock);
    if (gLogFile) fclose(gLogFile);
    gLogFile = NULL;
    pthread_mutex_unlock(&gLogLock);
}

static void LogWrite(int level, const char* fmt, ...) {
    if (level > gLogLevel) return;          /* OFF => one comparison, no work */

    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);   /* always NUL-terminates */
    va_end(ap);

    if (!__atomic_load_n(&gLogReady, __ATOMIC_ACQUIRE)) { fputs(buf, stderr); return; }
    pthread_mutex_lock(&gLogLock);
    if (gLogFile) {
        fputs(buf, gLogFile);
        fflush(gLogFile);
        if (gLogTee) { fputs(buf, stderr); fflush(stderr); }
    } else {
        fputs(buf, stderr);
        fflush(stderr);
    }
    pthread_mutex_unlock(&gLogLock);
}

#define LogError(...) LogWrite(FRAG_LOG_ERROR, __VA_ARGS__)
#define LogWarn(...)  LogWrite(FRAG_LOG_WARN,  __VA_ARGS__)
#define LogInfo(...)  LogWrite(FRAG_LOG_INFO,  __VA_ARGS__)
#define LogDebug(...) LogWrite(FRAG_LOG_DEBUG, __VA_ARGS__)
