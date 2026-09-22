/* Exercise partial activation and allocation failures without touching WinHTTP. */
#include <winsock2.h>
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
static int failAllocation;
static void* testAlloc(size_t size) { return failAllocation ? NULL : malloc(size); }
#define malloc testAlloc
#include "../main.c"
#undef malloc

static int failures, closes;
static DWORD accessSeen, flagsSeen;
static wchar_t hostSeen[256], pathSeen[512];
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d: %s\n", __LINE__, #x); failures++; } } while (0)
static HINTERNET WINAPI openMock(LPCWSTR a, DWORD access, LPCWSTR p, LPCWSTR b, DWORD f) {
    accessSeen = access; return (HINTERNET)1;
}
static HINTERNET WINAPI connectMock(HINTERNET s, LPCWSTR host, INTERNET_PORT p, DWORD r) {
    wcscpy_s(hostSeen, 256, host); return (HINTERNET)2;
}
static HINTERNET WINAPI requestMock(HINTERNET c, LPCWSTR v, LPCWSTR path, LPCWSTR ver,
                                  LPCWSTR ref, LPCWSTR* types, DWORD flags) {
    wcscpy_s(pathSeen, 512, path); flagsSeen = flags; return (HINTERNET)3;
}
static BOOL WINAPI closeMock(HINTERNET h) { closes++; return TRUE; }
int main(void) {
    InitializeCriticalSection(&gWhLock);
    gWhLockReady = 1;
    gWhOpen = openMock; gWhConnect = connectMock;
    gWhOpenRequest = requestMock; gWhClose = closeMock;
    wcscpy_s(gCfg.proxyHostW, 256, L"127.0.0.1"); gCfg.proxyPort = 19020;
    gWhActive = 0;
    WhOpenDetour(L"test", WINHTTP_ACCESS_TYPE_NAMED_PROXY, L"proxy", NULL, 0);
    CHECK(accessSeen == WINHTTP_ACCESS_TYPE_NAMED_PROXY);
    WhConnectDetour((HINTERNET)1, L"origin", 443, 0);
    CHECK(!wcscmp(hostSeen, L"origin"));
    CHECK(gWhConns == NULL);

    gWhActive = 1;
    WhOpenDetour(L"test", WINHTTP_ACCESS_TYPE_NAMED_PROXY, L"proxy", NULL, 0);
    CHECK(accessSeen == WINHTTP_ACCESS_TYPE_NO_PROXY);
    CHECK(WhConnectDetour((HINTERNET)1, L"origin", 8443, 0) != NULL);
    CHECK(!wcscmp(hostSeen, L"127.0.0.1"));
    CHECK(WhOpenRequestDetour((HINTERNET)2, L"GET", L"/path?q=1", NULL, NULL, NULL, WINHTTP_FLAG_SECURE) != NULL);
    CHECK(!wcscmp(pathSeen, L"/https://origin:8443/path?q=1"));
    CHECK(!(flagsSeen & WINHTTP_FLAG_SECURE));

    failAllocation = 1;
    CHECK(WhOpenRequestDetour((HINTERNET)2, L"GET", L"/path", NULL, NULL, NULL, WINHTTP_FLAG_SECURE) == NULL);
    CHECK(GetLastError() == ERROR_NOT_ENOUGH_MEMORY);
    WhForget((HINTERNET)1);
    CHECK(gWhConns == NULL);
    CHECK(WhConnectDetour((HINTERNET)1, L"origin", 443, 0) == NULL);
    CHECK(GetLastError() == ERROR_NOT_ENOUGH_MEMORY);
    CHECK(closes == 1);
    CHECK(gWhConns == NULL);
    DeleteCriticalSection(&gWhLock);
    printf("WinHTTP state tests: %d failures\n", failures);
    return failures ? 1 : 0;
}
