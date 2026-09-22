/* Exercise the real binary JSONL sink, including concurrent writers and I/O failure. */
#include "../capture.h"

static DWORD WINAPI writer(LPVOID argument) {
    unsigned char bytes[] = {(unsigned char)(ULONG_PTR)argument, 0, 255};
    unsigned long long connection = CaptureNextConnection();
    for (int i = 0; i < 20; ++i) CaptureWrite("test", connection, "in", bytes, sizeof(bytes), sizeof(bytes));
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 2) return 2;
    if (!CaptureInit(argv[1])) return 7;
    CaptureBackend("test", TRUE);
    const unsigned char bytes[] = {0, 255, 128, '"', '\\', '\n'};
    unsigned long long connection = CaptureNextConnection();
    SetLastError(12345);
    CaptureWrite("test", connection, "out", bytes, sizeof(bytes), sizeof(bytes));
    if (GetLastError() != 12345) return 3;
    size_t size = FRAGMENT_CAPTURE_LIMIT + 17;
    unsigned char* large = (unsigned char*)malloc(size);
    if (!large) return 4;
    memset(large, 0xa5, size);
    CaptureWrite("test", connection, "out", large, size, size);
    free(large);
    CaptureGap("test", connection, "out", "test-gap");
    HANDLE threads[4];
    for (int i = 0; i < 4; ++i) {
        threads[i] = CreateThread(NULL, 0, writer, (LPVOID)(ULONG_PTR)(i + 1), 0, NULL);
        if (!threads[i]) return 5;
    }
    if (WaitForMultipleObjects(4, threads, TRUE, 10000) != WAIT_OBJECT_0) return 6;
    for (int i = 0; i < 4; ++i) CloseHandle(threads[i]);
    /* Simulate disk failure without filling the user's disk or changing TLS. */
    CloseHandle(gCaptureFile);
    SetLastError(54321);
    CaptureWrite("test", connection, "out", bytes, sizeof(bytes), sizeof(bytes));
    if (CaptureAvailable() || GetLastError() != 54321) return 8;
    return 0;
}
