/* Emit a UTF-8 JSON array so Bun can compare a direct and launched argv. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int wmain(int argc, wchar_t** argv) {
    putchar('[');
    for (int i = 1; i < argc; ++i) {
        if (i > 1) putchar(',');
        int n = WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, NULL, 0, NULL, NULL);
        char* text = (char*)malloc(n);
        if (!text) return 2;
        WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, text, n, NULL, NULL);
        putchar('"');
        for (unsigned char* p = (unsigned char*)text; *p; ++p) {
            if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
            else if (*p < 32) printf("\\u%04x", (unsigned)*p);
            else putchar(*p);
        }
        putchar('"');
        free(text);
    }
    puts("]");
    return 0;
}
