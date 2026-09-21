#pragma once
#include <stdlib.h>
#include <wchar.h>

/* Quote every argument using the Windows CRT rules. Backslashes are doubled
 * only before a quote or the closing quote; empty arguments remain explicit.
 * CreateProcessW limits the entire command line, including NUL, to 32767. */
static wchar_t* FragmentCommandLine(int argc, wchar_t* const* argv) {
    size_t capacity = 1;
    for (int i = 0; i < argc; ++i) {
        size_t n = wcslen(argv[i]);
        if (n > 32766 || capacity + 2 * n + 3 > 65535) return NULL;
        capacity += 2 * n + 3;
    }
    wchar_t* result = (wchar_t*)malloc(capacity * sizeof(wchar_t));
    if (!result) return NULL;
    wchar_t* out = result;
    for (int i = 0; i < argc; ++i) {
        if (i) *out++ = L' ';
        *out++ = L'"';
        const wchar_t* p = argv[i];
        for (;;) {
            size_t slashes = 0;
            while (*p == L'\\') { ++slashes; ++p; }
            size_t count = (*p == L'"' || !*p) ? 2 * slashes : slashes;
            while (count--) *out++ = L'\\';
            if (!*p) break;
            if (*p == L'"') *out++ = L'\\';
            *out++ = *p++;
        }
        *out++ = L'"';
    }
    *out = 0;
    if (out - result >= 32767) { free(result); return NULL; }
    return result;
}
