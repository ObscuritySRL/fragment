#pragma once

#include "../common/curl_abi.h"

// curl_easy_setopt is variadic; the generated trampoline passes the first
// vararg by value, so we receive it as a va_list-typed slot.
typedef CURLcode(*CurlSetoptFn)(void*, CURLoption, va_list);

// curl_url_set(CURLU *handle, CURLUPart what, const char *part, unsigned flags)
typedef CURLUcode(*CurlUrlSetFn)(void*, CURLUPart, const char*, unsigned int);
// curl_url_get(CURLU *handle, CURLUPart what, char **part, unsigned flags)
typedef CURLUcode(*CurlUrlGetFn)(void*, CURLUPart, char**, unsigned int);
typedef void(*CurlFreeFn)(void*);
