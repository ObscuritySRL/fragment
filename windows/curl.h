#pragma once

#include "../common/curl_abi.h"

// Keep the real ABI variadic: on 32-bit targets curl_off_t occupies two words.
typedef CURLcode(*CurlSetoptFn)(void*, CURLoption, ...);

// curl_url_set(CURLU *handle, CURLUPart what, const char *part, unsigned flags)
typedef CURLUcode(*CurlUrlSetFn)(void*, CURLUPart, const char*, unsigned int);
// curl_url_get(CURLU *handle, CURLUPart what, char **part, unsigned flags)
typedef CURLUcode(*CurlUrlGetFn)(void*, CURLUPart, char**, unsigned int);
typedef void(*CurlFreeFn)(void*);
