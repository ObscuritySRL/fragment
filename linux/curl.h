#pragma once

#include "../common/curl_abi.h"

// Keep the actual variadic ABI. curl_off_t is 64 bits even on i386/armv7;
// those caller stubs preserve its two words and the detours forward its type.
typedef CURLcode(*CurlSetoptFn)(void*, CURLoption, ...);

// curl_url_set(CURLU *handle, CURLUPart what, const char *part, unsigned flags)
typedef CURLUcode(*CurlUrlSetFn)(void*, CURLUPart, const char*, unsigned int);
// curl_url_get(CURLU *handle, CURLUPart what, char **part, unsigned flags)
typedef CURLUcode(*CurlUrlGetFn)(void*, CURLUPart, char**, unsigned int);
typedef void(*CurlFreeFn)(void*);
