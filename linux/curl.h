#pragma once

#include "../common/curl_abi.h"

// curl_easy_setopt is variadic. Every real CURLOPT_* value is a single
// general-purpose word -- a pointer, a long, a curl_off_t (64-bit), or a
// function pointer; libcurl has NO option that takes a float/double -- so the
// one vararg is always passed in a single integer register on both the SysV
// (x86-64) and AAPCS64 (aarch64) ABIs. We therefore both receive and forward it
// through this fixed 3-argument view, sidestepping the un-forwardable va_list.
typedef CURLcode(*CurlSetoptFn)(void*, CURLoption, void*);

// curl_url_set(CURLU *handle, CURLUPart what, const char *part, unsigned flags)
typedef CURLUcode(*CurlUrlSetFn)(void*, CURLUPart, const char*, unsigned int);
// curl_url_get(CURLU *handle, CURLUPart what, char **part, unsigned flags)
typedef CURLUcode(*CurlUrlGetFn)(void*, CURLUPart, char**, unsigned int);
typedef void(*CurlFreeFn)(void*);
