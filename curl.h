#pragma once

typedef long CURLcode;
typedef int CURLoption;

// curl_easy_setopt option ids. These are part of libcurl's stable ABI and
// have never been renumbered, so they are valid for every curl version.
const CURLoption CURLOPT_PORT       = 3;       // CURLOPTTYPE_LONG + 3
const CURLoption CURLOPT_URL        = 10002;   // CURLOPTTYPE_OBJECTPOINT + 2
const CURLoption CURLOPT_PROXY      = 10004;   // + 4    (proxy URL)
const CURLoption CURLOPT_RESOLVE    = 10203;   // + 203  (DNS pin list)
const CURLoption CURLOPT_UNIX_SOCKET_PATH     = 10231; // + 231 (Unix socket)
const CURLoption CURLOPT_CONNECT_TO = 10243;   // + 243  (connect-to list)
const CURLoption CURLOPT_PRE_PROXY  = 10262;   // + 262  (pre/SOCKS proxy)
const CURLoption CURLOPT_ABSTRACT_UNIX_SOCKET = 10264; // + 264 (abstract UDS)
const CURLoption CURLOPT_CURLU      = 10282;   // + 282  (parsed URL handle)

// curl_url API (the "URL handle" interface, libcurl >= 7.62).
typedef int CURLUcode;
typedef int CURLUPart;
const CURLUPart CURLUPART_URL = 0;             // CURLUPart enum: URL == 0

// curl_easy_setopt is variadic; the generated trampoline passes the first
// vararg by value, so we receive it as a va_list-typed slot.
typedef CURLcode(*CurlSetoptFn)(void*, CURLoption, va_list);

// curl_url_set(CURLU *handle, CURLUPart what, const char *part, unsigned flags)
typedef CURLUcode(*CurlUrlSetFn)(void*, CURLUPart, const char*, unsigned int);
// curl_url_get(CURLU *handle, CURLUPart what, char **part, unsigned flags)
typedef CURLUcode(*CurlUrlGetFn)(void*, CURLUPart, char**, unsigned int);
typedef void(*CurlFreeFn)(void*);
