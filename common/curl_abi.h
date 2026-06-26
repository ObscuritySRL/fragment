#pragma once

// The slice of libcurl's stable ABI that does not change with the OS: the
// option ids and the scalar types. Shared by both ports -- these numbers are
// part of libcurl's stable ABI and have never been renumbered, so they are
// valid for every curl version. The function-pointer typedefs DO differ by
// calling convention (a va_list slot on the Windows trampoline, a single
// general-purpose word on the System V / AAPCS64 path) and live in each port's
// curl.h.

typedef long CURLcode;
typedef int  CURLoption;
typedef int  CURLUcode;
typedef int  CURLUPart;

// curl_easy_setopt option ids.
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
const CURLUPart CURLUPART_URL = 0;             // CURLUPart enum: URL == 0
