/* Tiny public-ABI test double, never a TLS implementation. Build /Od so its
 * compiler-generated prologues exercise supported inline relocation cases. */
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define API __declspec(dllexport) __declspec(noinline)
typedef struct MockSsl { int fail; int limit; } MockSsl;
static const unsigned char reply[] = {'r', 0, 255, 'x'};
API void* __cdecl SSL_CTX_new(const void* method) { (void)method; return (void*)1; }
API void* __cdecl SSL_new(void* context) { (void)context; return calloc(1, sizeof(MockSsl)); }
API int __cdecl SSL_get_error(void* context, int status) { (void)context; return status < 0 ? 2 : 0; }
API void __cdecl SSL_mock_set(void* context, int fail, int limit) {
    MockSsl* ssl = (MockSsl*)context; ssl->fail = fail; ssl->limit = limit;
}
API int __cdecl SSL_write(void* context, const void* data, int length) {
    MockSsl* ssl = (MockSsl*)context; int result = length;
    (void)data;
    if (ssl->fail) result = -1;
    else if (ssl->limit > 0 && result > ssl->limit) result = ssl->limit;
    errno = EINVAL; SetLastError(456); return result;
}
API int __cdecl SSL_read(void* context, void* data, int length) {
    MockSsl* ssl = (MockSsl*)context; int result = (int)sizeof(reply);
    if (ssl->fail) result = -1;
    else { if (length < result) result = length; if (result > 0) memcpy(data, reply, (size_t)result); }
    errno = EINVAL; SetLastError(456); return result;
}
API int __cdecl SSL_write_ex(void* context, const void* data, size_t length, size_t* actual) {
    int result = SSL_write(context, data, (int)length);
    if (result > 0) *actual = (size_t)result;
    return result > 0;
}
API int __cdecl SSL_read_ex(void* context, void* data, size_t length, size_t* actual) {
    int result = SSL_read(context, data, (int)length);
    if (result > 0) *actual = (size_t)result;
    return result > 0;
}
API int __cdecl SSL_clear(void* context) {
    MockSsl* ssl = (MockSsl*)context; ssl->fail = 0; ssl->limit = 0;
    errno = EINVAL; SetLastError(456); return 1;
}
API void __cdecl SSL_free(void* context) { free(context); errno = EINVAL; SetLastError(456); }
