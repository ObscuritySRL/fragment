#pragma once

/* Shared URL mutation logic. A rewritten CURLU contains the origin in its
 * serialized URL. Unwrap it before applying ANY caller mutation, then wrap
 * the assembled result again. This needs no handle-address cache (and thus
 * survives curl_url_dup/cleanup and address reuse). Call with the unhooked
 * setter to avoid recursion. libcurl requires exclusive access to a CURLU. */
static CURLUcode FragmentUrlSet(void* handle, CURLUPart what, const char* part,
                               unsigned int flags, CurlUrlSetFn set,
                               CurlUrlGetFn get, CurlFreeFn release) {
    // Older/static builds may expose only the setter. Retain whole-URL
    // coverage; component mutation requires the matching getter/free exports.
    if (!get || !release) {
        if (what != CURLUPART_URL || !part || !*part ||
            strncmp(part, gCfg.proxyPrefix, gCfg.proxyPrefixLen) == 0)
            return set(handle, what, part, flags);
        char* proxied = BuildProxiedUrl(part);
        if (!proxied) return 7;
        CURLUcode rc = set(handle, what, proxied, flags);
        free(proxied);
        return rc;
    }
    char* before = NULL;
    int wrapped = 0;
    CURLUcode readResult = get(handle, CURLUPART_URL, &before, 0);
    if (readResult == 7) return readResult; // do not mutate after an allocation failure
    if (before) {
        wrapped = strncmp(before, gCfg.proxyPrefix, gCfg.proxyPrefixLen) == 0;
        if (wrapped) {
            CURLUcode rc = set(handle, CURLUPART_URL, before + gCfg.proxyPrefixLen, 0);
            if (rc) { release(before); return rc; }
        }
    }
    // Already rewritten full URLs are accepted without double-prefixing.
    if (what == CURLUPART_URL && part &&
        strncmp(part, gCfg.proxyPrefix, gCfg.proxyPrefixLen) == 0)
        part += gCfg.proxyPrefixLen;

    CURLUcode rc = set(handle, what, part, flags);
    if (rc) {
        if (wrapped && set(handle, CURLUPART_URL, before, 0))
            set(handle, CURLUPART_URL, NULL, 0);
        if (before) release(before);
        return rc;
    }
    if (before) release(before);

    char* assembled = NULL;
    // A partial URL (or an explicit reset) cannot be serialized yet. Keep
    // it in origin form until a later mutation completes it.
    readResult = get(handle, CURLUPART_URL, &assembled, 0);
    if (readResult == 7) {
        set(handle, CURLUPART_URL, NULL, 0);
        return readResult;
    }
    if (readResult || !assembled) return 0;
    char* proxied = BuildProxiedUrl(assembled);
    if (!proxied && strncmp(assembled, gCfg.proxyPrefix, gCfg.proxyPrefixLen)) {
        release(assembled);
        set(handle, CURLUPART_URL, NULL, 0); // never leave a usable direct URL on OOM
        return 7; // CURLUE_OUT_OF_MEMORY
    }
    if (proxied) {
        rc = set(handle, CURLUPART_URL, proxied, 0);
        free(proxied);
        if (rc) set(handle, CURLUPART_URL, NULL, 0);
    }
    release(assembled);
    return rc;
}
