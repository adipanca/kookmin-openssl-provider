#include "km_util.h"
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/crypto.h>

int km_param_get_octet_string(const OSSL_PARAM params[], const char *key,
                              unsigned char **out, size_t *outlen) {
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, key);
    if (!p) return 0;

    /* Coba pointer langsung (tanpa copy) dulu */
    const void *ptr = NULL;
    size_t len = 0;
    if (OSSL_PARAM_get_octet_string_ptr(p, &ptr, &len)) {
        *out = OPENSSL_malloc(len);
        if (!*out) return 0;
        memcpy(*out, ptr, len);
        *outlen = len;
        return 1;
    }

    /* Fallback: minta OpenSSL alokasikan buffer untuk kita */
    void *buf = NULL;
    size_t used = 0;
    /* max_len = 0 artinya OpenSSL yang alokasikan via OPENSSL_malloc */
    if (!OSSL_PARAM_get_octet_string(p, &buf, 0, &used))
        return 0;

    *out = (unsigned char *)buf;   /* sudah dialokasikan oleh OpenSSL */
    *outlen = used;
    return 1;
}

int km_param_build_pubpriv(OSSL_PARAM_BLD *bld,
                           const unsigned char *pub, size_t publen,
                           const unsigned char *priv, size_t privlen,
                           OSSL_PARAM **out) {
    if (pub && publen) {
        if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub, publen))
            return 0;
    }
    if (priv && privlen) {
        if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv, privlen))
            return 0;
    }
    *out = OSSL_PARAM_BLD_to_param(bld);
    return *out != NULL;
}
