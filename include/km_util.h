#pragma once
#include <openssl/params.h>
#include <stddef.h>


int km_param_get_octet_string(const OSSL_PARAM params[], const char *key,
unsigned char **out, size_t *outlen);
int km_param_build_pubpriv(OSSL_PARAM_BLD *bld,
const unsigned char *pub, size_t publen,
const unsigned char *priv, size_t privlen,
OSSL_PARAM **out);