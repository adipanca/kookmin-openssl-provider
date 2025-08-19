#pragma once
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <oqs/oqs.h>


// Nama algoritma default kita (bisa Anda ganti):
#define KM_SIG_NAME "mldsa65"
#define KM_SIG_OQS_NAME "ML-DSA-65" // nama di liboqs


// Context provider
typedef struct {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx; // optional
} KM_PROVCTX;


// Struktur key untuk SIGNATURE (ML-DSA)
typedef struct {
    KM_PROVCTX *provctx;
    char alg_name[32];
    OQS_SIG *sig; // descriptor liboqs
    unsigned char *pub; size_t publen;
    unsigned char *priv; size_t privlen;
} KM_SIG_KEY;


KM_PROVCTX *km_provctx_new(const OSSL_CORE_HANDLE *handle);
void km_provctx_free(KM_PROVCTX *p);