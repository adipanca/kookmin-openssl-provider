#pragma once
#include <openssl/bio.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <oqs/oqs.h>
#include <openssl/core_object.h>     // OSSL_OBJECT_PARAM_*



// Nama algoritma default kita (bisa Anda ganti):
#define KM_SIG_NAME "mldsa65"
#define KM_SIG_OQS_NAME "ML-DSA-65" // nama di liboqs
typedef BIO *(*OSSL_FUNC_BIO_new_from_core_bio_fn)(const OSSL_CORE_HANDLE *, OSSL_CORE_BIO *);
typedef int (*OSSL_core_bio_write_ex_fn)(OSSL_CORE_BIO *bio,
                                         const void *data, size_t data_len,
                                         size_t *written);
typedef int (*OSSL_core_bio_read_ex_fn)(OSSL_CORE_BIO *bio,
                                        void *data, size_t data_len,
                                        size_t *readbytes);


// Context provider
typedef struct {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx; // optional
    /* Tambahan: bridge Core BIO */
    OSSL_FUNC_BIO_new_from_core_bio_fn bio_new_from_core_bio;
    OSSL_core_bio_write_ex_fn core_bio_write_ex;
    OSSL_core_bio_read_ex_fn  core_bio_read_ex;
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

extern const OSSL_ALGORITHM km_algs_encoder[];
extern const OSSL_ALGORITHM km_algs_decoder[];