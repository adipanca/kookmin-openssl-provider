// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * KM OpenSSL 3 provider
 *
 * Code strongly inspired by OpenSSL rsa kem.
 *
 * ToDo: Adding hybrid alg support; More testing with more key types.
 */

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <string.h>

#include "provider.h"

#ifdef NDEBUG
#define KM_KEM_PRINTF(a)
#define KM_KEM_PRINTF2(a, b)
#define KM_KEM_PRINTF3(a, b, c)
#else
#define KM_KEM_PRINTF(a)                                                      \
    if (getenv("KMKEM"))                                                      \
    printf(a)
#define KM_KEM_PRINTF2(a, b)                                                  \
    if (getenv("KMKEM"))                                                      \
    printf(a, b)
#define KM_KEM_PRINTF3(a, b, c)                                               \
    if (getenv("KMKEM"))                                                      \
    printf(a, b, c)
#endif // NDEBUG

static OSSL_FUNC_kem_newctx_fn km_kem_newctx;
static OSSL_FUNC_kem_encapsulate_init_fn km_kem_encaps_init;
static OSSL_FUNC_kem_encapsulate_fn km_qs_kem_encaps;
static OSSL_FUNC_kem_decapsulate_fn km_qs_kem_decaps;
static OSSL_FUNC_kem_freectx_fn km_kem_freectx;

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 */
typedef struct {
    OSSL_LIB_CTX *libctx;
    KMX_KEY *kem;
} PROV_KMKEM_CTX;

/// Common KEM functions

static void *km_kem_newctx(void *provctx) {
    PROV_KMKEM_CTX *pkemctx = OPENSSL_zalloc(sizeof(PROV_KMKEM_CTX));

    KM_KEM_PRINTF("KM KEM provider called: newctx\n");
    if (pkemctx == NULL)
        return NULL;
    pkemctx->libctx = PROV_KM_LIBCTX_OF(provctx);
    // kem will only be set in init

    return pkemctx;
}

static void km_kem_freectx(void *vpkemctx) {
    PROV_KMKEM_CTX *pkemctx = (PROV_KMKEM_CTX *)vpkemctx;

    KM_KEM_PRINTF("KM KEM provider called: freectx\n");
    kmx_key_free(pkemctx->kem);
    OPENSSL_free(pkemctx);
}

static int km_kem_decapsencaps_init(void *vpkemctx, void *vkem,
                                     int operation) {
    PROV_KMKEM_CTX *pkemctx = (PROV_KMKEM_CTX *)vpkemctx;

    KM_KEM_PRINTF3("KM KEM provider called: _init : New: %p; old: %p \n",
                    vkem, pkemctx->kem);
    if (pkemctx == NULL || vkem == NULL || !kmx_key_up_ref(vkem))
        return 0;
    kmx_key_free(pkemctx->kem);
    pkemctx->kem = vkem;

    return 1;
}

static int km_kem_encaps_init(void *vpkemctx, void *vkem,
                               const OSSL_PARAM params[]) {
    KM_KEM_PRINTF("KM KEM provider called: encaps_init\n");
    return km_kem_decapsencaps_init(vpkemctx, vkem, EVP_PKEY_OP_ENCAPSULATE);
}

static int km_kem_decaps_init(void *vpkemctx, void *vkem,
                               const OSSL_PARAM params[]) {
    KM_KEM_PRINTF("KM KEM provider called: decaps_init\n");
    return km_kem_decapsencaps_init(vpkemctx, vkem, EVP_PKEY_OP_DECAPSULATE);
}

/// Quantum-Safe KEM functions (KM)

static int km_qs_kem_encaps_keyslot(void *vpkemctx, unsigned char *out,
                                     size_t *outlen, unsigned char *secret,
                                     size_t *secretlen, int keyslot) {
    const PROV_KMKEM_CTX *pkemctx = (PROV_KMKEM_CTX *)vpkemctx;
    const OQS_KEM *kem_ctx = NULL;

    KM_KEM_PRINTF("KM KEM provider called: encaps\n");
    if (pkemctx->kem == NULL) {
        KM_KEM_PRINTF("KM Warning: KM_KEM not initialized\n");
        return -1;
    }

    kem_ctx = pkemctx->kem->kmx_provider_ctx.kmx_qs_ctx.kem;
    if (pkemctx->kem->comp_pubkey == NULL ||
        pkemctx->kem->comp_pubkey[keyslot] == NULL) {
        KM_KEM_PRINTF("KM Warning: public key is NULL\n");
        return -1;
    }
    if (outlen == NULL) {
        KM_KEM_PRINTF("KM Warning: outlen is NULL\n");
        return -1;
    }
    if (secretlen == NULL) {
        KM_KEM_PRINTF("KM Warning: secretlen is NULL\n");
        return -1;
    }
    if (out == NULL || secret == NULL) {
        *outlen = kem_ctx->length_ciphertext;
        *secretlen = kem_ctx->length_shared_secret;
        KM_KEM_PRINTF3("KEM returning lengths %ld and %ld\n",
                        kem_ctx->length_ciphertext,
                        kem_ctx->length_shared_secret);
        return 1;
    }

    if (*outlen < kem_ctx->length_ciphertext) {
        KM_KEM_PRINTF("KM Warning: out buffer too small\n");
        return -1;
    }
    if (*secretlen < kem_ctx->length_shared_secret) {
        KM_KEM_PRINTF("KM Warning: secret buffer too small\n");
        return -1;
    }
    *outlen = kem_ctx->length_ciphertext;
    *secretlen = kem_ctx->length_shared_secret;

    return OQS_SUCCESS == OQS_KEM_encaps(kem_ctx, out, secret,
                                         pkemctx->kem->comp_pubkey[keyslot]);
}

static int km_qs_kem_decaps_keyslot(void *vpkemctx, unsigned char *out,
                                     size_t *outlen, const unsigned char *in,
                                     size_t inlen, int keyslot) {
    const PROV_KMKEM_CTX *pkemctx = (PROV_KMKEM_CTX *)vpkemctx;
    const OQS_KEM *kem_ctx = NULL;

    KM_KEM_PRINTF("KM KEM provider called: decaps\n");
    if (pkemctx->kem == NULL) {
        KM_KEM_PRINTF("KM Warning: KM_KEM not initialized\n");
        return -1;
    }
    kem_ctx = pkemctx->kem->kmx_provider_ctx.kmx_qs_ctx.kem;
    if (pkemctx->kem->comp_privkey == NULL ||
        pkemctx->kem->comp_privkey[keyslot] == NULL) {
        KM_KEM_PRINTF("KM Warning: private key is NULL\n");
        return -1;
    }
    if (out == NULL) {
        if (outlen != NULL) {
            *outlen = kem_ctx->length_shared_secret;
        }
        KM_KEM_PRINTF2("KEM returning length %ld\n",
                        kem_ctx->length_shared_secret);
        return 1;
    }
    if (inlen != kem_ctx->length_ciphertext) {
        KM_KEM_PRINTF("KM Warning: wrong input length\n");
        return 0;
    }
    if (in == NULL) {
        KM_KEM_PRINTF("KM Warning: in is NULL\n");
        return -1;
    }
    if (outlen == NULL) {
        KM_KEM_PRINTF("KM Warning: outlen is NULL\n");
        return -1;
    }
    if (*outlen < kem_ctx->length_shared_secret) {
        KM_KEM_PRINTF("KM Warning: out buffer too small\n");
        return -1;
    }
    *outlen = kem_ctx->length_shared_secret;

    return OQS_SUCCESS == OQS_KEM_decaps(kem_ctx, out, in,
                                         pkemctx->kem->comp_privkey[keyslot]);
}

static int km_qs_kem_encaps(void *vpkemctx, unsigned char *out, size_t *outlen,
                             unsigned char *secret, size_t *secretlen) {
    return km_qs_kem_encaps_keyslot(vpkemctx, out, outlen, secret, secretlen,
                                     0);
}

static int km_qs_kem_decaps(void *vpkemctx, unsigned char *out, size_t *outlen,
                             const unsigned char *in, size_t inlen) {
    return km_qs_kem_decaps_keyslot(vpkemctx, out, outlen, in, inlen, 0);
}


static OSSL_FUNC_kem_encapsulate_fn km_hyb_kem_encaps;
static OSSL_FUNC_kem_decapsulate_fn km_hyb_kem_decaps;

/// EVP KEM functions

static int km_evp_kem_encaps_keyslot(void *vpkemctx, unsigned char *ct,
                                      size_t *ctlen, unsigned char *secret,
                                      size_t *secretlen, int keyslot) {
    int ret = OQS_SUCCESS, ret2 = 0;

    const PROV_KMKEM_CTX *pkemctx = (PROV_KMKEM_CTX *)vpkemctx;
    const KMX_EVP_CTX *evp_ctx = pkemctx->kem->kmx_provider_ctx.kmx_evp_ctx;

    size_t pubkey_kexlen = 0;
    size_t kexDeriveLen = 0, pkeylen = 0;
    unsigned char *pubkey_kex = pkemctx->kem->comp_pubkey[keyslot];

    // Free at err:
    EVP_PKEY_CTX *ctx = NULL, *kgctx = NULL;

    EVP_PKEY *pkey = NULL, *peerpk = NULL;
    unsigned char *ctkex_encoded = NULL;

    pubkey_kexlen = evp_ctx->evp_info->length_public_key;
    kexDeriveLen = evp_ctx->evp_info->kex_length_secret;

    *ctlen = pubkey_kexlen;
    *secretlen = kexDeriveLen;

    if (ct == NULL || secret == NULL) {
        KM_KEM_PRINTF3("EVP KEM returning lengths %ld and %ld\n", *ctlen,
                        *secretlen);
        return 1;
    }

    peerpk = EVP_PKEY_new();
    ON_ERR_SET_GOTO(!peerpk, ret, -1, err);

    ret2 = EVP_PKEY_copy_parameters(peerpk, evp_ctx->keyParam);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -1, err);

    ret2 = EVP_PKEY_set1_encoded_public_key(peerpk, pubkey_kex, pubkey_kexlen);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -1, err);

    kgctx = EVP_PKEY_CTX_new(evp_ctx->keyParam, NULL);
    ON_ERR_SET_GOTO(!kgctx, ret, -1, err);

    ret2 = EVP_PKEY_keygen_init(kgctx);
    ON_ERR_SET_GOTO(ret2 != 1, ret, -1, err);

    ret2 = EVP_PKEY_keygen(kgctx, &pkey);
    ON_ERR_SET_GOTO(ret2 != 1, ret, -1, err);

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    ON_ERR_SET_GOTO(!ctx, ret, -1, err);

    ret = EVP_PKEY_derive_init(ctx);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

    ret = EVP_PKEY_derive_set_peer(ctx, peerpk);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

    ret = EVP_PKEY_derive(ctx, secret, &kexDeriveLen);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

    pkeylen = EVP_PKEY_get1_encoded_public_key(pkey, &ctkex_encoded);
    ON_ERR_SET_GOTO(pkeylen <= 0 || !ctkex_encoded || pkeylen != pubkey_kexlen,
                    ret, -1, err);

    memcpy(ct, ctkex_encoded, pkeylen);

err:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(kgctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peerpk);
    OPENSSL_free(ctkex_encoded);
    return ret;
}

static int km_evp_kem_decaps_keyslot(void *vpkemctx, unsigned char *secret,
                                      size_t *secretlen,
                                      const unsigned char *ct, size_t ctlen,
                                      int keyslot) {
    KM_KEM_PRINTF("KM KEM provider called: km_hyb_kem_decaps\n");

    int ret = OQS_SUCCESS, ret2 = 0;
    const PROV_KMKEM_CTX *pkemctx = (PROV_KMKEM_CTX *)vpkemctx;
    const KMX_EVP_CTX *evp_ctx = pkemctx->kem->kmx_provider_ctx.kmx_evp_ctx;

    size_t pubkey_kexlen = evp_ctx->evp_info->length_public_key;
    size_t kexDeriveLen = evp_ctx->evp_info->kex_length_secret;
    unsigned char *privkey_kex = pkemctx->kem->comp_privkey[keyslot];
    size_t privkey_kexlen = evp_ctx->evp_info->length_private_key;

    // Free at err:
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL, *peerpkey = NULL;

    *secretlen = kexDeriveLen;
    if (secret == NULL)
        return 1;

    if (evp_ctx->evp_info->raw_key_support) {
        pkey = EVP_PKEY_new_raw_private_key(evp_ctx->evp_info->keytype, NULL,
                                            privkey_kex, privkey_kexlen);
        ON_ERR_SET_GOTO(!pkey, ret, -10, err);
    } else {
        pkey = d2i_AutoPrivateKey(&pkey, (const unsigned char **)&privkey_kex,
                                  privkey_kexlen);
        ON_ERR_SET_GOTO(!pkey, ret, -2, err);
    }

    peerpkey = EVP_PKEY_new();
    ON_ERR_SET_GOTO(!peerpkey, ret, -3, err);

    ret2 = EVP_PKEY_copy_parameters(peerpkey, evp_ctx->keyParam);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -4, err);

    ret2 = EVP_PKEY_set1_encoded_public_key(peerpkey, ct, pubkey_kexlen);
    ON_ERR_SET_GOTO(ret2 <= 0 || !peerpkey, ret, -5, err);

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    ON_ERR_SET_GOTO(!ctx, ret, -6, err);

    ret = EVP_PKEY_derive_init(ctx);
    ON_ERR_SET_GOTO(ret <= 0, ret, -7, err);
    ret = EVP_PKEY_derive_set_peer(ctx, peerpkey);
    ON_ERR_SET_GOTO(ret <= 0, ret, -8, err);

    ret = EVP_PKEY_derive(ctx, secret, &kexDeriveLen);
    ON_ERR_SET_GOTO(ret <= 0, ret, -9, err);

err:
    EVP_PKEY_free(peerpkey);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/// Hybrid KEM functions

static int km_hyb_kem_encaps(void *vpkemctx, unsigned char *ct, size_t *ctlen,
                              unsigned char *secret, size_t *secretlen) {
    int ret = OQS_SUCCESS;
    const PROV_KMKEM_CTX *pkemctx = (PROV_KMKEM_CTX *)vpkemctx;
    const KMX_KEY *kmx_key = pkemctx->kem;
    size_t secretLenClassical = 0, secretLenPQ = 0;
    size_t ctLenClassical = 0, ctLenPQ = 0;
    unsigned char *ctClassical, *ctPQ, *secretClassical, *secretPQ;

    ret = km_evp_kem_encaps_keyslot(vpkemctx, NULL, &ctLenClassical, NULL,
                                     &secretLenClassical,
                                     kmx_key->reverse_share ? 1 : 0);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);
    ret =
        km_qs_kem_encaps_keyslot(vpkemctx, NULL, &ctLenPQ, NULL, &secretLenPQ,
                                  kmx_key->reverse_share ? 0 : 1);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

    *ctlen = ctLenClassical + ctLenPQ;
    *secretlen = secretLenClassical + secretLenPQ;

    if (ct == NULL || secret == NULL) {
        KM_KEM_PRINTF3("HYB KEM returning lengths %ld and %ld\n", *ctlen,
                        *secretlen);
        return 1;
    }

    /* Rule: if the classical algorthm is not FIPS approved
       but the PQ algorithm is: PQ share comes first
       otherwise: classical share comes first
     */
    if (kmx_key->reverse_share) {
        ctPQ = ct;
        ctClassical = ct + ctLenPQ;
        secretPQ = secret;
        secretClassical = secret + secretLenPQ;
    } else {
        ctClassical = ct;
        ctPQ = ct + ctLenClassical;
        secretClassical = secret;
        secretPQ = secret + secretLenClassical;
    }

    ret = km_evp_kem_encaps_keyslot(vpkemctx, ctClassical, &ctLenClassical,
                                     secretClassical, &secretLenClassical,
                                     kmx_key->reverse_share ? 1 : 0);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

    ret = km_qs_kem_encaps_keyslot(vpkemctx, ctPQ, &ctLenPQ, secretPQ,
                                    &secretLenPQ,
                                    kmx_key->reverse_share ? 0 : 1);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

err:
    return ret;
}

static int km_hyb_kem_decaps(void *vpkemctx, unsigned char *secret,
                              size_t *secretlen, const unsigned char *ct,
                              size_t ctlen) {
    int ret = OQS_SUCCESS;
    const PROV_KMKEM_CTX *pkemctx = (PROV_KMKEM_CTX *)vpkemctx;
    const KMX_KEY *kmx_key = pkemctx->kem;
    const KMX_EVP_CTX *evp_ctx = pkemctx->kem->kmx_provider_ctx.kmx_evp_ctx;
    const OQS_KEM *qs_ctx = pkemctx->kem->kmx_provider_ctx.kmx_qs_ctx.kem;

    size_t secretLenClassical = 0, secretLenPQ = 0;
    size_t ctLenClassical = 0, ctLenPQ = 0;
    const unsigned char *ctClassical, *ctPQ;
    unsigned char *secretClassical, *secretPQ;

    ret = km_evp_kem_decaps_keyslot(vpkemctx, NULL, &secretLenClassical, NULL,
                                     0, kmx_key->reverse_share ? 1 : 0);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);
    ret = km_qs_kem_decaps_keyslot(vpkemctx, NULL, &secretLenPQ, NULL, 0,
                                    kmx_key->reverse_share ? 0 : 1);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

    *secretlen = secretLenClassical + secretLenPQ;

    if (secret == NULL)
        return 1;

    ctLenClassical = evp_ctx->evp_info->length_public_key;
    ctLenPQ = qs_ctx->length_ciphertext;

    ON_ERR_SET_GOTO(ctLenClassical + ctLenPQ != ctlen, ret, OQS_ERROR, err);

    /* Rule: if the classical algorthm is not FIPS approved
       but the PQ algorithm is: PQ share comes first
       otherwise: classical share comes first
     */
    if (kmx_key->reverse_share) {
        ctPQ = ct;
        ctClassical = ct + ctLenPQ;
        secretPQ = secret;
        secretClassical = secret + secretLenPQ;
    } else {
        ctClassical = ct;
        ctPQ = ct + ctLenClassical;
        secretClassical = secret;
        secretPQ = secret + secretLenClassical;
    }

    ret = km_evp_kem_decaps_keyslot(
        vpkemctx, secretClassical, &secretLenClassical, ctClassical,
        ctLenClassical, kmx_key->reverse_share ? 1 : 0);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);
    ret = km_qs_kem_decaps_keyslot(vpkemctx, secretPQ, &secretLenPQ, ctPQ,
                                    ctLenPQ, kmx_key->reverse_share ? 0 : 1);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

err:
    return ret;
}

#define MAKE_KEM_FUNCTIONS(alg)                                                \
    const OSSL_DISPATCH km_##alg##_kem_functions[] = {                        \
        {OSSL_FUNC_KEM_NEWCTX, (void (*)(void))km_kem_newctx},                \
        {OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))km_kem_encaps_init}, \
        {OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))km_qs_kem_encaps},        \
        {OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))km_kem_decaps_init}, \
        {OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))km_qs_kem_decaps},        \
        {OSSL_FUNC_KEM_FREECTX, (void (*)(void))km_kem_freectx},              \
        {0, NULL}};

#define MAKE_HYB_KEM_FUNCTIONS(alg)                                            \
    const OSSL_DISPATCH km_##alg##_kem_functions[] = {                        \
        {OSSL_FUNC_KEM_NEWCTX, (void (*)(void))km_kem_newctx},                \
        {OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))km_kem_encaps_init}, \
        {OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))km_hyb_kem_encaps},       \
        {OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))km_kem_decaps_init}, \
        {OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))km_hyb_kem_decaps},       \
        {OSSL_FUNC_KEM_FREECTX, (void (*)(void))km_kem_freectx},              \
        {0, NULL}};

// keep this just in case we need to become ALG-specific at some point in time
MAKE_KEM_FUNCTIONS(generic)
MAKE_HYB_KEM_FUNCTIONS(hybrid)
