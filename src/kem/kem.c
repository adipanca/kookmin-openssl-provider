// SPDX-License-Identifier: Apache-2.0 AND MIT
// KM OpenSSL 3 provider

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <string.h>

#include "provider.h"

/* =========================================================================
 * Logging (aktif bila KMKEM ter-set)
 * ========================================================================= */
#ifdef NDEBUG
#  define KMKEM_LOG0(msg)                do {} while (0)
#  define KMKEM_LOG1(fmt,a)              do {} while (0)
#  define KMKEM_LOG2(fmt,a,b)            do {} while (0)
#else
static int kmkem_log_on(void) { return getenv("KMKEM") != NULL; }
#  define KMKEM_LOG0(msg)                do { if (kmkem_log_on()) printf("%s", (msg)); } while(0)
#  define KMKEM_LOG1(fmt,a)              do { if (kmkem_log_on()) printf((fmt),(a)); } while(0)
#  define KMKEM_LOG2(fmt,a,b)            do { if (kmkem_log_on()) printf((fmt),(a),(b)); } while(0)
#endif

/* =========================================================================
 * Deklarasi OSSL KEM hooks
 * ========================================================================= */
static OSSL_FUNC_kem_newctx_fn         km_kem_newctx;
static OSSL_FUNC_kem_encapsulate_init_fn km_kem_encaps_init;
static OSSL_FUNC_kem_decapsulate_init_fn km_kem_decaps_init;
static OSSL_FUNC_kem_encapsulate_fn    km_qs_kem_encaps;
static OSSL_FUNC_kem_decapsulate_fn    km_qs_kem_decaps;
static OSSL_FUNC_kem_freectx_fn        km_kem_freectx;

/* Versi hybrid (classical+PQ) */
static OSSL_FUNC_kem_encapsulate_fn    km_hyb_kem_encaps;
static OSSL_FUNC_kem_decapsulate_fn    km_hyb_kem_decaps;

/* =========================================================================
 * Context
 * ========================================================================= */
typedef struct {
    OSSL_LIB_CTX *libctx;
    KMX_KEY      *kem;       /* diisi saat *_init */
} PROV_KMKEM_CTX;

/* =========================================================================
 * Util
 * ========================================================================= */
static int km_kem_bind_key(PROV_KMKEM_CTX *c, KMX_KEY *k)
{
    KMKEM_LOG2("kem_init: new=%p old=%p\n", (void*)k, (void*)c->kem);
    if (!c || !k) return 0;
    if (!kmx_key_up_ref(k)) return 0;
    kmx_key_free(c->kem);
    c->kem = k;
    return 1;
}

/* =========================================================================
 * Common KEM funcs
 * ========================================================================= */
static void *km_kem_newctx(void *provctx)
{
    PROV_KMKEM_CTX *c = OPENSSL_zalloc(sizeof(*c));
    KMKEM_LOG0("kem_newctx\n");
    if (!c) return NULL;
    c->libctx = PROV_KM_LIBCTX_OF(provctx);
    return c;
}

static void km_kem_freectx(void *vctx)
{
    PROV_KMKEM_CTX *c = (PROV_KMKEM_CTX *)vctx;
    KMKEM_LOG0("kem_freectx\n");
    if (!c) return;
    kmx_key_free(c->kem);
    OPENSSL_free(c);
}

static int km_kem_decapsencaps_init(void *vctx, void *vkey, int op)
{
    (void)op; /* reserved, menjaga ABI/semantik */
    PROV_KMKEM_CTX *c = (PROV_KMKEM_CTX *)vctx;
    KMKEM_LOG0("kem_*caps_init\n");
    return km_kem_bind_key(c, (KMX_KEY *)vkey);
}

static int km_kem_encaps_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    (void)params;
    KMKEM_LOG0("kem_encaps_init\n");
    return km_kem_decapsencaps_init(vctx, vkey, EVP_PKEY_OP_ENCAPSULATE);
}

static int km_kem_decaps_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    (void)params;
    KMKEM_LOG0("kem_decaps_init\n");
    return km_kem_decapsencaps_init(vctx, vkey, EVP_PKEY_OP_DECAPSULATE);
}

/* =========================================================================
 * QS (liboqs) KEM – satu keyslot
 * ========================================================================= */
static int km_qs_kem_encaps_keyslot(void *vctx,
                                    unsigned char *out, size_t *outlen,
                                    unsigned char *secret, size_t *secretlen,
                                    int keyslot)
{
    const PROV_KMKEM_CTX *c = (PROV_KMKEM_CTX *)vctx;
    KMKEM_LOG0("qs_encaps\n");
    if (!c || !c->kem) { KMKEM_LOG0("warn: kem ctx not ready\n"); return -1; }

    const OQS_KEM *qs = c->kem->kmx_provider_ctx.kmx_qs_ctx.kem;
    if (!c->kem->comp_pubkey || !c->kem->comp_pubkey[keyslot]) {
        KMKEM_LOG0("warn: pubkey NULL\n"); return -1;
    }
    if (!outlen || !secretlen) { KMKEM_LOG0("warn: outlen/secretlen NULL\n"); return -1; }

    if (!out || !secret) {
        *outlen    = qs->length_ciphertext;
        *secretlen = qs->length_shared_secret;
        KMKEM_LOG2("qs sizes: ct=%lu ss=%lu\n", (unsigned long)*outlen, (unsigned long)*secretlen);
        return 1;
    }
    if (*outlen < qs->length_ciphertext)    { KMKEM_LOG0("warn: ct buf small\n"); return -1; }
    if (*secretlen < qs->length_shared_secret){ KMKEM_LOG0("warn: ss buf small\n"); return -1; }

    *outlen    = qs->length_ciphertext;
    *secretlen = qs->length_shared_secret;
    return (OQS_SUCCESS == OQS_KEM_encaps(qs, out, secret, c->kem->comp_pubkey[keyslot]));
}

static int km_qs_kem_decaps_keyslot(void *vctx,
                                    unsigned char *out, size_t *outlen,
                                    const unsigned char *in, size_t inlen,
                                    int keyslot)
{
    const PROV_KMKEM_CTX *c = (PROV_KMKEM_CTX *)vctx;
    KMKEM_LOG0("qs_decaps\n");
    if (!c || !c->kem) { KMKEM_LOG0("warn: kem ctx not ready\n"); return -1; }

    const OQS_KEM *qs = c->kem->kmx_provider_ctx.kmx_qs_ctx.kem;
    if (!c->kem->comp_privkey || !c->kem->comp_privkey[keyslot]) {
        KMKEM_LOG0("warn: privkey NULL\n"); return -1;
    }

    if (!out) {
        if (outlen) *outlen = qs->length_shared_secret;
        KMKEM_LOG1("qs ss size=%lu\n", (unsigned long)qs->length_shared_secret);
        return 1;
    }
    if (!in) { KMKEM_LOG0("warn: ct NULL\n"); return -1; }
    if (!outlen) { KMKEM_LOG0("warn: outlen NULL\n"); return -1; }
    if (inlen != qs->length_ciphertext) { KMKEM_LOG0("warn: ct size mismatch\n"); return 0; }
    if (*outlen < qs->length_shared_secret) { KMKEM_LOG0("warn: ss buf small\n"); return -1; }

    *outlen = qs->length_shared_secret;
    return (OQS_SUCCESS == OQS_KEM_decaps(qs, out, in, c->kem->comp_privkey[keyslot]));
}

/* entry (QS only) */
static int km_qs_kem_encaps(void *vctx,
                            unsigned char *out, size_t *outlen,
                            unsigned char *secret, size_t *secretlen)
{
    return km_qs_kem_encaps_keyslot(vctx, out, outlen, secret, secretlen, 0);
}

static int km_qs_kem_decaps(void *vctx,
                            unsigned char *out, size_t *outlen,
                            const unsigned char *in, size_t inlen)
{
    return km_qs_kem_decaps_keyslot(vctx, out, outlen, in, inlen, 0);
}

/* =========================================================================
 * EVP (classical) KEM – satu keyslot
 * ========================================================================= */
static int km_evp_kem_encaps_keyslot(void *vctx,
                                     unsigned char *ct, size_t *ctlen,
                                     unsigned char *secret, size_t *secretlen,
                                     int keyslot)
{
    int ret = OQS_SUCCESS, rc = 0;

    const PROV_KMKEM_CTX *c  = (PROV_KMKEM_CTX *)vctx;
    const KMX_EVP_CTX    *ec = c->kem->kmx_provider_ctx.kmx_evp_ctx;

    size_t pk_len = ec->evp_info->length_public_key;
    size_t ss_len = ec->evp_info->kex_length_secret;
    unsigned char *peer_pub = c->kem->comp_pubkey[keyslot];

    EVP_PKEY_CTX *kg = NULL, *dctx = NULL;
    EVP_PKEY *my = NULL, *peer = NULL;
    unsigned char *ct_enc = NULL;
    size_t got = 0;

    *ctlen = pk_len;
    *secretlen = ss_len;

    if (!ct || !secret) {
        KMKEM_LOG2("evp sizes: ct=%lu ss=%lu\n",(unsigned long)*ctlen,(unsigned long)*secretlen);
        return 1;
    }

    peer = EVP_PKEY_new();
    ON_ERR_SET_GOTO(!peer, ret, -1, done);

    rc = EVP_PKEY_copy_parameters(peer, ec->keyParam);
    ON_ERR_SET_GOTO(rc <= 0, ret, -1, done);

    rc = EVP_PKEY_set1_encoded_public_key(peer, peer_pub, pk_len);
    ON_ERR_SET_GOTO(rc <= 0, ret, -1, done);

    kg = EVP_PKEY_CTX_new(ec->keyParam, NULL);
    ON_ERR_SET_GOTO(!kg, ret, -1, done);

    rc = EVP_PKEY_keygen_init(kg);
    ON_ERR_SET_GOTO(rc != 1, ret, -1, done);

    rc = EVP_PKEY_keygen(kg, &my);
    ON_ERR_SET_GOTO(rc != 1, ret, -1, done);

    dctx = EVP_PKEY_CTX_new(my, NULL);
    ON_ERR_SET_GOTO(!dctx, ret, -1, done);

    ret = EVP_PKEY_derive_init(dctx);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, done);

    ret = EVP_PKEY_derive_set_peer(dctx, peer);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, done);

    ret = EVP_PKEY_derive(dctx, secret, &ss_len);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, done);

    got = EVP_PKEY_get1_encoded_public_key(my, &ct_enc);
    ON_ERR_SET_GOTO(got <= 0 || !ct_enc || got != pk_len, ret, -1, done);

    memcpy(ct, ct_enc, got);

done:
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_CTX_free(kg);
    EVP_PKEY_free(my);
    EVP_PKEY_free(peer);
    OPENSSL_free(ct_enc);
    return ret;
}

static int km_evp_kem_decaps_keyslot(void *vctx,
                                     unsigned char *secret, size_t *secretlen,
                                     const unsigned char *ct, size_t ctlen,
                                     int keyslot)
{
    KMKEM_LOG0("evp_decaps\n");

    int ret = OQS_SUCCESS, rc = 0;
    const PROV_KMKEM_CTX *c  = (PROV_KMKEM_CTX *)vctx;
    const KMX_EVP_CTX    *ec = c->kem->kmx_provider_ctx.kmx_evp_ctx;

    size_t pk_len = ec->evp_info->length_public_key;
    size_t ss_len = ec->evp_info->kex_length_secret;
    unsigned char *priv = c->kem->comp_privkey[keyslot];
    size_t priv_len = ec->evp_info->length_private_key;

    EVP_PKEY_CTX *dctx = NULL;
    EVP_PKEY *my = NULL, *peer = NULL;

    *secretlen = ss_len;
    if (!secret) return 1;

    if (ec->evp_info->raw_key_support) {
        my = EVP_PKEY_new_raw_private_key(ec->evp_info->keytype, NULL, priv, priv_len);
        ON_ERR_SET_GOTO(!my, ret, -10, out);
    } else {
        my = d2i_AutoPrivateKey(&my, (const unsigned char **)&priv, priv_len);
        ON_ERR_SET_GOTO(!my, ret, -2, out);
    }

    peer = EVP_PKEY_new();
    ON_ERR_SET_GOTO(!peer, ret, -3, out);

    rc = EVP_PKEY_copy_parameters(peer, ec->keyParam);
    ON_ERR_SET_GOTO(rc <= 0, ret, -4, out);

    rc = EVP_PKEY_set1_encoded_public_key(peer, ct, pk_len);
    ON_ERR_SET_GOTO(rc <= 0 || !peer, ret, -5, out);

    dctx = EVP_PKEY_CTX_new(my, NULL);
    ON_ERR_SET_GOTO(!dctx, ret, -6, out);

    ret = EVP_PKEY_derive_init(dctx);
    ON_ERR_SET_GOTO(ret <= 0, ret, -7, out);

    ret = EVP_PKEY_derive_set_peer(dctx, peer);
    ON_ERR_SET_GOTO(ret <= 0, ret, -8, out);

    ret = EVP_PKEY_derive(dctx, secret, &ss_len);
    ON_ERR_SET_GOTO(ret <= 0, ret, -9, out);

out:
    EVP_PKEY_free(peer);
    EVP_PKEY_free(my);
    EVP_PKEY_CTX_free(dctx);
    return ret;
}

/* =========================================================================
 * HYBRID KEM (classical + PQ)
 * ========================================================================= */
static int km_hyb_kem_encaps(void *vctx,
                             unsigned char *ct, size_t *ctlen,
                             unsigned char *secret, size_t *secretlen)
{
    int ret = OQS_SUCCESS;
    const PROV_KMKEM_CTX *c = (PROV_KMKEM_CTX *)vctx;
    const KMX_KEY *k = c->kem;

    size_t ct_c_len=0, ss_c_len=0;
    size_t ct_q_len=0, ss_q_len=0;

    /* stage 1: ukur */
    ret = km_evp_kem_encaps_keyslot(vctx, NULL, &ct_c_len, NULL, &ss_c_len, k->reverse_share ? 1 : 0);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, out);
    ret = km_qs_kem_encaps_keyslot (vctx, NULL, &ct_q_len, NULL, &ss_q_len, k->reverse_share ? 0 : 1);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, out);

    *ctlen    = ct_c_len + ct_q_len;
    *secretlen= ss_c_len + ss_q_len;

    if (!ct || !secret) {
        KMKEM_LOG2("hyb sizes: ct=%lu ss=%lu\n",(unsigned long)*ctlen,(unsigned long)*secretlen);
        return 1;
    }

    /* aturan urutan share (sama seperti versi Anda) */
    unsigned char *ctC, *ctQ, *ssC, *ssQ;
    if (k->reverse_share) {
        ctQ = ct;            ctC = ct + ct_q_len;
        ssQ = secret;        ssC = secret + ss_q_len;
    } else {
        ctC = ct;            ctQ = ct + ct_c_len;
        ssC = secret;        ssQ = secret + ss_c_len;
    }

    /* stage 2: isi */
    ret = km_evp_kem_encaps_keyslot(vctx, ctC, &ct_c_len, ssC, &ss_c_len, k->reverse_share ? 1 : 0);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, out);
    ret = km_qs_kem_encaps_keyslot (vctx, ctQ, &ct_q_len, ssQ, &ss_q_len, k->reverse_share ? 0 : 1);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, out);

out:
    return ret;
}

static int km_hyb_kem_decaps(void *vctx,
                             unsigned char *secret, size_t *secretlen,
                             const unsigned char *ct, size_t ctlen)
{
    int ret = OQS_SUCCESS;
    const PROV_KMKEM_CTX *c = (PROV_KMKEM_CTX *)vctx;
    const KMX_KEY *k = c->kem;
    const KMX_EVP_CTX *ec = k->kmx_provider_ctx.kmx_evp_ctx;
    const OQS_KEM *qs = k->kmx_provider_ctx.kmx_qs_ctx.kem;

    size_t ss_c_len=0, ss_q_len=0;
    size_t ct_c_len=ec->evp_info->length_public_key;
    size_t ct_q_len=qs->length_ciphertext;

    /* ukur secret */
    ret = km_evp_kem_decaps_keyslot(vctx, NULL, &ss_c_len, NULL, 0, k->reverse_share ? 1 : 0);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, out);
    ret = km_qs_kem_decaps_keyslot (vctx, NULL, &ss_q_len, NULL, 0, k->reverse_share ? 0 : 1);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, out);

    *secretlen = ss_c_len + ss_q_len;
    if (!secret) return 1;

    ON_ERR_SET_GOTO(ct_c_len + ct_q_len != ctlen, ret, OQS_ERROR, out);

    /* partisi ciphertext input */
    const unsigned char *ctC, *ctQ;
    unsigned char *ssC, *ssQ;
    if (k->reverse_share) {
        ctQ = ct;                ctC = ct + ct_q_len;
        ssQ = secret;            ssC = secret + ss_q_len;
    } else {
        ctC = ct;                ctQ = ct + ct_c_len;
        ssC = secret;            ssQ = secret + ss_c_len;
    }

    ret = km_evp_kem_decaps_keyslot(vctx, ssC, &ss_c_len, ctC, ct_c_len, k->reverse_share ? 1 : 0);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, out);
    ret = km_qs_kem_decaps_keyslot (vctx, ssQ, &ss_q_len, ctQ, ct_q_len, k->reverse_share ? 0 : 1);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, out);

out:
    return ret;
}

/* =========================================================================
 * DISPATCH TABLES
 * ========================================================================= */
#define MAKE_KEM_FUNCTIONS(alg)                                                \
    const OSSL_DISPATCH km_##alg##_kem_functions[] = {                         \
        { OSSL_FUNC_KEM_NEWCTX,           (void (*)(void))km_kem_newctx },     \
        { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))km_kem_encaps_init },\
        { OSSL_FUNC_KEM_ENCAPSULATE,      (void (*)(void))km_qs_kem_encaps },  \
        { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))km_kem_decaps_init },\
        { OSSL_FUNC_KEM_DECAPSULATE,      (void (*)(void))km_qs_kem_decaps },  \
        { OSSL_FUNC_KEM_FREECTX,          (void (*)(void))km_kem_freectx },    \
        { 0, NULL }                                                            \
    }

#define MAKE_HYB_KEM_FUNCTIONS(alg)                                            \
    const OSSL_DISPATCH km_##alg##_kem_functions[] = {                         \
        { OSSL_FUNC_KEM_NEWCTX,           (void (*)(void))km_kem_newctx },     \
        { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))km_kem_encaps_init },\
        { OSSL_FUNC_KEM_ENCAPSULATE,      (void (*)(void))km_hyb_kem_encaps }, \
        { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))km_kem_decaps_init },\
        { OSSL_FUNC_KEM_DECAPSULATE,      (void (*)(void))km_hyb_kem_decaps }, \
        { OSSL_FUNC_KEM_FREECTX,          (void (*)(void))km_kem_freectx },    \
        { 0, NULL }                                                            \
    }

/* tetap generic/hybrid seperti semula */
MAKE_KEM_FUNCTIONS(generic);
MAKE_HYB_KEM_FUNCTIONS(hybrid);
