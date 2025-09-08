/*
 * Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/pem.h> /* PEM_BUFSIZE and public PEM functions */
#include <openssl/pkcs12.h>
#include <openssl/proverr.h>
#include <openssl/x509.h>
// #include "internal/asn1.h"
// instead just:
int asn1_d2i_read_bio(BIO *in, BUF_MEM **pb); // TBD: OK to use?

#include "encdec.h"

#ifdef NDEBUG
#define KM_DEC_PRINTF(a)
#define KM_DEC_PRINTF2(a, b)
#define KM_DEC_PRINTF3(a, b, c)
#else
#define KM_DEC_PRINTF(a)                                                      \
    if (getenv("KMDEC"))                                                      \
    printf(a)
#define KM_DEC_PRINTF2(a, b)                                                  \
    if (getenv("KMDEC"))                                                      \
    printf(a, b)
#define KM_DEC_PRINTF3(a, b, c)                                               \
    if (getenv("KMDEC"))                                                      \
    printf(a, b, c)
#endif // NDEBUG

struct der2key_ctx_st; /* Forward declaration */
typedef int check_key_fn(void *, struct der2key_ctx_st *ctx);
typedef void adjust_key_fn(void *, struct der2key_ctx_st *ctx);
typedef void free_key_fn(void *);
typedef void *d2i_PKCS8_fn(void **, const unsigned char **, long,
                           struct der2key_ctx_st *);
struct keytype_desc_st {
    const char *keytype_name;
    const OSSL_DISPATCH *fns; /* Keymgmt (to pilfer functions from) */

    /* The input structure name */
    const char *structure_name;

    /*
     * The EVP_PKEY_xxx type macro.  Should be zero for type specific
     * structures, non-zero when the outermost structure is PKCS#8 or
     * SubjectPublicKeyInfo.  This determines which of the function
     * pointers below will be used.
     */
    int evp_type;

    /* The selection mask for OSSL_FUNC_decoder_does_selection() */
    int selection_mask;

    /* For type specific decoders, we use the corresponding d2i */
    d2i_of_void *d2i_private_key; /* From type-specific DER */
    d2i_of_void *d2i_public_key;  /* From type-specific DER */
    d2i_of_void *d2i_key_params;  /* From type-specific DER */
    d2i_PKCS8_fn *d2i_PKCS8;      /* Wrapped in a PrivateKeyInfo */
    d2i_of_void *d2i_PUBKEY;      /* Wrapped in a SubjectPublicKeyInfo */

    /*
     * For any key, we may need to check that the key meets expectations.
     * This is useful when the same functions can decode several variants
     * of a key.
     */
    check_key_fn *check_key;

    /*
     * For any key, we may need to make provider specific adjustments, such
     * as ensure the key carries the correct library context.
     */
    adjust_key_fn *adjust_key;
    /* {type}_free() */
    free_key_fn *free_key;
};

// Start steal. Alternative: Open up d2i_X509_PUBKEY_INTERNAL
// as per https://github.com/openssl/openssl/issues/16697 (TBD)
// stolen from openssl/crypto/x509/x_pubkey.c as ossl_d2i_X509_PUBKEY_INTERNAL
// not public: dangerous internal struct dependency: Suggest opening up
// ossl_d2i_X509_PUBKEY_INTERNAL or find out how to decode X509 with own ASN1
// calls
struct X509_pubkey_st {
    X509_ALGOR *algor;
    ASN1_BIT_STRING *public_key;

    EVP_PKEY *pkey;

    /* extra data for the callback, used by d2i_PUBKEY_ex */
    OSSL_LIB_CTX *libctx;
    char *propq;

    /* Flag to force legacy keys */
    unsigned int flag_force_legacy : 1;
};

ASN1_SEQUENCE(X509_PUBKEY_INTERNAL) =
    {ASN1_SIMPLE(X509_PUBKEY, algor, X509_ALGOR),
     ASN1_SIMPLE(
         X509_PUBKEY, public_key,
         ASN1_BIT_STRING)} static_ASN1_SEQUENCE_END_name(X509_PUBKEY,
                                                         X509_PUBKEY_INTERNAL)

        X509_PUBKEY
    * kmx_d2i_X509_PUBKEY_INTERNAL(const unsigned char **pp, long len,
                                    OSSL_LIB_CTX *libctx) {
    X509_PUBKEY *xpub = OPENSSL_zalloc(sizeof(*xpub));

    if (xpub == NULL)
        return NULL;
    return (X509_PUBKEY *)ASN1_item_d2i_ex((ASN1_VALUE **)&xpub, pp, len,
                                           ASN1_ITEM_rptr(X509_PUBKEY_INTERNAL),
                                           libctx, NULL);
}
// end steal TBD

/*
 * Context used for DER to key decoding.
 */
struct der2key_ctx_st {
    PROV_KM_CTX *provctx;
    struct keytype_desc_st *desc;
    /* The selection that is passed to km_der2key_decode() */
    int selection;
    /* Flag used to signal that a failure is fatal */
    unsigned int flag_fatal : 1;
};

int km_read_der(PROV_KM_CTX *provctx, OSSL_CORE_BIO *cin,
                 unsigned char **data, long *len) {
    KM_DEC_PRINTF("KM DEC provider: km_read_der called.\n");

    BUF_MEM *mem = NULL;
    BIO *in = km_bio_new_from_core_bio(provctx, cin);
    int ok = (asn1_d2i_read_bio(in, &mem) >= 0);

    if (ok) {
        *data = (unsigned char *)mem->data;
        *len = (long)mem->length;
        OPENSSL_free(mem);
    }
    BIO_free(in);
    return ok;
}

typedef void *key_from_pkcs8_t(const PKCS8_PRIV_KEY_INFO *p8inf,
                               OSSL_LIB_CTX *libctx, const char *propq);
static void *km_der2key_decode_p8(const unsigned char **input_der,
                                   long input_der_len,
                                   struct der2key_ctx_st *ctx,
                                   key_from_pkcs8_t *key_from_pkcs8) {
    PKCS8_PRIV_KEY_INFO *p8inf = NULL;
    const X509_ALGOR *alg = NULL;
    void *key = NULL;

    KM_DEC_PRINTF2(
        "KM DEC provider: km_der2key_decode_p8 called. Keytype: %d.\n",
        ctx->desc->evp_type);

    if ((p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, input_der, input_der_len)) !=
            NULL &&
        PKCS8_pkey_get0(NULL, NULL, NULL, &alg, p8inf) &&
        OBJ_obj2nid(alg->algorithm) == ctx->desc->evp_type)
        key = key_from_pkcs8(p8inf, PROV_KM_LIBCTX_OF(ctx->provctx), NULL);
    PKCS8_PRIV_KEY_INFO_free(p8inf);

    return key;
}

KMX_KEY *kmx_d2i_PUBKEY(KMX_KEY **a, const unsigned char **pp, long length) {
    KMX_KEY *key = NULL;
    // taken from internal code for d2i_PUBKEY_int:
    X509_PUBKEY *xpk;

    KM_DEC_PRINTF2(
        "KM DEC provider: kmx_d2i_PUBKEY called with length %ld\n", length);

    // only way to re-create X509 object?? TBD
    xpk = kmx_d2i_X509_PUBKEY_INTERNAL(pp, length, NULL);

    key = kmx_key_from_x509pubkey(xpk, NULL, NULL);
    X509_PUBKEY_free(xpk);

    if (key == NULL)
        return NULL;

    if (a != NULL) {
        kmx_key_free(*a);
        *a = key;
    }
    return key;
}

/* ---------------------------------------------------------------------- */

static OSSL_FUNC_decoder_freectx_fn der2key_freectx;
static OSSL_FUNC_decoder_decode_fn km_der2key_decode;
static OSSL_FUNC_decoder_export_object_fn der2key_export_object;

static struct der2key_ctx_st *der2key_newctx(void *provctx,
                                             struct keytype_desc_st *desc,
                                             const char *tls_name) {
    struct der2key_ctx_st *ctx = OPENSSL_zalloc(sizeof(*ctx));

    KM_DEC_PRINTF3("KM DEC provider: der2key_newctx called with tls_name %s. "
                    "Keytype: %d\n",
                    tls_name, desc->evp_type);

    if (ctx != NULL) {
        ctx->provctx = provctx;
        ctx->desc = desc;
        if (desc->evp_type == 0) {
            ctx->desc->evp_type = OBJ_sn2nid(tls_name);
            KM_DEC_PRINTF2("KM DEC provider: der2key_newctx set "
                            "evp_type to %d\n",
                            ctx->desc->evp_type);
        }
    }
    return ctx;
}

static void der2key_freectx(void *vctx) {
    struct der2key_ctx_st *ctx = vctx;

    OPENSSL_free(ctx);
}

static int der2key_check_selection(int selection,
                                   const struct keytype_desc_st *desc) {
    /*
     * The selections are kinda sorta "levels", i.e. each selection given
     * here is assumed to include those following.
     */
    int checks[] = {OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                    OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                    OSSL_KEYMGMT_SELECT_ALL_PARAMETERS};
    size_t i;

    KM_DEC_PRINTF3("KM DEC provider: der2key_check_selection called with "
                    "selection %d (%d).\n",
                    selection, desc->selection_mask);

    /* The decoder implementations made here support guessing */
    if (selection == 0)
        return 1;

    for (i = 0; i < OSSL_NELEM(checks); i++) {
        int check1 = (selection & checks[i]) != 0;
        int check2 = (desc->selection_mask & checks[i]) != 0;

        /*
         * If the caller asked for the currently checked bit(s), return
         * whether the decoder description says it's supported.
         */
        KM_DEC_PRINTF3("KM DEC provider: der2key_check_selection "
                        "returning %d (%d).\n",
                        check1, check2);

        if (check1)
            return check2;
    }

    /* This should be dead code, but just to be safe... */
    return 0;
}

static int km_der2key_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
                              OSSL_CALLBACK *data_cb, void *data_cbarg,
                              OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg) {
    struct der2key_ctx_st *ctx = vctx;
    unsigned char *der = NULL;
    const unsigned char *derp;
    long der_len = 0;
    void *key = NULL;
    int ok = 0;

    KM_DEC_PRINTF("KM DEC provider: km_der2key_decode called.\n");

    ctx->selection = selection;
    /*
     * The caller is allowed to specify 0 as a selection mark, to have the
     * structure and key type guessed.  For type-specific structures, this
     * is not recommended, as some structures are very similar.
     * Note that 0 isn't the same as OSSL_KEYMGMT_SELECT_ALL, as the latter
     * signifies a private key structure, where everything else is assumed
     * to be present as well.
     */
    if (selection == 0)
        selection = ctx->desc->selection_mask;
    if ((selection & ctx->desc->selection_mask) == 0) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    ok = km_read_der(ctx->provctx, cin, &der, &der_len);
    if (!ok)
        goto next;

    ok = 0; /* Assume that we fail */

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        derp = der;
        if (ctx->desc->d2i_PKCS8 != NULL) {
            key = ctx->desc->d2i_PKCS8(NULL, &derp, der_len, ctx);
            if (ctx->flag_fatal)
                goto end;
        } else if (ctx->desc->d2i_private_key != NULL) {
            key = ctx->desc->d2i_private_key(NULL, &derp, der_len);
        }
        if (key == NULL && ctx->selection != 0)
            goto next;
    }
    if (key == NULL && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        derp = der;
        if (ctx->desc->d2i_PUBKEY != NULL)
            key = ctx->desc->d2i_PUBKEY(NULL, &derp, der_len);
        else
            key = ctx->desc->d2i_public_key(NULL, &derp, der_len);
        if (key == NULL && ctx->selection != 0)
            goto next;
    }
    if (key == NULL && (selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0) {
        derp = der;
        if (ctx->desc->d2i_key_params != NULL)
            key = ctx->desc->d2i_key_params(NULL, &derp, der_len);
        if (key == NULL && ctx->selection != 0)
            goto next;
    }

    /*
     * Last minute check to see if this was the correct type of key.  This
     * should never lead to a fatal error, i.e. the decoding itself was
     * correct, it was just an unexpected key type.  This is generally for
     * classes of key types that have subtle variants, like RSA-PSS keys as
     * opposed to plain RSA keys.
     */
    if (key != NULL && ctx->desc->check_key != NULL &&
        !ctx->desc->check_key(key, ctx)) {
        ctx->desc->free_key(key);
        key = NULL;
    }

    if (key != NULL && ctx->desc->adjust_key != NULL)
        ctx->desc->adjust_key(key, ctx);

next:
    /*
     * Indicated that we successfully decoded something, or not at all.
     * Ending up "empty handed" is not an error.
     */
    ok = 1;

    /*
     * We free memory here so it's not held up during the callback, because
     * we know the process is recursive and the allocated chunks of memory
     * add up.
     */
    OPENSSL_free(der);
    der = NULL;

    if (key != NULL) {
        OSSL_PARAM params[4];
        int object_type = OSSL_OBJECT_PKEY;

        params[0] =
            OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
        params[1] = OSSL_PARAM_construct_utf8_string(
            OSSL_OBJECT_PARAM_DATA_TYPE, (char *)ctx->desc->keytype_name, 0);
        /* The address of the key becomes the octet string */
        params[2] = OSSL_PARAM_construct_octet_string(
            OSSL_OBJECT_PARAM_REFERENCE, &key, sizeof(key));
        params[3] = OSSL_PARAM_construct_end();

        ok = data_cb(params, data_cbarg);
    }

end:
    ctx->desc->free_key(key);
    OPENSSL_free(der);

    return ok;
}

static int der2key_export_object(void *vctx, const void *reference,
                                 size_t reference_sz, OSSL_CALLBACK *export_cb,
                                 void *export_cbarg) {
    struct der2key_ctx_st *ctx = vctx;
    OSSL_FUNC_keymgmt_export_fn *export =
        km_prov_get_keymgmt_export(ctx->desc->fns);
    void *keydata;

    KM_DEC_PRINTF("KM DEC provider: der2key_export_object called.\n");

    if (reference_sz == sizeof(keydata) && export != NULL) {
        /* The contents of the reference is the address to our object */
        keydata = *(void **)reference;

        return export(keydata, ctx->selection, export_cb, export_cbarg);
    }
    return 0;
}

/* ---------------------------------------------------------------------- */

static void *kmx_d2i_PKCS8(void **key, const unsigned char **der, long der_len,
                            struct der2key_ctx_st *ctx) {
    KM_DEC_PRINTF("KM DEC provider: kmx_d2i_PKCS8 called.\n");

    return km_der2key_decode_p8(der, der_len, ctx,
                                 (key_from_pkcs8_t *)kmx_key_from_pkcs8);
}

static void kmx_key_adjust(void *key, struct der2key_ctx_st *ctx) {
    KM_DEC_PRINTF("KM DEC provider: kmx_key_adjust called.\n");

    kmx_key_set0_libctx(key, PROV_KM_LIBCTX_OF(ctx->provctx));
}

// KM provider uses NIDs generated at load time as EVP_type identifiers
// so initially this must be 0 and set to a real value by OBJ_sn2nid later

/* ---------------------------------------------------------------------- */

/*
 * The DO_ macros help define the selection mask and the method functions
 * for each kind of object we want to decode.
 */
#define DO_type_specific_keypair(keytype)                                      \
    "type-specific", 0, (OSSL_KEYMGMT_SELECT_KEYPAIR), NULL, NULL, NULL, NULL, \
        NULL, NULL, kmx_key_adjust, (free_key_fn *)kmx_key_free

#define DO_type_specific_pub(keytype)                                          \
    "type-specific", 0, (OSSL_KEYMGMT_SELECT_PUBLIC_KEY), NULL, NULL, NULL,    \
        NULL, NULL, NULL, kmx_key_adjust, (free_key_fn *)kmx_key_free

#define DO_type_specific_priv(keytype)                                         \
    "type-specific", 0, (OSSL_KEYMGMT_SELECT_PRIVATE_KEY), NULL, NULL, NULL,   \
        NULL, NULL, NULL, kmx_key_adjust, (free_key_fn *)kmx_key_free

#define DO_type_specific_params(keytype)                                       \
    "type-specific", 0, (OSSL_KEYMGMT_SELECT_ALL_PARAMETERS), NULL, NULL,      \
        NULL, NULL, NULL, NULL, kmx_key_adjust, (free_key_fn *)kmx_key_free

#define DO_type_specific(keytype)                                              \
    "type-specific", 0, (OSSL_KEYMGMT_SELECT_ALL), NULL, NULL, NULL, NULL,     \
        NULL, NULL, kmx_key_adjust, (free_key_fn *)kmx_key_free

#define DO_type_specific_no_pub(keytype)                                       \
    "type-specific", 0,                                                        \
        (OSSL_KEYMGMT_SELECT_PRIVATE_KEY |                                     \
         OSSL_KEYMGMT_SELECT_ALL_PARAMETERS),                                  \
        NULL, NULL, NULL, NULL, NULL, NULL, kmx_key_adjust,                   \
        (free_key_fn *)kmx_key_free

#define DO_PrivateKeyInfo(keytype)                                             \
    "PrivateKeyInfo", 0, (OSSL_KEYMGMT_SELECT_PRIVATE_KEY), NULL, NULL, NULL,  \
        kmx_d2i_PKCS8, NULL, NULL, kmx_key_adjust,                           \
        (free_key_fn *)kmx_key_free

#define DO_SubjectPublicKeyInfo(keytype)                                       \
    "SubjectPublicKeyInfo", 0, (OSSL_KEYMGMT_SELECT_PUBLIC_KEY), NULL, NULL,   \
        NULL, NULL, (d2i_of_void *)kmx_d2i_PUBKEY, NULL, kmx_key_adjust,     \
        (free_key_fn *)kmx_key_free

/*
 * MAKE_DECODER is the single driver for creating OSSL_DISPATCH tables.
 * It takes the following arguments:
 *
 * kmkemhyb    Possible prefix for KM KEM hybrids; typically empty
 * keytype_name The implementation key type as a string.
 * keytype      The implementation key type.  This must correspond exactly
 *              to our existing keymgmt keytype names...  in other words,
 *              there must exist an km_##keytype##_keymgmt_functions.
 * type         The type name for the set of functions that implement the
 *              decoder for the key type.  This isn't necessarily the same
 *              as keytype.  For example, the key types ed25519, ed448,
 *              x25519 and x448 are all handled by the same functions with
 *              the common type name ecx.
 * kind         The kind of support to implement.  This translates into
 *              the DO_##kind macros above, to populate the keytype_desc_st
 *              structure.
 */
// reverted const to be able to change NID/evp_type after assignment
#define MAKE_DECODER(kmkemhyb, keytype_name, keytype, type, kind)             \
    static struct keytype_desc_st kind##_##keytype##_desc = {                  \
        keytype_name, km##kmkemhyb##_##keytype##_keymgmt_functions,          \
        DO_##kind(keytype)};                                                   \
                                                                               \
    static OSSL_FUNC_decoder_newctx_fn kind##_der2##keytype##_newctx;          \
                                                                               \
    static void *kind##_der2##keytype##_newctx(void *provctx) {                \
        KM_DEC_PRINTF("KM DEC provider: _newctx called.\n");                 \
        return der2key_newctx(provctx, &kind##_##keytype##_desc,               \
                              keytype_name);                                   \
    }                                                                          \
    static int kind##_der2##keytype##_does_selection(void *provctx,            \
                                                     int selection) {          \
        KM_DEC_PRINTF("KM DEC provider: _does_selection called.\n");         \
        return der2key_check_selection(selection, &kind##_##keytype##_desc);   \
    }                                                                          \
    const OSSL_DISPATCH km_##kind##_der_to_##keytype##_decoder_functions[] =  \
        {{OSSL_FUNC_DECODER_NEWCTX,                                            \
          (void (*)(void))kind##_der2##keytype##_newctx},                      \
         {OSSL_FUNC_DECODER_FREECTX, (void (*)(void))der2key_freectx},         \
         {OSSL_FUNC_DECODER_DOES_SELECTION,                                    \
          (void (*)(void))kind##_der2##keytype##_does_selection},              \
         {OSSL_FUNC_DECODER_DECODE, (void (*)(void))km_der2key_decode},       \
         {OSSL_FUNC_DECODER_EXPORT_OBJECT,                                     \
          (void (*)(void))der2key_export_object},                              \
         {0, NULL}}

///// KM_TEMPLATE_FRAGMENT_DECODER_MAKE_START
#ifdef KM_KEM_ENCODERS

MAKE_DECODER(, "kyber512", kyber512, kmx, PrivateKeyInfo);
MAKE_DECODER(, "kyber512", kyber512, kmx, SubjectPublicKeyInfo);

MAKE_DECODER(, "kyber768", kyber768, kmx, PrivateKeyInfo);
MAKE_DECODER(, "kyber768", kyber768, kmx, SubjectPublicKeyInfo);

MAKE_DECODER(, "kyber1024", kyber1024, kmx, PrivateKeyInfo);
MAKE_DECODER(, "kyber1024", kyber1024, kmx, SubjectPublicKeyInfo);


MAKE_DECODER(, "mlkem512", mlkem512, kmx, PrivateKeyInfo);
MAKE_DECODER(, "mlkem512", mlkem512, kmx, SubjectPublicKeyInfo);

MAKE_DECODER(, "mlkem768", mlkem768, kmx, PrivateKeyInfo);
MAKE_DECODER(, "mlkem768", mlkem768, kmx, SubjectPublicKeyInfo);

MAKE_DECODER(, "mlkem1024", mlkem1024, kmx, PrivateKeyInfo);
MAKE_DECODER(, "mlkem1024", mlkem1024, kmx, SubjectPublicKeyInfo);


#endif /* KM_KEM_ENCODERS */

MAKE_DECODER(, "dilithium2", dilithium2, kmx, PrivateKeyInfo);
MAKE_DECODER(, "dilithium2", dilithium2, kmx, SubjectPublicKeyInfo);

MAKE_DECODER(, "dilithium3", dilithium3, kmx, PrivateKeyInfo);
MAKE_DECODER(, "dilithium3", dilithium3, kmx, SubjectPublicKeyInfo);

MAKE_DECODER(, "dilithium5", dilithium5, kmx, PrivateKeyInfo);
MAKE_DECODER(, "dilithium5", dilithium5, kmx, SubjectPublicKeyInfo);

MAKE_DECODER(, "mldsa44", mldsa44, kmx, PrivateKeyInfo);
MAKE_DECODER(, "mldsa44", mldsa44, kmx, SubjectPublicKeyInfo);

MAKE_DECODER(, "mldsa65", mldsa65, kmx, PrivateKeyInfo);
MAKE_DECODER(, "mldsa65", mldsa65, kmx, SubjectPublicKeyInfo);

MAKE_DECODER(, "mldsa87", mldsa87, kmx, PrivateKeyInfo);
MAKE_DECODER(, "mldsa87", mldsa87, kmx, SubjectPublicKeyInfo);

MAKE_DECODER(, "sphincssha2128fsimple", sphincssha2128fsimple, kmx,
             PrivateKeyInfo);
MAKE_DECODER(, "sphincssha2128fsimple", sphincssha2128fsimple, kmx,
             SubjectPublicKeyInfo);

MAKE_DECODER(, "sphincssha2128ssimple", sphincssha2128ssimple, kmx,
             PrivateKeyInfo);
MAKE_DECODER(, "sphincssha2128ssimple", sphincssha2128ssimple, kmx,
             SubjectPublicKeyInfo);
MAKE_DECODER(, "sphincssha2192fsimple", sphincssha2192fsimple, kmx,
             PrivateKeyInfo);
MAKE_DECODER(, "sphincssha2192fsimple", sphincssha2192fsimple, kmx,
             SubjectPublicKeyInfo);
MAKE_DECODER(, "sphincsshake128fsimple", sphincsshake128fsimple, kmx,
             PrivateKeyInfo);
MAKE_DECODER(, "sphincsshake128fsimple", sphincsshake128fsimple, kmx,
             SubjectPublicKeyInfo);
///// KM_TEMPLATE_FRAGMENT_DECODER_MAKE_END
