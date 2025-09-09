// SPDX-License-Identifier: Apache-2.0 AND MIT
// KM OpenSSL 3 provider

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
/* ======================================================================
 * Decoder-side utilities
 * ====================================================================== */

#ifdef NDEBUG
#  define KM_DEC_PRINTF(...)   do {} while (0)
#  define KM_DEC_PRINTF2(...)  do {} while (0)
#  define KM_DEC_PRINTF3(...)  do {} while (0)
#else
static inline int KM_DEC_LOG_ENABLED(void) { return getenv("KMDEC") != NULL; }
#  define KM_DEC_PRINTF(fmt)                           do { if (KM_DEC_LOG_ENABLED()) printf("%s", (fmt)); } while (0)
#  define KM_DEC_PRINTF2(fmt,a)                        do { if (KM_DEC_LOG_ENABLED()) printf((fmt),(a)); } while (0)
#  define KM_DEC_PRINTF3(fmt,a,b)                      do { if (KM_DEC_LOG_ENABLED()) printf((fmt),(a),(b)); } while (0)
#endif /* NDEBUG */

/* Forward decls & typedefs (signatures dipertahankan) */
struct der2key_ctx_st;
typedef int  check_key_fn(void *, struct der2key_ctx_st *ctx);
typedef void adjust_key_fn(void *, struct der2key_ctx_st *ctx);
typedef void free_key_fn(void *);
typedef void *d2i_PKCS8_fn(void **, const unsigned char **, long, struct der2key_ctx_st *);

struct keytype_desc_st {
    const char *keytype_name;
    const OSSL_DISPATCH *fns;       /* keymgmt dispatch table */

    const char *structure_name;     /* nama struktur input */

    /*
     * evp_type: 0 untuk tipe spesifik;
     * non-zero bila terbungkus PKCS#8 / SPKI (menentukan jalur d2i_* mana).
     */
    int evp_type;

    int selection_mask;             /* untuk OSSL_FUNC_decoder_does_selection() */

    /* jalur d2i tipe-spesifik */
    d2i_of_void *d2i_private_key;
    d2i_of_void *d2i_public_key;
    d2i_of_void *d2i_key_params;
    d2i_PKCS8_fn *d2i_PKCS8;        /* private key info wrapper */
    d2i_of_void *d2i_PUBKEY;        /* SubjectPublicKeyInfo wrapper */

    /* hook validasi & penyesuaian */
    check_key_fn  *check_key;
    adjust_key_fn *adjust_key;
    free_key_fn   *free_key;        /* {type}_free() */
};

/* --------- “steal” bloc: internal X509_PUBKEY decoder (tetap sama fungsi) --- */
/* Catatan: bergantung pada struktur internal; gunakan dengan kehati-hatian. */
struct X509_pubkey_st {
    X509_ALGOR      *algor;
    ASN1_BIT_STRING *public_key;
    EVP_PKEY        *pkey;
    OSSL_LIB_CTX    *libctx;
    char            *propq;
    unsigned int     flag_force_legacy : 1;
};

ASN1_SEQUENCE(X509_PUBKEY_INTERNAL) = {
    ASN1_SIMPLE(X509_PUBKEY, algor, X509_ALGOR),
    ASN1_SIMPLE(X509_PUBKEY, public_key, ASN1_BIT_STRING)
} static_ASN1_SEQUENCE_END_name(X509_PUBKEY, X509_PUBKEY_INTERNAL)

X509_PUBKEY *kmx_d2i_X509_PUBKEY_INTERNAL(const unsigned char **pp, long len,
                                          OSSL_LIB_CTX *libctx) {
    X509_PUBKEY *xpub = OPENSSL_zalloc(sizeof(*xpub));
    if (xpub == NULL) return NULL;

    /* ASN1_item_d2i_ex akan mengganti *xpub; sukses → milik caller */
    return (X509_PUBKEY *)ASN1_item_d2i_ex((ASN1_VALUE **)&xpub, pp, len,
                                           ASN1_ITEM_rptr(X509_PUBKEY_INTERNAL),
                                           libctx, NULL);
}
/* --------------------------- end steal --------------------------------- */

/* Context DER→key */
struct der2key_ctx_st {
    PROV_KM_CTX *provctx;
    struct keytype_desc_st *desc;
    int  selection;          /* diteruskan ke km_der2key_decode() */
    unsigned int flag_fatal : 1;
};

/* --------- I/O helper: baca DER dari core BIO --------- */
int km_read_der(PROV_KM_CTX *provctx, OSSL_CORE_BIO *cin,
                unsigned char **data, long *len) {
    KM_DEC_PRINTF("KM DEC provider: km_read_der called.\n");

    if (!provctx || !cin || !data || !len) {
        ERR_raise(ERR_LIB_USER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    BIO *in = km_bio_new_from_core_bio(provctx, cin);
    BUF_MEM *mem = NULL;
    int ok = 0;

    if (!in) return 0;

    ok = (asn1_d2i_read_bio(in, &mem) >= 0);
    if (ok && mem) {
        *data = (unsigned char *)mem->data;
        *len  = (long)mem->length;
        OPENSSL_free(mem);          /* mem->data dipindahkan ke caller */
    }

    BIO_free(in);
    return ok;
}

/* --------- PKCS#8 decoder wrapper --------- */
typedef void *key_from_pkcs8_t(const PKCS8_PRIV_KEY_INFO *p8inf,
                               OSSL_LIB_CTX *libctx, const char *propq);

static void *km_der2key_decode_p8(const unsigned char **input_der,
                                  long input_der_len,
                                  struct der2key_ctx_st *ctx,
                                  key_from_pkcs8_t *key_from_pkcs8) {
    KM_DEC_PRINTF2("KM DEC provider: km_der2key_decode_p8 called. Keytype: %d.\n",
                   ctx && ctx->desc ? ctx->desc->evp_type : -1);

    if (!input_der || !ctx || !ctx->desc || !key_from_pkcs8) {
        ERR_raise(ERR_LIB_USER, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    PKCS8_PRIV_KEY_INFO *p8inf = NULL;
    const X509_ALGOR *alg = NULL;
    void *key = NULL;

    p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, input_der, input_der_len);
    if (p8inf == NULL) goto done;

    if (!PKCS8_pkey_get0(NULL, NULL, NULL, &alg, p8inf) || alg == NULL)
        goto done;

    if (OBJ_obj2nid(alg->algorithm) != ctx->desc->evp_type)
        goto done;

    key = key_from_pkcs8(p8inf, PROV_KM_LIBCTX_OF(ctx->provctx), NULL);

done:
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    return key;
}

/* --------- SPKI (PUBKEY) decoder untuk KMX_KEY --------- */
KMX_KEY *kmx_d2i_PUBKEY(KMX_KEY **a, const unsigned char **pp, long length) {
    KM_DEC_PRINTF2("KM DEC provider: kmx_d2i_PUBKEY called with length %ld\n", length);

    if (!pp || length <= 0) {
        ERR_raise(ERR_LIB_USER, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    /* Bangun X509_PUBKEY dari DER internal */
    X509_PUBKEY *xpk = kmx_d2i_X509_PUBKEY_INTERNAL(pp, length, NULL);
    if (!xpk) return NULL;

    /* Konversi ke KMX_KEY (fungsi existing) */
    KMX_KEY *key = kmx_key_from_x509pubkey(xpk, NULL, NULL);
    X509_PUBKEY_free(xpk);

    if (!key) return NULL;

    if (a != NULL) {
        kmx_key_free(*a);
        *a = key;
    }
    return key;
}

/* ======================================================================
 * der2key_* — behavior compatible, different structure
 * ====================================================================== */

static OSSL_FUNC_decoder_freectx_fn        der2key_freectx;
static OSSL_FUNC_decoder_decode_fn         km_der2key_decode;
static OSSL_FUNC_decoder_export_object_fn  der2key_export_object;

/* -------------------- small helpers -------------------- */

static int km_matches_selection(int selection, int mask) {
    /* 0 = guessing supported */
    if (selection == 0) return 1;
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        return (mask & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        return (mask & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
    if (selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)
        return (mask & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0;
    return 0;
}

static void *km_try_decode_priv(struct der2key_ctx_st *ctx,
                                const unsigned char *der, long der_len) {
    const unsigned char *p = der;
    void *key = NULL;

    if (ctx->desc->d2i_PKCS8 != NULL) {
        key = ctx->desc->d2i_PKCS8(NULL, &p, der_len, ctx);
        if (ctx->flag_fatal) return NULL; /* patuhi semantik lama */
    } else if (ctx->desc->d2i_private_key != NULL) {
        p = der;
        key = ctx->desc->d2i_private_key(NULL, &p, der_len);
    }
    return key;
}

static void *km_try_decode_pub(struct der2key_ctx_st *ctx,
                               const unsigned char *der, long der_len) {
    const unsigned char *p = der;
    if (ctx->desc->d2i_PUBKEY != NULL)
        return ctx->desc->d2i_PUBKEY(NULL, &p, der_len);

    p = der;
    return ctx->desc->d2i_public_key
             ? ctx->desc->d2i_public_key(NULL, &p, der_len)
             : NULL;
}

static void *km_try_decode_params(struct der2key_ctx_st *ctx,
                                  const unsigned char *der, long der_len) {
    const unsigned char *p = der;
    return ctx->desc->d2i_key_params
             ? ctx->desc->d2i_key_params(NULL, &p, der_len)
             : NULL;
}

/* -------------------- ctx lifecycle -------------------- */

static struct der2key_ctx_st *der2key_newctx(void *provctx,
                                             struct keytype_desc_st *desc,
                                             const char *tls_name) {
    KM_DEC_PRINTF3("KM DEC provider: der2key_newctx tls=%s type=%d\n",
                   tls_name, desc ? desc->evp_type : -1);

    struct der2key_ctx_st *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx) return NULL;

    ctx->provctx = (PROV_KM_CTX *)provctx;
    ctx->desc    = desc;
    ctx->selection = 0;
    ctx->flag_fatal = 0;

    if (desc && desc->evp_type == 0 && tls_name) {
        ctx->desc->evp_type = OBJ_sn2nid(tls_name);
        KM_DEC_PRINTF2("KM DEC provider: der2key_newctx set evp_type=%d\n",
                       ctx->desc->evp_type);
    }
    return ctx;
}

static void der2key_freectx(void *vctx) {
    struct der2key_ctx_st *ctx = (struct der2key_ctx_st *)vctx;
    OPENSSL_free(ctx);
}

/* -------------------- selection check -------------------- */

static int der2key_check_selection(int selection,
                                   const struct keytype_desc_st *desc) {
    KM_DEC_PRINTF3("KM DEC provider: der2key_check_selection sel=%d mask=%d\n",
                   selection, desc ? desc->selection_mask : 0);

    if (!desc) return 0;

    /* Logging kompatibel, namun logika lebih ringkas */
    if (selection == 0) return 1;

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        return (desc->selection_mask & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        return (desc->selection_mask & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
    if (selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)
        return (desc->selection_mask & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0;

    return 0;
}

/* -------------------- core decode -------------------- */

static int km_der2key_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
                             OSSL_CALLBACK *data_cb, void *data_cbarg,
                             OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg) {
    (void)pw_cb; (void)pw_cbarg; /* tidak dipakai pada jalur ini */

    struct der2key_ctx_st *ctx = (struct der2key_ctx_st *)vctx;
    unsigned char *der = NULL;
    long der_len = 0;
    int ok = 0;
    void *key = NULL;

    KM_DEC_PRINTF("KM DEC provider: km_der2key_decode called.\n");

    if (!ctx || !ctx->desc || !cin || !data_cb) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    ctx->selection = selection;

    /* 0 berarti “guessing”; gunakan mask dari deskriptor */
    if (selection == 0)
        selection = ctx->desc->selection_mask;

    /* jika tidak kompatibel, langsung gagal sesuai perilaku lama */
    if ((selection & ctx->desc->selection_mask) == 0) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    /* baca DER */
    if (!km_read_der(ctx->provctx, cin, &der, &der_len))
        goto done_success_empty; /* “empty handed” bukan error */

    /* coba decode sesuai prioritas lama: private → public → params */
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        key = km_try_decode_priv(ctx, der, der_len);
        if (key == NULL && ctx->selection != 0) goto done_success_empty;
    }
    if (!key && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)) {
        key = km_try_decode_pub(ctx, der, der_len);
        if (key == NULL && ctx->selection != 0) goto done_success_empty;
    }
    if (!key && (selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)) {
        key = km_try_decode_params(ctx, der, der_len);
        if (key == NULL && ctx->selection != 0) goto done_success_empty;
    }

    /* validasi varian kunci (mis. RSA-PSS vs RSA) — tidak fatal */
    if (key && ctx->desc->check_key && !ctx->desc->check_key(key, ctx)) {
        ctx->desc->free_key(key);
        key = NULL;
    }

    if (key && ctx->desc->adjust_key)
        ctx->desc->adjust_key(key, ctx);

done_success_empty:
    ok = 1; /* “berhasil decode sesuatu, atau tidak sama sekali” */

    /* lepaskan buffer DER sebelum callback (mengikuti komentar asli) */
    OPENSSL_free(der); der = NULL;

    if (key) {
        /* siapkan params untuk callback */
        OSSL_PARAM params[4];
        int object_type = OSSL_OBJECT_PKEY;

        params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                     (char *)ctx->desc->keytype_name, 0);
        params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                      &key, sizeof(key)); /* alamat objek */
        params[3] = OSSL_PARAM_construct_end();

        ok = data_cb(params, data_cbarg);
    }

    /* free di akhir sesuai perilaku awal */
    ctx->desc->free_key(key);
    OPENSSL_free(der);
    return ok;
}

/* -------------------- export object -------------------- */

static int der2key_export_object(void *vctx, const void *reference,
                                 size_t reference_sz, OSSL_CALLBACK *export_cb,
                                 void *export_cbarg) {
    struct der2key_ctx_st *ctx = (struct der2key_ctx_st *)vctx;
    OSSL_FUNC_keymgmt_export_fn *export = km_prov_get_keymgmt_export(ctx->desc->fns);

    KM_DEC_PRINTF("KM DEC provider: der2key_export_object called.\n");

    if (!export || reference_sz != sizeof(void *))
        return 0;

    /* isi reference adalah alamat objek */
    void *keydata = *(void * const *)reference;
    return export(keydata, ctx->selection, export_cb, export_cbarg);
}

/* -------------------- KMX glue -------------------- */

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
// #ifdef KM_KEM_ENCODERS

MAKE_DECODER(, "kyber512", kyber512, kmx, PrivateKeyInfo);
MAKE_DECODER(, "kyber512", kyber512, kmx, SubjectPublicKeyInfo);
MAKE_DECODER(_ecx, "x25519_kyber512", x25519_kyber512, kmx, PrivateKeyInfo);
MAKE_DECODER(_ecx, "x25519_kyber512", x25519_kyber512, kmx,
             SubjectPublicKeyInfo);

MAKE_DECODER(, "kyber768", kyber768, kmx, PrivateKeyInfo);
MAKE_DECODER(, "kyber768", kyber768, kmx, SubjectPublicKeyInfo);
MAKE_DECODER(_ecx, "x25519_kyber768", x25519_kyber768, kmx, PrivateKeyInfo);
MAKE_DECODER(_ecx, "x25519_kyber768", x25519_kyber768, kmx,
             SubjectPublicKeyInfo);

MAKE_DECODER(, "kyber1024", kyber1024, kmx, PrivateKeyInfo);
MAKE_DECODER(, "kyber1024", kyber1024, kmx, SubjectPublicKeyInfo);


MAKE_DECODER(, "mlkem512", mlkem512, kmx, PrivateKeyInfo);
MAKE_DECODER(, "mlkem512", mlkem512, kmx, SubjectPublicKeyInfo);
MAKE_DECODER(_ecx, "x25519_mlkem512", x25519_mlkem512, kmx, PrivateKeyInfo);
MAKE_DECODER(_ecx, "x25519_mlkem512", x25519_mlkem512, kmx,
             SubjectPublicKeyInfo);

MAKE_DECODER(, "mlkem768", mlkem768, kmx, PrivateKeyInfo);
MAKE_DECODER(, "mlkem768", mlkem768, kmx, SubjectPublicKeyInfo);
MAKE_DECODER(_ecx, "X25519MLKEM768", X25519MLKEM768, kmx, PrivateKeyInfo);
MAKE_DECODER(_ecx, "X25519MLKEM768", X25519MLKEM768, kmx,
             SubjectPublicKeyInfo);

MAKE_DECODER(, "mlkem1024", mlkem1024, kmx, PrivateKeyInfo);
MAKE_DECODER(, "mlkem1024", mlkem1024, kmx, SubjectPublicKeyInfo);


// #endif /* KM_KEM_ENCODERS */

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
