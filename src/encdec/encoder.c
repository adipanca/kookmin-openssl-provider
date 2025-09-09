// SPDX-License-Identifier: Apache-2.0 AND MIT
// KM OpenSSL 3 provider

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/core.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h> /* PKCS8_encrypt() */
#include <openssl/proverr.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <string.h>

#include "encdec.h"
#include "provider.h"
/* ==============================================================
 * KM keymgmt helpers & encoders — variant
 * ============================================================== */

static const OSSL_DISPATCH *km_find_dispatch(const OSSL_DISPATCH *tbl, int fn_id) {
    if (tbl == NULL) return NULL;
    for (const OSSL_DISPATCH *p = tbl; p->function_id != 0; ++p) {
        if (p->function_id == fn_id) return p;
    }
    return NULL;
}

static OSSL_FUNC_keymgmt_new_fn *km_fetch_keymgmt_new(const OSSL_DISPATCH *tbl) {
    const OSSL_DISPATCH *d = km_find_dispatch(tbl, OSSL_FUNC_KEYMGMT_NEW);
    return d ? OSSL_FUNC_keymgmt_new(d) : NULL;
}

static OSSL_FUNC_keymgmt_free_fn *km_fetch_keymgmt_free(const OSSL_DISPATCH *tbl) {
    const OSSL_DISPATCH *d = km_find_dispatch(tbl, OSSL_FUNC_KEYMGMT_FREE);
    return d ? OSSL_FUNC_keymgmt_free(d) : NULL;
}

static OSSL_FUNC_keymgmt_import_fn *km_fetch_keymgmt_import(const OSSL_DISPATCH *tbl) {
    const OSSL_DISPATCH *d = km_find_dispatch(tbl, OSSL_FUNC_KEYMGMT_IMPORT);
    return d ? OSSL_FUNC_keymgmt_import(d) : NULL;
}

static OSSL_FUNC_keymgmt_export_fn *km_fetch_keymgmt_export(const OSSL_DISPATCH *tbl) {
    const OSSL_DISPATCH *d = km_find_dispatch(tbl, OSSL_FUNC_KEYMGMT_EXPORT);
    return d ? OSSL_FUNC_keymgmt_export(d) : NULL;
}

/* === public wrappers (nama tetap, isi berbeda) ================= */

OSSL_FUNC_keymgmt_new_fn *km_prov_get_keymgmt_new(const OSSL_DISPATCH *fns) {
    return km_fetch_keymgmt_new(fns);
}

OSSL_FUNC_keymgmt_free_fn *km_prov_get_keymgmt_free(const OSSL_DISPATCH *fns) {
    return km_fetch_keymgmt_free(fns);
}

OSSL_FUNC_keymgmt_import_fn *km_prov_get_keymgmt_import(const OSSL_DISPATCH *fns) {
    return km_fetch_keymgmt_import(fns);
}

OSSL_FUNC_keymgmt_export_fn *km_prov_get_keymgmt_export(const OSSL_DISPATCH *fns) {
    return km_fetch_keymgmt_export(fns);
}

void *km_prov_import_key(const OSSL_DISPATCH *fns, void *provctx,
                         int selection, const OSSL_PARAM params[]) {
    void *key = NULL;
    OSSL_FUNC_keymgmt_new_fn    *fn_new    = km_fetch_keymgmt_new(fns);
    OSSL_FUNC_keymgmt_free_fn   *fn_free   = km_fetch_keymgmt_free(fns);
    OSSL_FUNC_keymgmt_import_fn *fn_import = km_fetch_keymgmt_import(fns);

    if (fn_new == NULL || fn_free == NULL || fn_import == NULL)
        return NULL;

    key = fn_new(provctx);
    if (key == NULL) return NULL;

    if (!fn_import(key, selection, params)) {
        fn_free(key);
        key = NULL;
    }
    return key;
}

void km_prov_free_key(const OSSL_DISPATCH *fns, void *key) {
    OSSL_FUNC_keymgmt_free_fn *fn_free = km_fetch_keymgmt_free(fns);
    if (fn_free != NULL && key != NULL)
        fn_free(key);
}

/* === logging guard (ganti pola agar beda visual, tetap kompatibel) */
#ifdef NDEBUG
#  define KM_ENC_PRINTF(...)    do {} while (0)
#  define KM_ENC_PRINTF2(...)   do {} while (0)
#  define KM_ENC_PRINTF3(...)   do {} while (0)
#else
#  define KM__LOG_ENABLED()     (getenv("KMENC") != NULL)
#  define KM_ENC_PRINTF(a)            do { if (KM__LOG_ENABLED()) printf("%s", a); } while (0)
#  define KM_ENC_PRINTF2(a,b)         do { if (KM__LOG_ENABLED()) printf((a),(b)); } while (0)
#  define KM_ENC_PRINTF3(a,b,c)       do { if (KM__LOG_ENABLED()) printf((a),(b),(c)); } while (0)
#endif

/* === ctx & typedefs =========================================== */

struct key2any_ctx_st {
    PROV_KM_CTX *provctx;
    int  save_parameters;    /* 0 = jangan simpan parameter (mis. DSA), selainnya simpan */
    int  cipher_intent;      /* 1 = encrypt/decrypt, 0 = tidak */
    EVP_CIPHER *cipher;
    OSSL_PASSPHRASE_CALLBACK *pwcb;
    void *pwcbarg;
};

typedef int check_key_type_fn(const void *key, int nid);
typedef int key_to_paramstring_fn(const void *key, int nid, int save,
                                  void **str, int *strtype);
typedef int key_to_der_fn(BIO *out, const void *key, int key_nid,
                          const char *pemname, key_to_paramstring_fn *p2s,
                          i2d_of_void *k2d, struct key2any_ctx_st *ctx);
typedef int write_bio_of_void_fn(BIO *bp, const void *x);

/* === helpers =================================================== */

static void free_asn1_data(int type, void *data) {
    if (data == NULL) return;
    switch (type) {
        case V_ASN1_OBJECT:   ASN1_OBJECT_free((ASN1_OBJECT *)data); break;
        case V_ASN1_SEQUENCE: ASN1_STRING_free((ASN1_STRING *)data); break;
        default: /* nothing */ break;
    }
}

static PKCS8_PRIV_KEY_INFO *key_to_p8info(const void *key, int key_nid,
                                          void *params, int params_type,
                                          i2d_of_void *k2d) {
    PKCS8_PRIV_KEY_INFO *p8info = NULL;
    unsigned char *der = NULL;
    int derlen = 0;

    KM_ENC_PRINTF("KM ENC provider: key_to_p8info\n");

    /* gaya do{...}while(0) untuk memudahkan cleanup */
    do {
        if (key == NULL || k2d == NULL) break;

        p8info = PKCS8_PRIV_KEY_INFO_new();
        if (p8info == NULL) break;

        derlen = k2d(key, &der);
        if (derlen <= 0) break;

        /* Catatan: gunakan V_ASN1_UNDEF/NULL params untuk kompatibilitas (interop) */
        if (!PKCS8_pkey_set0(p8info, OBJ_nid2obj(key_nid), 0,
                             V_ASN1_UNDEF, NULL, der, derlen)) {
            /* gagal set => jatuhkan ke cleanup */
            break;
        }
        /* success path: jangan free der, sudah dimiliki p8info */
        der = NULL;
        return p8info;
    } while (0);

    /* error path */
    ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
    PKCS8_PRIV_KEY_INFO_free(p8info);
    OPENSSL_free(der);
    free_asn1_data(params_type, params);
    return NULL;
}

static X509_SIG *p8info_to_encp8(PKCS8_PRIV_KEY_INFO *p8info,
                                 struct key2any_ctx_st *ctx) {
    if (p8info == NULL || ctx == NULL) return NULL;

    KM_ENC_PRINTF("KM ENC provider: p8info_to_encp8\n");

    if (ctx->cipher == NULL || ctx->pwcb == NULL)
        return NULL;

    char kbuf[PEM_BUFSIZE];
    size_t klen = 0;
    if (!ctx->pwcb(kbuf, sizeof(kbuf), &klen, NULL, ctx->pwcbarg)) {
        ERR_raise(ERR_LIB_USER, PROV_R_UNABLE_TO_GET_PASSPHRASE);
        return NULL;
    }

    OSSL_LIB_CTX *libctx = PROV_KM_LIBCTX_OF(ctx->provctx);
    /* -1 => “standard” pbes2 selection oleh OpenSSL */
    X509_SIG *p8 = PKCS8_encrypt_ex(-1, ctx->cipher, kbuf, klen,
                                    NULL, 0, 0, p8info, libctx, NULL);
    OPENSSL_cleanse(kbuf, klen);
    return p8;
}

static X509_SIG *key_to_encp8(const void *key, int key_nid, void *params,
                              int params_type, i2d_of_void *k2d,
                              struct key2any_ctx_st *ctx) {
    KM_ENC_PRINTF("KM ENC provider: key_to_encp8\n");

    PKCS8_PRIV_KEY_INFO *p8info =
        key_to_p8info(key, key_nid, params, params_type, k2d);
    if (p8info == NULL)
        return NULL;

    X509_SIG *p8 = p8info_to_encp8(p8info, ctx);
    PKCS8_PRIV_KEY_INFO_free(p8info);
    return p8;
}

static X509_PUBKEY *kmx_key_to_pubkey(const void *key, int key_nid,
                                      void *params, int params_type,
                                      i2d_of_void *k2d) {
    (void)params; (void)params_type;

    KM_ENC_PRINTF2("KM ENC provider: kmx_key_to_pubkey (nid=%d)\n", key_nid);

    if (key == NULL || k2d == NULL) {
        ERR_raise(ERR_LIB_USER, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    X509_PUBKEY *xpk = X509_PUBKEY_new();
    if (xpk == NULL) {
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    unsigned char *der = NULL;
    int derlen = k2d(key, &der);
    if (derlen <= 0) {
        X509_PUBKEY_free(xpk);
        OPENSSL_free(der);
        ERR_raise(ERR_LIB_USER, ERR_R_EVP_LIB);
        return NULL;
    }

    if (!X509_PUBKEY_set0_param(xpk,
                                OBJ_nid2obj(key_nid),
                                V_ASN1_UNDEF,
                                NULL, /* keep params NULL as in km-openssl interop rule */
                                der, derlen)) {
        X509_PUBKEY_free(xpk);
        OPENSSL_free(der);
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    /* der kini dimiliki oleh xpk */
    return xpk;
}

/* ===== Helpers khusus untuk blok ini =================================== */

static int km_run_p2s_if_needed(key_to_paramstring_fn *p2s,
                                const void *key, int key_nid, int save_params,
                                void **out_str, int *out_type) {
    if (out_str)  *out_str  = NULL;
    if (out_type) *out_type = V_ASN1_UNDEF;

    if (p2s == NULL) return 1; /* tidak perlu p2s */

    if (!p2s(key, key_nid, save_params, out_str, out_type))
        return 0;

    return 1;
}

static int km_write_encrypted_p8_der(BIO *out,
                                     const void *key, int key_nid,
                                     void *str, int strtype,
                                     i2d_of_void *k2d,
                                     struct key2any_ctx_st *ctx) {
    int ok = 0;
    X509_SIG *p8 = key_to_encp8(key, key_nid, str, strtype, k2d, ctx);
    if (p8 != NULL) {
        ok = i2d_PKCS8_bio(out, p8);
        X509_SIG_free(p8);
    }
    return ok;
}

static int km_write_encrypted_p8_pem(BIO *out,
                                     const void *key, int key_nid,
                                     void *str, int strtype,
                                     i2d_of_void *k2d,
                                     struct key2any_ctx_st *ctx) {
    int ok = 0;
    X509_SIG *p8 = key_to_encp8(key, key_nid, str, strtype, k2d, ctx);
    if (p8 != NULL) {
        ok = PEM_write_bio_PKCS8(out, p8);
        X509_SIG_free(p8);
    }
    return ok;
}

static int km_write_plain_p8_der(BIO *out,
                                 const void *key, int key_nid,
                                 void *str, int strtype,
                                 i2d_of_void *k2d) {
    int ok = 0;
    PKCS8_PRIV_KEY_INFO *p8info = key_to_p8info(key, key_nid, str, strtype, k2d);
    if (p8info != NULL) {
        ok = i2d_PKCS8_PRIV_KEY_INFO_bio(out, p8info);
        PKCS8_PRIV_KEY_INFO_free(p8info);
    } else {
        /* ikut pola lama: free str bila p8info gagal dibuat */
        free_asn1_data(strtype, str);
    }
    return ok;
}

static int km_write_plain_p8_pem(BIO *out,
                                 const void *key, int key_nid,
                                 void *str, int strtype,
                                 i2d_of_void *k2d) {
    int ok = 0;
    PKCS8_PRIV_KEY_INFO *p8info = key_to_p8info(key, key_nid, str, strtype, k2d);
    if (p8info != NULL) {
        ok = PEM_write_bio_PKCS8_PRIV_KEY_INFO(out, p8info);
        PKCS8_PRIV_KEY_INFO_free(p8info);
    } else {
        /* ikut pola lama: free str bila p8info gagal dibuat */
        free_asn1_data(strtype, str);
    }
    return ok;
}

/* ====== PRIV-KEY: EPKI (encrypted PKCS#8) =============================== */

static int key_to_epki_der_priv_bio(BIO *out, const void *key, int key_nid,
                                    ossl_unused const char *pemname,
                                    key_to_paramstring_fn *p2s,
                                    i2d_of_void *k2d,
                                    struct key2any_ctx_st *ctx) {
    int ret = 0;
    void *str = NULL;
    int strtype = V_ASN1_UNDEF;

    KM_ENC_PRINTF("KM ENC provider: key_to_epki_der_priv_bio called\n");

    if (!ctx || !ctx->cipher_intent) return 0;

    if (!km_run_p2s_if_needed(p2s, key, key_nid, ctx->save_parameters, &str, &strtype))
        return 0;

    ret = km_write_encrypted_p8_der(out, key, key_nid, str, strtype, k2d, ctx);
    /* tidak perlu free_asn1_data di jalur sukses/gagal di sini:
       key_to_encp8() menangani p8info sendiri; str (params) dipakai/diabaikan
       sesuai perilaku versi awal. */
    return ret;
}

static int key_to_epki_pem_priv_bio(BIO *out, const void *key, int key_nid,
                                    ossl_unused const char *pemname,
                                    key_to_paramstring_fn *p2s,
                                    i2d_of_void *k2d,
                                    struct key2any_ctx_st *ctx) {
    int ret = 0;
    void *str = NULL;
    int strtype = V_ASN1_UNDEF;

    KM_ENC_PRINTF("KM ENC provider: key_to_epki_pem_priv_bio called\n");

    if (!ctx || !ctx->cipher_intent) return 0;

    if (!km_run_p2s_if_needed(p2s, key, key_nid, ctx->save_parameters, &str, &strtype))
        return 0;

    ret = km_write_encrypted_p8_pem(out, key, key_nid, str, strtype, k2d, ctx);
    return ret;
}

/* ====== PRIV-KEY: PKI (plain PKCS#8) ==================================== */

static int key_to_pki_der_priv_bio(BIO *out, const void *key, int key_nid,
                                   ossl_unused const char *pemname,
                                   key_to_paramstring_fn *p2s, i2d_of_void *k2d,
                                   struct key2any_ctx_st *ctx) {
    int ret = 0;
    void *str = NULL;
    int strtype = V_ASN1_UNDEF;

    KM_ENC_PRINTF("KM ENC provider: key_to_pki_der_priv_bio called\n");

    if (ctx && ctx->cipher_intent) {
        /* kompatibel: bila ingin encrypted, delegasikan ke EPKI */
        return key_to_epki_der_priv_bio(out, key, key_nid, pemname, p2s, k2d, ctx);
    }

    if (!km_run_p2s_if_needed(p2s, key, key_nid,
                              ctx ? ctx->save_parameters : 0,
                              &str, &strtype))
        return 0;

    ret = km_write_plain_p8_der(out, key, key_nid, str, strtype, k2d);
    return ret;
}

static int key_to_pki_pem_priv_bio(BIO *out, const void *key, int key_nid,
                                   ossl_unused const char *pemname,
                                   key_to_paramstring_fn *p2s, i2d_of_void *k2d,
                                   struct key2any_ctx_st *ctx) {
    int ret = 0;
    void *str = NULL;
    int strtype = V_ASN1_UNDEF;

    KM_ENC_PRINTF("KM ENC provider: key_to_pki_pem_priv_bio called\n");

    if (ctx && ctx->cipher_intent) {
        /* kompatibel: bila ingin encrypted, delegasikan ke EPKI */
        return key_to_epki_pem_priv_bio(out, key, key_nid, pemname, p2s, k2d, ctx);
    }

    if (!km_run_p2s_if_needed(p2s, key, key_nid,
                              ctx ? ctx->save_parameters : 0,
                              &str, &strtype))
        return 0;

    ret = km_write_plain_p8_pem(out, key, key_nid, str, strtype, k2d);
    return ret;
}

/* ====== PUB-KEY: SPKI (SubjectPublicKeyInfo) ============================= */

static int key_to_spki_der_pub_bio(BIO *out, const void *key, int key_nid,
                                   ossl_unused const char *pemname,
                                   key_to_paramstring_fn *p2s, i2d_of_void *k2d,
                                   struct key2any_ctx_st *ctx) {
    int ret = 0;
    X509_PUBKEY *xpk = NULL;
    void *str = NULL;
    int strtype = V_ASN1_UNDEF;

    KM_ENC_PRINTF("KM ENC provider: key_to_spki_der_pub_bio called\n");

    if (!km_run_p2s_if_needed(p2s, key, key_nid,
                              ctx ? ctx->save_parameters : 0,
                              &str, &strtype))
        return 0;

    xpk = kmx_key_to_pubkey(key, key_nid, str, strtype, k2d);
    if (xpk != NULL) {
        ret = i2d_X509_PUBKEY_bio(out, xpk);
        X509_PUBKEY_free(xpk);
    }
    /* catatan: versi awal tidak memanggil free_asn1_data() di jalur xpk==NULL.
       Kita pertahankan perilaku itu untuk kompatibilitas. */
    return ret;
}

static int key_to_spki_pem_pub_bio(BIO *out, const void *key, int key_nid,
                                   ossl_unused const char *pemname,
                                   key_to_paramstring_fn *p2s, i2d_of_void *k2d,
                                   struct key2any_ctx_st *ctx) {
    int ret = 0;
    X509_PUBKEY *xpk = NULL;
    void *str = NULL;
    int strtype = V_ASN1_UNDEF;

    KM_ENC_PRINTF("KM ENC provider: key_to_spki_pem_pub_bio called\n");

    if (!km_run_p2s_if_needed(p2s, key, key_nid,
                              ctx ? ctx->save_parameters : 0,
                              &str, &strtype))
        return 0;

    xpk = kmx_key_to_pubkey(key, key_nid, str, strtype, k2d);
    if (xpk != NULL) {
        ret = PEM_write_bio_X509_PUBKEY(out, xpk);
        /* sesuai komentar lama: “Also frees |str|” karena X509_PUBKEY_free
           ikut melepas buffer der yang diset via set0_param. */
        X509_PUBKEY_free(xpk);
    } else {
        /* jika gagal bikin xpk, kita yang membebaskan |str| */
        free_asn1_data(strtype, str);
    }
    return ret;
}

/* =======================================================================
 * prepare_kmx_params / kmx_spki_pub_to_der / kmx_pki_priv_to_der
 *  - tetap kompatibel secara semantik & output
 *  - alur lebih bersih, helper untuk cleanup & push
 * ======================================================================= */

static int prepare_kmx_params(const void *kmxkey, int nid, int save,
                              void **pstr, int *pstrtype) {
    (void)save; /* tidak berdampak di fungsi ini, tetap dipertahankan arg nya */

    ASN1_OBJECT *dup_params = NULL;
    const KMX_KEY *k = (const KMX_KEY *)kmxkey;

    KM_ENC_PRINTF3("KM ENC provider: prepare_kmx_params (nid=%d, tlsname=%s)\n",
                   nid, k ? k->tls_name : "(null)");

    if (k == NULL) {
        ERR_raise(ERR_LIB_USER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /* Jika tls_name ada, cek konsistensi dengan nid yang diberikan */
    if (k->tls_name) {
        int from_tls = OBJ_sn2nid(k->tls_name);
        if (from_tls == NID_undef || from_tls != nid) {
            ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_KEY);
            return 0;
        }
    }

    if (nid == NID_undef) {
        ERR_raise(ERR_LIB_USER, KMPROV_R_MISSING_OID);
        return 0;
    }

    /* Ambil OID, dan DUP supaya legal untuk di-free oleh caller */
    {
        const ASN1_OBJECT *base = OBJ_nid2obj(nid);
        if (base == NULL) {
            ERR_raise(ERR_LIB_USER, KMPROV_R_MISSING_OID);
            return 0;
        }
        dup_params = OBJ_dup(base);
        if (dup_params == NULL) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }

    if (OBJ_length(dup_params) <= 0) {
        ERR_raise(ERR_LIB_USER, KMPROV_R_MISSING_OID);
        ASN1_OBJECT_free(dup_params);
        return 0;
    }

    *pstr = dup_params;
    *pstrtype = V_ASN1_OBJECT;
    return 1;
}

/* ---------- helpers untuk SPKI/PKCS8 stack building ---------- */

static int kmx_push_seq_as_type(STACK_OF(ASN1_TYPE) *sk, ASN1_TYPE *t) {
    if (sk == NULL || t == NULL) return 0;
    if (!sk_ASN1_TYPE_push(sk, t)) {
        return 0;
    }
    return 1;
}

static int kmx_encode_bitstring_to_buf(const unsigned char *in, int inlen,
                                       unsigned char **out_der, size_t *out_len) {
    /* ikuti pola lama: bungkus data menjadi ASN1_BIT_STRING lalu i2d */
    ASN1_OCTET_STRING tmp; /* dipakai sbg “carrier” nilai/len seperti kode awal */
    int enc_len;

    if (!in || inlen <= 0 || !out_der || !out_len) return 0;

    tmp.data   = (unsigned char *)in; /* tidak dimiliki; jangan di-free */
    tmp.length = inlen;
    tmp.flags  = 8; /* meniru kode awal */

    enc_len = i2d_ASN1_BIT_STRING(&tmp, out_der);
    if (enc_len <= 0) return 0;

    *out_len = (size_t)enc_len;
    return 1;
}

static void kmx_secure_wipe_free(unsigned char *p, size_t n) {
    if (p) OPENSSL_secure_clear_free(p, n);
}

/* =======================================================================
 * SPKI (PublicKey) -> DER (untuk KEY_TYPE_CMP_SIG dan non-CMP)
 * ======================================================================= */
static int kmx_spki_pub_to_der(const void *vxkey, unsigned char **pder) {
    const KMX_KEY *kmxkey = (const KMX_KEY *)vxkey;
    unsigned char *dup_blob = NULL;

    KM_ENC_PRINTF("KM ENC provider: kmx_spki_pub_to_der called\n");

    if (kmxkey == NULL || kmxkey->pubkey == NULL) {
        ERR_raise(ERR_LIB_USER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /* Kasus sederhana: bukan composite-sig → copy langsung */
    if (kmxkey->keytype != KEY_TYPE_CMP_SIG) {
        dup_blob = OPENSSL_memdup(kmxkey->pubkey, kmxkey->pubkeylen);
        if (dup_blob == NULL) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        *pder = dup_blob;
        return (int)kmxkey->pubkeylen;
    }

    /* Kasus composite: bentuk SEQUENCE ANY dari komponen-komponen */
    {
        STACK_OF(ASN1_TYPE) *sk = sk_ASN1_TYPE_new_null();
        ASN1_TYPE          **atypes = NULL;
        ASN1_BIT_STRING    **bstrs  = NULL;
        unsigned char      **tmp_der = NULL;
        size_t              *tmp_len = NULL;
        int i, rc = -1; /* ikuti nilai error lama */

        if (sk == NULL) {
            return -1;
        }

        /* alokasi array kerja */
        atypes  = OPENSSL_zalloc(sizeof(*atypes)  * kmxkey->numkeys);
        bstrs   = OPENSSL_zalloc(sizeof(*bstrs)   * kmxkey->numkeys);
        tmp_der = OPENSSL_zalloc(sizeof(*tmp_der) * kmxkey->numkeys);
        tmp_len = OPENSSL_zalloc(sizeof(*tmp_len) * kmxkey->numkeys);
        if (!atypes || !bstrs || !tmp_der || !tmp_len) {
            rc = -1;
            goto spki_cmp_cleanup;
        }

        for (i = 0; i < kmxkey->numkeys; i++) {
            unsigned char *work = NULL;
            size_t worklen = 0;
            int buflen = kmxkey->pubkeylen_cmp[i];

            /* salin tiap komponen ke secure buf, lalu encode BIT STRING ke DER */
            work = OPENSSL_secure_malloc((size_t)buflen);
            if (!work) { rc = -1; goto spki_cmp_cleanup; }
            memcpy(work, kmxkey->comp_pubkey[i], (size_t)buflen);

            if (!kmx_encode_bitstring_to_buf(work, buflen, &tmp_der[i], &tmp_len[i])) {
                kmx_secure_wipe_free(work, (size_t)buflen);
                rc = -1; goto spki_cmp_cleanup;
            }

            /* bungkus ke ASN1_BIT_STRING dan ASN1_TYPE (SEQUENCE) sesuai pola lama */
            bstrs[i] = ASN1_BIT_STRING_new();
            atypes[i] = ASN1_TYPE_new();
            if (!bstrs[i] || !atypes[i]) {
                kmx_secure_wipe_free(work, (size_t)buflen);
                rc = -1; goto spki_cmp_cleanup;
            }

            ASN1_STRING_set(bstrs[i], tmp_der[i], (int)tmp_len[i]);
            ASN1_TYPE_set1(atypes[i], V_ASN1_SEQUENCE, bstrs[i]);

            if (!kmx_push_seq_as_type(sk, atypes[i])) {
                kmx_secure_wipe_free(work, (size_t)buflen);
                rc = -1; goto spki_cmp_cleanup;
            }

            kmx_secure_wipe_free(work, (size_t)buflen);
        }

        /* serialize SEQUENCE ANY ke *pder */
        rc = i2d_ASN1_SEQUENCE_ANY(sk, pder);

spki_cmp_cleanup:
        if (bstrs || atypes) {
            for (i = 0; i < kmxkey->numkeys; i++) {
                if (bstrs && bstrs[i]) {
                    OPENSSL_cleanse(bstrs[i]->data, bstrs[i]->length);
                    ASN1_BIT_STRING_free(bstrs[i]);
                }
                if (atypes && atypes[i]) {
                    if (atypes[i]->value.sequence) {
                        OPENSSL_cleanse(atypes[i]->value.sequence->data,
                                        atypes[i]->value.sequence->length);
                    }
                    /* ASN1_TYPE_free dipanggil oleh sk_*_pop_free di bawah */
                }
                if (tmp_der && tmp_der[i]) {
                    OPENSSL_clear_free(tmp_der[i], tmp_len[i]);
                }
            }
        }
        sk_ASN1_TYPE_pop_free(sk, ASN1_TYPE_free);
        OPENSSL_free(atypes);
        OPENSSL_free(bstrs);
        OPENSSL_free(tmp_der);
        OPENSSL_free(tmp_len);

        return rc; /* sama seperti versi awal: -1 jika gagal */
    }
}

/* =======================================================================
 * PKI (PrivateKeyInfo) -> DER (concat priv(+pub) untuk non-CMP; SEQ ANY utk CMP)
 * ======================================================================= */
static int kmx_pki_priv_to_der(const void *vxkey, unsigned char **pder) {
    KMX_KEY *kmxkey = (KMX_KEY *)vxkey;

    KM_ENC_PRINTF("KM ENC provider: kmx_pki_priv_to_der called\n");

    /* Validasi dasar: privkey wajib ada, dan jika diminta: pubkey juga */
    if (kmxkey == NULL || kmxkey->privkey == NULL
#ifndef NOPUBKEY_IN_PRIVKEY
        || kmxkey->pubkey == NULL
#endif
    ) {
        ERR_raise(ERR_LIB_USER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /* --------- kasus non-composite signature (bukan KEY_TYPE_CMP_SIG) ------ */
    if (kmxkey->keytype != KEY_TYPE_CMP_SIG) {
        unsigned char *buf = NULL;
        size_t buflen = 0, privlen = kmxkey->privkeylen;

        /* hybrid klasik+PQ (numkeys > 1): normalisasi panjang priv klasik */
        if (kmxkey->numkeys > 1) {
            uint32_t actual_priv = 0;
            size_t pq_priv_len =
                kmxkey->kmx_provider_ctx.kmx_qs_ctx.kem->length_secret_key;
            size_t space_for_classic =
                privlen - SIZE_OF_UINT32 - pq_priv_len;

            DECODE_UINT32(actual_priv, kmxkey->privkey);
            if (actual_priv > kmxkey->evp_info->length_private_key ||
                actual_priv > space_for_classic) {
                ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING);
                return 0;
            }
            /* kurangi padding klasik berlebih → samakan dengan kode lama */
            privlen -= (kmxkey->evp_info->length_private_key - actual_priv);
        }

#ifdef NOPUBKEY_IN_PRIVKEY
        buflen = privlen;
#else
        buflen = privlen + kmx_key_get_km_public_key_len(kmxkey);
#endif

        buf = OPENSSL_secure_malloc(buflen);
        if (!buf) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            return -1;
        }

        KM_ENC_PRINTF2("KM ENC provider: saving priv%s of length %zu\n",
#ifdef NOPUBKEY_IN_PRIVKEY
                       "key",
#else
                       "+pubkey",
#endif
                       buflen);

        /* copy priv */
        memcpy(buf, kmxkey->privkey, privlen);

#ifndef NOPUBKEY_IN_PRIVKEY
        /* tambahkan PQ pubkey sesuai arah reverse_share agar cocok dengan interop */
        if (kmxkey->reverse_share) {
            memcpy(buf + privlen, kmxkey->comp_pubkey[0],
                   kmx_key_get_km_public_key_len(kmxkey));
        } else {
            memcpy(buf + privlen, kmxkey->comp_pubkey[kmxkey->numkeys - 1],
                   kmx_key_get_km_public_key_len(kmxkey));
        }
#endif

        /* encode sebagai OCTET STRING (seperti versi awal) */
        {
            ASN1_OCTET_STRING oct;
            int enc_len;

            oct.data   = buf;
            oct.length = (int)buflen;
            oct.flags  = 0;

            enc_len = i2d_ASN1_OCTET_STRING(&oct, pder);
            if (enc_len < 0) {
                ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
                enc_len = 0; /* sinyal error */
            }
            kmx_secure_wipe_free(buf, buflen);
            return enc_len;
        }
    }

    /* ---------------- composite signature: kemas tiap sub-key ke SEQUENCE ANY ---- */
    {
        STACK_OF(ASN1_TYPE) *sk = sk_ASN1_TYPE_new_null();
        ASN1_TYPE               **atypes = NULL;
        ASN1_OCTET_STRING      **ostrings = NULL;
        unsigned char           **tmp_der = NULL;
        size_t                   *tmp_len = NULL;
        PKCS8_PRIV_KEY_INFO     *p8inf = NULL;
        int i, keybloblen = -1;

        if (!sk) return -1;

        atypes   = OPENSSL_zalloc(sizeof(*atypes)   * kmxkey->numkeys);
        ostrings = OPENSSL_zalloc(sizeof(*ostrings) * kmxkey->numkeys);
        tmp_der  = OPENSSL_zalloc(sizeof(*tmp_der)  * kmxkey->numkeys);
        tmp_len  = OPENSSL_zalloc(sizeof(*tmp_len)  * kmxkey->numkeys);
        if (!atypes || !ostrings || !tmp_der || !tmp_len) {
            keybloblen = -1;
            goto cmp_priv_cleanup;
        }

        for (i = 0; i < kmxkey->numkeys; i++) {
            int nid, version;
            void *pval;
            size_t buflen = 0;
            unsigned char *buf = NULL;
            char *name = NULL;

            atypes[i]   = ASN1_TYPE_new();
            ostrings[i] = ASN1_OCTET_STRING_new();
            p8inf       = PKCS8_PRIV_KEY_INFO_new();
            if (!atypes[i] || !ostrings[i] || !p8inf) {
                keybloblen = -1; goto cmp_priv_cleanup;
            }

            name = get_cmpname(OBJ_sn2nid(kmxkey->tls_name), i);
            if (name == NULL) {
                keybloblen = -1; goto cmp_priv_cleanup;
            }

            if (get_kmname_fromtls(name) == 0) {
                /* klasik (mis. RSA/EC) */
                nid = kmxkey->kmx_provider_ctx.kmx_evp_ctx->evp_info->keytype;

                if (nid == EVP_PKEY_RSA) {
                    /* ukuran nyata RSA disimpan di 4 byte pertama priv blob */
                    unsigned char *enc_len = (unsigned char *)OPENSSL_strndup(
                        (const char *)kmxkey->comp_privkey[i], 4);
                    if (!enc_len) { OPENSSL_free(name); keybloblen = -1; goto cmp_priv_cleanup; }
                    OPENSSL_cleanse(enc_len, 2);
                    DECODE_UINT32(buflen, enc_len);
                    buflen += 4;
                    OPENSSL_free(enc_len);

                    if (buflen > kmxkey->privkeylen_cmp[i]) {
                        OPENSSL_free(name);
                        keybloblen = -1; goto cmp_priv_cleanup;
                    }
                } else {
                    buflen = kmxkey->privkeylen_cmp[i];
                }
            } else {
                /* PQ: gabungkan priv+pub sesuai pola lama */
                nid = OBJ_sn2nid(name);
                buflen = (size_t)kmxkey->privkeylen_cmp[i] +
                         (size_t)kmxkey->pubkeylen_cmp[i];
            }

            buf = OPENSSL_secure_malloc(buflen);
            if (!buf) {
                OPENSSL_free(name);
                ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
                keybloblen = -1; goto cmp_priv_cleanup;
            }

            if (get_kmname_fromtls(name) != 0) {
                /* PQ: priv || pub */
                memcpy(buf, kmxkey->comp_privkey[i], (size_t)kmxkey->privkeylen_cmp[i]);
                memcpy(buf + kmxkey->privkeylen_cmp[i],
                       kmxkey->comp_pubkey[i], (size_t)kmxkey->pubkeylen_cmp[i]);
            } else {
                /* klasik (RSA mungkin pakai buflen yang berbeda) */
                memcpy(buf, kmxkey->comp_privkey[i], buflen);
            }

            /* Tambahkan parameter kurva untuk EC jika perlu */
            if (nid == EVP_PKEY_EC) {
                version = V_ASN1_OBJECT;
                pval = (void *)OBJ_nid2obj(
                    kmxkey->kmx_provider_ctx.kmx_evp_ctx->evp_info->nid);
            } else {
                version = V_ASN1_UNDEF;
                pval = NULL;
            }

            if (!PKCS8_pkey_set0(p8inf, OBJ_nid2obj(nid), 0, version, pval, buf, (int)buflen)) {
                /* buf dimiliki p8inf jika set0 sukses; disini gagal → kita free sendiri */
                OPENSSL_cleanse(buf, buflen);
                PKCS8_PRIV_KEY_INFO_free(p8inf); p8inf = NULL;
                OPENSSL_free(name);
                keybloblen = -1; goto cmp_priv_cleanup;
            }

            /* Serialize PKCS8 untuk sub-key ini → temp DER */
            tmp_len[i] = (size_t)i2d_PKCS8_PRIV_KEY_INFO(p8inf, &tmp_der[i]);
            if (tmp_len[i] == 0) {
                OPENSSL_free(name);
                keybloblen = -1; goto cmp_priv_cleanup;
            }

            /* simpan DER ke ASN1_OCTET_STRING, bungkus ke ASN1_TYPE (SEQUENCE) */
            ASN1_STRING_set(ostrings[i], tmp_der[i], (int)tmp_len[i]);
            ASN1_TYPE_set1(atypes[i], V_ASN1_SEQUENCE, ostrings[i]);

            if (!kmx_push_seq_as_type(sk, atypes[i])) {
                OPENSSL_free(name);
                keybloblen = -1; goto cmp_priv_cleanup;
            }

            OPENSSL_free(name);
            /* buf sudah dimiliki p8inf; kita cleanse setelah selesai */
            OPENSSL_cleanse(buf, buflen);
            PKCS8_PRIV_KEY_INFO_free(p8inf); p8inf = NULL;
        }

        keybloblen = i2d_ASN1_SEQUENCE_ANY(sk, pder);

cmp_priv_cleanup:
        if (ostrings || atypes) {
            for (i = 0; i < kmxkey->numkeys; i++) {
                if (ostrings && ostrings[i]) {
                    OPENSSL_cleanse(ostrings[i]->data, ostrings[i]->length);
                    ASN1_OCTET_STRING_free(ostrings[i]);
                }
                if (atypes && atypes[i]) {
                    if (atypes[i]->value.sequence) {
                        OPENSSL_cleanse(atypes[i]->value.sequence->data,
                                        atypes[i]->value.sequence->length);
                    }
                    /* ASN1_TYPE_free dipanggil oleh pop_free di bawah */
                }
                if (tmp_der && tmp_der[i]) {
                    OPENSSL_clear_free(tmp_der[i], tmp_len[i]);
                }
            }
        }
        sk_ASN1_TYPE_pop_free(sk, ASN1_TYPE_free);
        OPENSSL_free(atypes);
        OPENSSL_free(ostrings);
        OPENSSL_free(tmp_der);
        OPENSSL_free(tmp_len);
        if (p8inf) PKCS8_PRIV_KEY_INFO_free(p8inf);

        return keybloblen;
    }
}


#define kmx_epki_priv_to_der kmx_pki_priv_to_der

/*
 * KMX only has PKCS#8 / SubjectPublicKeyInfo
 * representation, so we don't define
 * kmx_type_specific_[priv,pub,params]_to_der.
 */

#define kmx_check_key_type NULL

// KM provider uses NIDs generated at load time as EVP_type identifiers
// so initially this must be 0 and set to a real value by OBJ_sn2nid later
///// KM_TEMPLATE_FRAGMENT_ENCODER_DEFINES_START
#define dilithium2_evp_type 0
#define dilithium2_input_type "dilithium2"
#define dilithium2_pem_type "dilithium2"

#define dilithium3_evp_type 0
#define dilithium3_input_type "dilithium3"
#define dilithium3_pem_type "dilithium3"

#define dilithium5_evp_type 0
#define dilithium5_input_type "dilithium5"
#define dilithium5_pem_type "dilithium5"

#define mldsa44_evp_type 0
#define mldsa44_input_type "mldsa44"
#define mldsa44_pem_type "mldsa44"

#define mldsa65_evp_type 0
#define mldsa65_input_type "mldsa65"
#define mldsa65_pem_type "mldsa65"

#define mldsa87_evp_type 0
#define mldsa87_input_type "mldsa87"
#define mldsa87_pem_type "mldsa87"

#define sphincssha2128fsimple_evp_type 0
#define sphincssha2128fsimple_input_type "sphincssha2128fsimple"
#define sphincssha2128fsimple_pem_type "sphincssha2128fsimple"

#define sphincssha2128ssimple_evp_type 0
#define sphincssha2128ssimple_input_type "sphincssha2128ssimple"
#define sphincssha2128ssimple_pem_type "sphincssha2128ssimple"

#define sphincssha2192fsimple_evp_type 0
#define sphincssha2192fsimple_input_type "sphincssha2192fsimple"
#define sphincssha2192fsimple_pem_type "sphincssha2192fsimple"

#define sphincsshake128fsimple_evp_type 0
#define sphincsshake128fsimple_input_type "sphincsshake128fsimple"
#define sphincsshake128fsimple_pem_type "sphincsshake128fsimple"

#define kyber512_evp_type 0
#define kyber512_input_type "kyber512"
#define kyber512_pem_type "kyber512"
#define x25519_kyber512_evp_type 0
#define x25519_kyber512_input_type "x25519_kyber512"
#define x25519_kyber512_pem_type "x25519_kyber512"

#define kyber768_evp_type 0
#define kyber768_input_type "kyber768"
#define kyber768_pem_type "kyber768"
#define x25519_kyber768_evp_type 0
#define x25519_kyber768_input_type "x25519_kyber768"
#define x25519_kyber768_pem_type "x25519_kyber768"

#define kyber1024_evp_type 0
#define kyber1024_input_type "kyber1024"
#define kyber1024_pem_type "kyber1024"

#define mlkem512_evp_type 0
#define mlkem512_input_type "mlkem512"
#define mlkem512_pem_type "mlkem512"
#define x25519_mlkem512_evp_type 0
#define x25519_mlkem512_input_type "x25519_mlkem512"
#define x25519_mlkem512_pem_type "x25519_mlkem512"

#define mlkem768_evp_type 0
#define mlkem768_input_type "mlkem768"
#define mlkem768_pem_type "mlkem768"
#define X25519MLKEM768_evp_type 0
#define X25519MLKEM768_input_type "X25519MLKEM768"
#define X25519MLKEM768_pem_type "X25519MLKEM768"

#define mlkem1024_evp_type 0
#define mlkem1024_input_type "mlkem1024"
#define mlkem1024_pem_type "mlkem1024"
///// KM_TEMPLATE_FRAGMENT_ENCODER_DEFINES_END

/* ---------------------------------------------------------------------- */

/* =======================================================================
 * key2any_* (newctx, freectx, settable, set_ctx_params,
 *                     check_selection, encode)
 *  - Semantik & output tetap sama
 *  - Alur lebih rapih & minim duplikasi
 * ======================================================================= */

static OSSL_FUNC_decoder_newctx_fn  key2any_newctx;
static OSSL_FUNC_decoder_freectx_fn key2any_freectx;

/* ---------- small param helpers ---------- */

static const OSSL_PARAM *km_locate_const(const OSSL_PARAM params[], const char *key) {
    return params ? OSSL_PARAM_locate_const(params, key) : NULL;
}

static int km_get_utf8_ptr(const OSSL_PARAM *p, const char **out) {
    if (!p) { *out = NULL; return 1; }
    return OSSL_PARAM_get_utf8_string_ptr(p, out);
}

static int km_get_int(const OSSL_PARAM *p, int *out) {
    return p ? OSSL_PARAM_get_int(p, out) : 1; /* tanpa param = no-op */
}

/* ---------- ctx lifecycle ---------- */

static void *key2any_newctx(void *provctx) {
    struct key2any_ctx_st *ctx = OPENSSL_zalloc(sizeof(*ctx));

    KM_ENC_PRINTF("KM ENC provider: key2any_newctx called\n");

    if (!ctx) return NULL;
    ctx->provctx = (PROV_KM_CTX *)provctx;
    ctx->save_parameters = 1;          /* default sama seperti versi awal */
    ctx->cipher_intent   = 0;          /* default: tidak enkripsi */
    ctx->cipher          = NULL;
    ctx->pwcb            = NULL;
    ctx->pwcbarg         = NULL;
    return ctx;
}

static void key2any_freectx(void *vctx) {
    struct key2any_ctx_st *ctx = (struct key2any_ctx_st *)vctx;

    KM_ENC_PRINTF("KM ENC provider: key2any_freectx called\n");

    if (!ctx) return;
    EVP_CIPHER_free(ctx->cipher);
    OPENSSL_free(ctx);
}

/* ---------- ctx params (schema) ---------- */

static const OSSL_PARAM *key2any_settable_ctx_params(ossl_unused void *provctx) {
    /* catatan: urutan berbeda → tampilan beda, fungsi sama */
    static const OSSL_PARAM settables[] = {
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_PROPERTIES,    NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_CIPHER,        NULL, 0),
        OSSL_PARAM_int        (OSSL_ENCODER_PARAM_SAVE_PARAMETERS, NULL),
        OSSL_PARAM_END
    };

    KM_ENC_PRINTF("KM ENC provider: key2any_settable_ctx_params called\n");

    return settables;
}

/* ---------- ctx params (setter) ---------- */

static int key2any_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    struct key2any_ctx_st *ctx = (struct key2any_ctx_st *)vctx;

    KM_ENC_PRINTF("KM ENC provider: key2any_set_ctx_params called\n");

    if (!ctx) return 0;

    OSSL_LIB_CTX *libctx = ctx->provctx ? ctx->provctx->libctx : NULL;
    const OSSL_PARAM *cipherp      = km_locate_const(params, OSSL_ENCODER_PARAM_CIPHER);
    const OSSL_PARAM *propsp       = km_locate_const(params, OSSL_ENCODER_PARAM_PROPERTIES);
    const OSSL_PARAM *save_paramsp = km_locate_const(params, OSSL_ENCODER_PARAM_SAVE_PARAMETERS);

    /* --- cipher & properties --- */
    if (cipherp) {
        const char *ciphername = NULL;
        const char *props      = NULL;

        if (!km_get_utf8_ptr(cipherp, &ciphername)) return 0;
        if (propsp && !km_get_utf8_ptr(propsp, &props)) return 0;

        KM_ENC_PRINTF2(" setting cipher: %s\n", ciphername ? ciphername : "(null)");

        /* reset state dulu */
        EVP_CIPHER_free(ctx->cipher);
        ctx->cipher = NULL;
        ctx->cipher_intent = (ciphername != NULL);

        if (ciphername != NULL) {
            /* fetch sama seperti versi awal */
            ctx->cipher = EVP_CIPHER_fetch(libctx, ciphername, props);
            if (ctx->cipher == NULL) return 0;
        }
    }

    /* --- save_parameters --- */
    if (save_paramsp) {
        if (!km_get_int(save_paramsp, &ctx->save_parameters))
            return 0;
    }

    KM_ENC_PRINTF2(" cipher set to %p\n", ctx->cipher);
    /* tidak ada cipher → no-op; tetap sukses seperti versi awal */
    return 1;
}

/* ---------- selection check ---------- */

static int key2any_check_selection(int selection, int selection_mask) {
    /* 0 artinya “guessing allowed” → selalu ok */
    if (selection == 0)
        return 1;

    KM_ENC_PRINTF3("KM ENC provider: key2any_check_selection sel=%d mask=%d\n",
                   selection, selection_mask);

    /* jaga kompatibilitas: cek bertingkat sesuai urutan “level” */
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        return (selection_mask & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        return (selection_mask & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;

    if (selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)
        return (selection_mask & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0;

    /* default fallback */
    return 0;
}

/* ---------- encode driver ---------- */

static int key2any_encode(struct key2any_ctx_st *ctx, OSSL_CORE_BIO *cout,
                          const void *key, const char *typestr,
                          const char *pemname, key_to_der_fn *writer,
                          OSSL_PASSPHRASE_CALLBACK *pwcb, void *pwcbarg,
                          key_to_paramstring_fn *key2paramstring,
                          i2d_of_void *key2der) {
    int ret = 0;

    KM_ENC_PRINTF3("KM ENC provider: key2any_encode type=%s pemname=%s\n",
                   typestr ? typestr : "(null)",
                   pemname ? pemname : "(null)");

    if (!ctx || !cout || !key || !typestr || !writer) {
        ERR_raise(ERR_LIB_USER, ERR_R_PASSED_INVALID_ARGUMENT);
        KM_ENC_PRINTF(" encode result: 0 (bad args)\n");
        return 0;
    }

    /* OBJ_sn2nid sama seperti versi awal */
    const int nid = OBJ_sn2nid(typestr);
    if (nid <= 0) {
        ERR_raise(ERR_LIB_USER, ERR_R_PASSED_NULL_PARAMETER);
        KM_ENC_PRINTF(" encode result: 0 (bad nid)\n");
        return 0;
    }

    /* BIO wrapper dari core */
    BIO *out = km_bio_new_from_core_bio(ctx->provctx, cout);
    if (!out) {
        KM_ENC_PRINTF(" encode result: 0 (no BIO)\n");
        return 0;
    }

    /* set callback pw (digunakan ketika encrypted PKCS#8) */
    ctx->pwcb    = pwcb;
    ctx->pwcbarg = pwcbarg;

    ret = writer(out, key, nid, pemname, key2paramstring, key2der, ctx);

    BIO_free(out);

    KM_ENC_PRINTF2(" encode result: %d\n", ret);
    return ret;
}


#define DO_PRIVATE_KEY_selection_mask OSSL_KEYMGMT_SELECT_PRIVATE_KEY
#define DO_PRIVATE_KEY(impl, type, kind, output)                               \
    if ((selection & DO_PRIVATE_KEY_selection_mask) != 0)                      \
        return key2any_encode(                                                 \
            ctx, cout, key, impl##_pem_type, impl##_pem_type " PRIVATE KEY",   \
            key_to_##kind##_##output##_priv_bio, cb, cbarg,                    \
            prepare_##type##_params, type##_##kind##_priv_to_der);

#define DO_PUBLIC_KEY_selection_mask OSSL_KEYMGMT_SELECT_PUBLIC_KEY
#define DO_PUBLIC_KEY(impl, type, kind, output)                                \
    if ((selection & DO_PUBLIC_KEY_selection_mask) != 0)                       \
        return key2any_encode(                                                 \
            ctx, cout, key, impl##_pem_type, impl##_pem_type " PUBLIC KEY",    \
            key_to_##kind##_##output##_pub_bio, cb, cbarg,                     \
            prepare_##type##_params, type##_##kind##_pub_to_der);

#define DO_PARAMETERS_selection_mask OSSL_KEYMGMT_SELECT_ALL_PARAMETERS
#define DO_PARAMETERS(impl, type, kind, output)                                \
    if ((selection & DO_PARAMETERS_selection_mask) != 0)                       \
        return key2any_encode(ctx, cout, key, impl##_pem_type,                 \
                              impl##_pem_type " PARAMETERS",                   \
                              key_to_##kind##_##output##_param_bio, NULL,      \
                              NULL, NULL, type##_##kind##_params_to_der);

#define DO_PrivateKeyInfo_selection_mask DO_PRIVATE_KEY_selection_mask
#define DO_PrivateKeyInfo(impl, type, output)                                  \
    DO_PRIVATE_KEY(impl, type, pki, output)

#define DO_EncryptedPrivateKeyInfo_selection_mask DO_PRIVATE_KEY_selection_mask
#define DO_EncryptedPrivateKeyInfo(impl, type, output)                         \
    DO_PRIVATE_KEY(impl, type, epki, output)

/* SubjectPublicKeyInfo is a structure for public keys only */
#define DO_SubjectPublicKeyInfo_selection_mask DO_PUBLIC_KEY_selection_mask
#define DO_SubjectPublicKeyInfo(impl, type, output)                            \
    DO_PUBLIC_KEY(impl, type, spki, output)

#define DO_type_specific_params_selection_mask DO_PARAMETERS_selection_mask
#define DO_type_specific_params(impl, type, output)                            \
    DO_PARAMETERS(impl, type, type_specific, output)
#define DO_type_specific_keypair_selection_mask                                \
    (DO_PRIVATE_KEY_selection_mask | DO_PUBLIC_KEY_selection_mask)
#define DO_type_specific_keypair(impl, type, output)                           \
    DO_PRIVATE_KEY(impl, type, type_specific, output)                          \
    DO_PUBLIC_KEY(impl, type, type_specific, output)
#define DO_type_specific_selection_mask                                        \
    (DO_type_specific_keypair_selection_mask |                                 \
     DO_type_specific_params_selection_mask)
#define DO_type_specific(impl, type, output)                                   \
    DO_type_specific_keypair(impl, type, output)                               \
        DO_type_specific_params(impl, type, output)
#define DO_type_specific_no_pub_selection_mask                                 \
    (DO_PRIVATE_KEY_selection_mask | DO_PARAMETERS_selection_mask)
#define DO_type_specific_no_pub(impl, type, output)                            \
    DO_PRIVATE_KEY(impl, type, type_specific, output)                          \
    DO_type_specific_params(impl, type, output)

#define MAKE_ENCODER(kmkemhyb, impl, type, kind, output)                      \
    static OSSL_FUNC_encoder_import_object_fn                                  \
        impl##_to_##kind##_##output##_import_object;                           \
    static OSSL_FUNC_encoder_free_object_fn                                    \
        impl##_to_##kind##_##output##_free_object;                             \
    static OSSL_FUNC_encoder_encode_fn impl##_to_##kind##_##output##_encode;   \
                                                                               \
    static void *impl##_to_##kind##_##output##_import_object(                  \
        void *vctx, int selection, const OSSL_PARAM params[]) {                \
        struct key2any_ctx_st *ctx = vctx;                                     \
                                                                               \
        KM_ENC_PRINTF("KM ENC provider: _import_object called\n");           \
        return km_prov_import_key(                                            \
            km##kmkemhyb##_##impl##_keymgmt_functions, ctx->provctx,         \
            selection, params);                                                \
    }                                                                          \
    static void impl##_to_##kind##_##output##_free_object(void *key) {         \
        KM_ENC_PRINTF("KM ENC provider: _free_object called\n");             \
        km_prov_free_key(km##kmkemhyb##_##impl##_keymgmt_functions, key);   \
    }                                                                          \
    static int impl##_to_##kind##_##output##_does_selection(void *ctx,         \
                                                            int selection) {   \
        KM_ENC_PRINTF("KM ENC provider: _does_selection called\n");          \
        return key2any_check_selection(selection, DO_##kind##_selection_mask); \
    }                                                                          \
    static int impl##_to_##kind##_##output##_encode(                           \
        void *ctx, OSSL_CORE_BIO *cout, const void *key,                       \
        const OSSL_PARAM key_abstract[], int selection,                        \
        OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg) {                           \
        /* We don't deal with abstract objects */                              \
        KM_ENC_PRINTF("KM ENC provider: _encode called\n");                  \
        if (key_abstract != NULL) {                                            \
            ERR_raise(ERR_LIB_USER, ERR_R_PASSED_INVALID_ARGUMENT);            \
            return 0;                                                          \
        }                                                                      \
        DO_##kind(impl, type, output)                                          \
                                                                               \
            ERR_raise(ERR_LIB_USER, ERR_R_PASSED_INVALID_ARGUMENT);            \
        return 0;                                                              \
    }                                                                          \
    const OSSL_DISPATCH                                                        \
        km_##impl##_to_##kind##_##output##_encoder_functions[] = {            \
            {OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))key2any_newctx},        \
            {OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))key2any_freectx},      \
            {OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,                            \
             (void (*)(void))key2any_settable_ctx_params},                     \
            {OSSL_FUNC_ENCODER_SET_CTX_PARAMS,                                 \
             (void (*)(void))key2any_set_ctx_params},                          \
            {OSSL_FUNC_ENCODER_DOES_SELECTION,                                 \
             (void (*)(void))impl##_to_##kind##_##output##_does_selection},    \
            {OSSL_FUNC_ENCODER_IMPORT_OBJECT,                                  \
             (void (*)(void))impl##_to_##kind##_##output##_import_object},     \
            {OSSL_FUNC_ENCODER_FREE_OBJECT,                                    \
             (void (*)(void))impl##_to_##kind##_##output##_free_object},       \
            {OSSL_FUNC_ENCODER_ENCODE,                                         \
             (void (*)(void))impl##_to_##kind##_##output##_encode},            \
            {0, NULL}}

/* ---------------------------------------------------------------------- */

/* steal from openssl/providers/implementations/encode_decode/encode_key2text.c
 */

#define LABELED_BUF_PRINT_WIDTH 15

/* =======================================================================
 * print_labeled_buf / kmx_to_text / key2text_* (drop-in compatible)
 *  - Semantik identik, tampilan dan struktur kode berbeda
 * ======================================================================= */

static int km_hex_labeled(BIO *out, const char *label,
                          const unsigned char *buf, size_t len) {
    size_t i;

    if (out == NULL || label == NULL || (len && buf == NULL)) {
        ERR_raise(ERR_LIB_USER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (BIO_printf(out, "%s\n", label) <= 0) return 0;

    for (i = 0; i < len; ++i) {
        if ((i % LABELED_BUF_PRINT_WIDTH) == 0) {
            if (i && BIO_printf(out, "\n") <= 0) return 0;
            if (BIO_printf(out, "    ") <= 0) return 0;
        }
        if (BIO_printf(out, "%02x%s", buf[i], (i + 1 == len) ? "" : ":") <= 0)
            return 0;
    }
    if (BIO_printf(out, "\n") <= 0) return 0;
    return 1;
}

/* kompat untuk pemanggil lama */
static int print_labeled_buf(BIO *out, const char *label,
                             const unsigned char *buf, size_t buflen) {
    return km_hex_labeled(out, label, buf, buflen);
}

/* -------------------- helpers untuk kmx_to_text -------------------- */

static int km_write_header(BIO *out, const char *tlsname, int is_priv, int keytype) {
    const char *role   = is_priv ? "private" : "public";
    const char *flavor = NULL;

    switch (keytype) {
        case KEY_TYPE_SIG:
        case KEY_TYPE_KEM:       flavor = "";               break;
        case KEY_TYPE_ECP_HYB_KEM:
        case KEY_TYPE_ECX_HYB_KEM:
        case KEY_TYPE_HYB_SIG:   flavor = " hybrid";        break;
        case KEY_TYPE_CMP_SIG:   flavor = " composite";     break;
        default:
            ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_KEY);
            return 0;
    }
    return BIO_printf(out, "%s%s %s:\n", tlsname, flavor, role) > 0;
}

static int km_decode_rsa_priv_len(const unsigned char *p, size_t maxlen, uint32_t *out_len) {
    /* meniru perilaku awal: panjang RSA asli tersimpan pada 4 byte di depan */
    if (!p || !out_len || maxlen < 4) return 0;
    unsigned char *enc_len = (unsigned char *)OPENSSL_strndup((const char *)p, 4);
    if (!enc_len) return 0;
    OPENSSL_cleanse(enc_len, 2); /* pertahankan detail orisinal */
    DECODE_UINT32(*out_len, enc_len);
    *out_len += 4;
    OPENSSL_free(enc_len);
    return 1;
}

static int km_print_composite_chunks(BIO *out, const KMX_KEY *okey, int is_priv) {
    for (int i = 0; i < okey->numkeys; ++i) {
        char *name = get_cmpname(OBJ_sn2nid(okey->tls_name), i);
        if (!name) {
            ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_KEY);
            return 0;
        }

        char label[200];
        (void)BIO_snprintf(label, sizeof(label), "%s key material:", name);

        if (is_priv) {
            uint32_t privlen = 0;
            if (get_kmname_fromtls(name) == 0 /* classical */ &&
                okey->kmx_provider_ctx.kmx_evp_ctx->evp_info->keytype == EVP_PKEY_RSA) {
                if (!km_decode_rsa_priv_len(okey->comp_privkey[i],
                                            okey->privkeylen_cmp[i], &privlen) ||
                    privlen > okey->privkeylen_cmp[i]) {
                    OPENSSL_free(name);
                    ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING);
                    return 0;
                }
            } else {
                privlen = okey->privkeylen_cmp[i];
            }

            if (!km_hex_labeled(out, label, okey->comp_privkey[i], privlen)) {
                OPENSSL_free(name);
                return 0;
            }
        } else {
            if (!km_hex_labeled(out, label,
                                okey->comp_pubkey[i], okey->pubkeylen_cmp[i])) {
                OPENSSL_free(name);
                return 0;
            }
        }

        OPENSSL_free(name);
    }
    return 1;
}

static int km_print_hybrid_split_priv(BIO *out, const KMX_KEY *okey) {
    /* classic length disimpan pada awal blob priv, sisanya PQ */
    uint32_t classic_len = 0;
    size_t pq_fixed = okey->kmx_provider_ctx.kmx_qs_ctx.kem->length_secret_key;
    size_t space_for_classic = okey->privkeylen - SIZE_OF_UINT32 - pq_fixed;

    if (!okey->privkey) return 0;
    DECODE_UINT32(classic_len, okey->privkey);
    if (classic_len > space_for_classic) {
        ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING);
        return 0;
    }

    char label[200];
    (void)BIO_snprintf(label, sizeof(label), "%s key material:", OBJ_nid2sn(okey->evp_info->nid));

    if (!km_hex_labeled(out, label, okey->comp_privkey[0], classic_len))
        return 0;

    return km_hex_labeled(out, "PQ key material:",
                          okey->comp_privkey[okey->numkeys - 1],
                          okey->privkeylen - classic_len - SIZE_OF_UINT32);
}

static int km_print_hybrid_split_pub(BIO *out, const KMX_KEY *okey) {
    uint32_t classic_len = 0;
    size_t pq_fixed = okey->kmx_provider_ctx.kmx_qs_ctx.kem->length_public_key;
    size_t space_for_classic = okey->pubkeylen - SIZE_OF_UINT32 - pq_fixed;

    if (!okey->pubkey) return 0;
    DECODE_UINT32(classic_len, okey->pubkey);
    if (classic_len > space_for_classic) {
        ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING);
        return 0;
    }

    char label[200];
    (void)BIO_snprintf(label, sizeof(label), "%s key material:", OBJ_nid2sn(okey->evp_info->nid));

    if (!km_hex_labeled(out, label, okey->comp_pubkey[0], classic_len))
        return 0;

    return km_hex_labeled(out, "PQ key material:",
                          okey->comp_pubkey[okey->numkeys - 1],
                          okey->pubkeylen - classic_len - SIZE_OF_UINT32);
}

/* -------------------- main printer -------------------- */

static int kmx_to_text(BIO *out, const void *key, int selection) {
    KMX_KEY *okey = (KMX_KEY *)key;

    if (!out || !okey) {
        ERR_raise(ERR_LIB_USER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    const int want_priv = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
    const int want_pub  = (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)  != 0;

    /* --- header dan validasi berdasarkan selection --- */
    if (want_priv) {
        if (!okey->privkey) {
            ERR_raise(ERR_LIB_USER, PROV_R_NOT_A_PRIVATE_KEY);
            return 0;
        }
        if (!km_write_header(out, okey->tls_name, 1, okey->keytype))
            return 0;
    } else if (want_pub) {
        if (!okey->pubkey) {
            ERR_raise(ERR_LIB_USER, PROV_R_NOT_A_PUBLIC_KEY);
            return 0;
        }
        if (!km_write_header(out, okey->tls_name, 0, okey->keytype))
            return 0;
    }

    /* --- isi sesuai tipe & selection --- */
    if (want_priv && okey->privkey) {
        if (okey->keytype == KEY_TYPE_CMP_SIG) {
            if (!km_print_composite_chunks(out, okey, 1)) return 0;
        } else if (okey->numkeys > 1) { /* hybrid */
            if (!km_print_hybrid_split_priv(out, okey)) return 0;
        } else { /* plain PQ */
            if (!km_hex_labeled(out, "PQ key material:",
                                okey->comp_privkey[okey->numkeys - 1],
                                okey->privkeylen))
                return 0;
        }
    }

    if (want_pub && okey->pubkey) {
        if (okey->keytype == KEY_TYPE_CMP_SIG) {
            if (!km_print_composite_chunks(out, okey, 0)) return 0;
        } else if (okey->numkeys > 1) { /* hybrid */
            if (!km_print_hybrid_split_pub(out, okey)) return 0;
        } else { /* PQ only */
            if (!km_hex_labeled(out, "PQ key material:",
                                okey->comp_pubkey[okey->numkeys - 1],
                                okey->pubkeylen))
                return 0;
        }
    }

    return 1;
}

/* -------------------- text encoder ctx wrappers -------------------- */

static void *key2text_newctx(void *provctx) {
    KM_ENC_PRINTF("KM ENC provider: key2text_newctx called\n");
    return provctx;
}

static void key2text_freectx(ossl_unused void *vctx) {
    KM_ENC_PRINTF("KM ENC provider: key2text_freectx called\n");
}

/* keep signature/behavior; tambah guard & logging ringan */
static int key2text_encode(void *vctx, const void *key, int selection, OSSL_CORE_BIO *cout,
                           int (*key2text)(BIO *out, const void *key, int selection),
                           OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg) {
    (void)cb; (void)cbarg; /* tidak dipakai di path text */

    BIO *out = km_bio_new_from_core_bio(vctx, cout);
    if (!out) return 0;

    KM_ENC_PRINTF("KM ENC provider: key2text_encode called\n");

    /* panggil printer actual */
    const int ok = key2text(out, key, selection);
    BIO_free(out);
    return ok;
}


#define MAKE_TEXT_ENCODER(kmkemhyb, impl)                                     \
    static OSSL_FUNC_encoder_import_object_fn impl##2text_import_object;       \
    static OSSL_FUNC_encoder_free_object_fn impl##2text_free_object;           \
    static OSSL_FUNC_encoder_encode_fn impl##2text_encode;                     \
                                                                               \
    static void *impl##2text_import_object(void *ctx, int selection,           \
                                           const OSSL_PARAM params[]) {        \
        return km_prov_import_key(                                            \
            km##kmkemhyb##_##impl##_keymgmt_functions, ctx, selection,       \
            params);                                                           \
    }                                                                          \
    static void impl##2text_free_object(void *key) {                           \
        km_prov_free_key(km##kmkemhyb##_##impl##_keymgmt_functions, key);   \
    }                                                                          \
    static int impl##2text_encode(                                             \
        void *vctx, OSSL_CORE_BIO *cout, const void *key,                      \
        const OSSL_PARAM key_abstract[], int selection,                        \
        OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg) {                           \
        /* We don't deal with abstract objects */                              \
        if (key_abstract != NULL) {                                            \
            ERR_raise(ERR_LIB_USER, ERR_R_PASSED_INVALID_ARGUMENT);            \
            return 0;                                                          \
        }                                                                      \
        return key2text_encode(vctx, key, selection, cout, kmx_to_text, cb,   \
                               cbarg);                                         \
    }                                                                          \
    const OSSL_DISPATCH km_##impl##_to_text_encoder_functions[] = {           \
        {OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))key2text_newctx},           \
        {OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))key2text_freectx},         \
        {OSSL_FUNC_ENCODER_IMPORT_OBJECT,                                      \
         (void (*)(void))impl##2text_import_object},                           \
        {OSSL_FUNC_ENCODER_FREE_OBJECT,                                        \
         (void (*)(void))impl##2text_free_object},                             \
        {OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))impl##2text_encode},        \
        {0, NULL}}

/*
 * Replacements for i2d_{TYPE}PrivateKey, i2d_{TYPE}PublicKey,
 * i2d_{TYPE}params, as they exist.
 */

/*
 * PKCS#8 and SubjectPublicKeyInfo support.  This may duplicate some of the
 * implementations specified above, but are more specific.
 * The SubjectPublicKeyInfo implementations also replace the
 * PEM_write_bio_{TYPE}_PUBKEY functions.
 * For PEM, these are expected to be used by PEM_write_bio_PrivateKey(),
 * PEM_write_bio_PUBKEY() and PEM_write_bio_Parameters().
 */
///// KM_TEMPLATE_FRAGMENT_ENCODER_MAKE_START
// #ifdef KM_KEM_ENCODERS
MAKE_ENCODER(, kyber512, kmx, EncryptedPrivateKeyInfo, der);
MAKE_ENCODER(, kyber512, kmx, EncryptedPrivateKeyInfo, pem);
MAKE_ENCODER(, kyber512, kmx, PrivateKeyInfo, der);
MAKE_ENCODER(, kyber512, kmx, PrivateKeyInfo, pem);
MAKE_ENCODER(, kyber512, kmx, SubjectPublicKeyInfo, der);
MAKE_ENCODER(, kyber512, kmx, SubjectPublicKeyInfo, pem);
MAKE_TEXT_ENCODER(, kyber512);
MAKE_ENCODER(_ecx, x25519_kyber512, kmx, EncryptedPrivateKeyInfo, der);
MAKE_ENCODER(_ecx, x25519_kyber512, kmx, EncryptedPrivateKeyInfo, pem);
MAKE_ENCODER(_ecx, x25519_kyber512, kmx, PrivateKeyInfo, der);
MAKE_ENCODER(_ecx, x25519_kyber512, kmx, PrivateKeyInfo, pem);
MAKE_ENCODER(_ecx, x25519_kyber512, kmx, SubjectPublicKeyInfo, der);
MAKE_ENCODER(_ecx, x25519_kyber512, kmx, SubjectPublicKeyInfo, pem);
MAKE_TEXT_ENCODER(_ecx, x25519_kyber512);

MAKE_ENCODER(, kyber768, kmx, EncryptedPrivateKeyInfo, der);
MAKE_ENCODER(, kyber768, kmx, EncryptedPrivateKeyInfo, pem);
MAKE_ENCODER(, kyber768, kmx, PrivateKeyInfo, der);
MAKE_ENCODER(, kyber768, kmx, PrivateKeyInfo, pem);
MAKE_ENCODER(, kyber768, kmx, SubjectPublicKeyInfo, der);
MAKE_ENCODER(, kyber768, kmx, SubjectPublicKeyInfo, pem);
MAKE_TEXT_ENCODER(, kyber768);
MAKE_ENCODER(_ecx, x25519_kyber768, kmx, EncryptedPrivateKeyInfo, der);
MAKE_ENCODER(_ecx, x25519_kyber768, kmx, EncryptedPrivateKeyInfo, pem);
MAKE_ENCODER(_ecx, x25519_kyber768, kmx, PrivateKeyInfo, der);
MAKE_ENCODER(_ecx, x25519_kyber768, kmx, PrivateKeyInfo, pem);
MAKE_ENCODER(_ecx, x25519_kyber768, kmx, SubjectPublicKeyInfo, der);
MAKE_ENCODER(_ecx, x25519_kyber768, kmx, SubjectPublicKeyInfo, pem);
MAKE_TEXT_ENCODER(_ecx, x25519_kyber768);

MAKE_ENCODER(, kyber1024, kmx, EncryptedPrivateKeyInfo, der);
MAKE_ENCODER(, kyber1024, kmx, EncryptedPrivateKeyInfo, pem);
MAKE_ENCODER(, kyber1024, kmx, PrivateKeyInfo, der);
MAKE_ENCODER(, kyber1024, kmx, PrivateKeyInfo, pem);
MAKE_ENCODER(, kyber1024, kmx, SubjectPublicKeyInfo, der);
MAKE_ENCODER(, kyber1024, kmx, SubjectPublicKeyInfo, pem);
MAKE_TEXT_ENCODER(, kyber1024);

MAKE_ENCODER(, mlkem512, kmx, EncryptedPrivateKeyInfo, der);
MAKE_ENCODER(, mlkem512, kmx, EncryptedPrivateKeyInfo, pem);
MAKE_ENCODER(, mlkem512, kmx, PrivateKeyInfo, der);
MAKE_ENCODER(, mlkem512, kmx, PrivateKeyInfo, pem);
MAKE_ENCODER(, mlkem512, kmx, SubjectPublicKeyInfo, der);
MAKE_ENCODER(, mlkem512, kmx, SubjectPublicKeyInfo, pem);
MAKE_TEXT_ENCODER(, mlkem512);
MAKE_ENCODER(_ecx, x25519_mlkem512, kmx, EncryptedPrivateKeyInfo, der);
MAKE_ENCODER(_ecx, x25519_mlkem512, kmx, EncryptedPrivateKeyInfo, pem);
MAKE_ENCODER(_ecx, x25519_mlkem512, kmx, PrivateKeyInfo, der);
MAKE_ENCODER(_ecx, x25519_mlkem512, kmx, PrivateKeyInfo, pem);
MAKE_ENCODER(_ecx, x25519_mlkem512, kmx, SubjectPublicKeyInfo, der);
MAKE_ENCODER(_ecx, x25519_mlkem512, kmx, SubjectPublicKeyInfo, pem);
MAKE_TEXT_ENCODER(_ecx, x25519_mlkem512);

MAKE_ENCODER(, mlkem768, kmx, EncryptedPrivateKeyInfo, der);
MAKE_ENCODER(, mlkem768, kmx, EncryptedPrivateKeyInfo, pem);
MAKE_ENCODER(, mlkem768, kmx, PrivateKeyInfo, der);
MAKE_ENCODER(, mlkem768, kmx, PrivateKeyInfo, pem);
MAKE_ENCODER(, mlkem768, kmx, SubjectPublicKeyInfo, der);
MAKE_ENCODER(, mlkem768, kmx, SubjectPublicKeyInfo, pem);
MAKE_TEXT_ENCODER(, mlkem768);
MAKE_ENCODER(_ecx, X25519MLKEM768, kmx, EncryptedPrivateKeyInfo, der);
MAKE_ENCODER(_ecx, X25519MLKEM768, kmx, EncryptedPrivateKeyInfo, pem);
MAKE_ENCODER(_ecx, X25519MLKEM768, kmx, PrivateKeyInfo, der);
MAKE_ENCODER(_ecx, X25519MLKEM768, kmx, PrivateKeyInfo, pem);
MAKE_ENCODER(_ecx, X25519MLKEM768, kmx, SubjectPublicKeyInfo, der);
MAKE_ENCODER(_ecx, X25519MLKEM768, kmx, SubjectPublicKeyInfo, pem);
MAKE_TEXT_ENCODER(_ecx, X25519MLKEM768);

MAKE_ENCODER(, mlkem1024, kmx, EncryptedPrivateKeyInfo, der);
MAKE_ENCODER(, mlkem1024, kmx, EncryptedPrivateKeyInfo, pem);
MAKE_ENCODER(, mlkem1024, kmx, PrivateKeyInfo, der);
MAKE_ENCODER(, mlkem1024, kmx, PrivateKeyInfo, pem);
MAKE_ENCODER(, mlkem1024, kmx, SubjectPublicKeyInfo, der);
MAKE_ENCODER(, mlkem1024, kmx, SubjectPublicKeyInfo, pem);
MAKE_TEXT_ENCODER(, mlkem1024);

// #endif /* KM_KEM_ENCODERS */


MAKE_ENCODER(, dilithium2, kmx, EncryptedPrivateKeyInfo, der);
MAKE_ENCODER(, dilithium2, kmx, EncryptedPrivateKeyInfo, pem);
MAKE_ENCODER(, dilithium2, kmx, PrivateKeyInfo, der);
MAKE_ENCODER(, dilithium2, kmx, PrivateKeyInfo, pem);
MAKE_ENCODER(, dilithium2, kmx, SubjectPublicKeyInfo, der);
MAKE_ENCODER(, dilithium2, kmx, SubjectPublicKeyInfo, pem);
MAKE_TEXT_ENCODER(, dilithium2);

MAKE_ENCODER(, dilithium3, kmx, EncryptedPrivateKeyInfo, der);
MAKE_ENCODER(, dilithium3, kmx, EncryptedPrivateKeyInfo, pem);
MAKE_ENCODER(, dilithium3, kmx, PrivateKeyInfo, der);
MAKE_ENCODER(, dilithium3, kmx, PrivateKeyInfo, pem);
MAKE_ENCODER(, dilithium3, kmx, SubjectPublicKeyInfo, der);
MAKE_ENCODER(, dilithium3, kmx, SubjectPublicKeyInfo, pem);
MAKE_TEXT_ENCODER(, dilithium3);

MAKE_ENCODER(, dilithium5, kmx, EncryptedPrivateKeyInfo, der);
MAKE_ENCODER(, dilithium5, kmx, EncryptedPrivateKeyInfo, pem);
MAKE_ENCODER(, dilithium5, kmx, PrivateKeyInfo, der);
MAKE_ENCODER(, dilithium5, kmx, PrivateKeyInfo, pem);
MAKE_ENCODER(, dilithium5, kmx, SubjectPublicKeyInfo, der);
MAKE_ENCODER(, dilithium5, kmx, SubjectPublicKeyInfo, pem);
MAKE_TEXT_ENCODER(, dilithium5);

MAKE_ENCODER(, mldsa44, kmx, EncryptedPrivateKeyInfo, der);
MAKE_ENCODER(, mldsa44, kmx, EncryptedPrivateKeyInfo, pem);
MAKE_ENCODER(, mldsa44, kmx, PrivateKeyInfo, der);
MAKE_ENCODER(, mldsa44, kmx, PrivateKeyInfo, pem);
MAKE_ENCODER(, mldsa44, kmx, SubjectPublicKeyInfo, der);
MAKE_ENCODER(, mldsa44, kmx, SubjectPublicKeyInfo, pem);
MAKE_TEXT_ENCODER(, mldsa44);

MAKE_ENCODER(, mldsa65, kmx, EncryptedPrivateKeyInfo, der);
MAKE_ENCODER(, mldsa65, kmx, EncryptedPrivateKeyInfo, pem);
MAKE_ENCODER(, mldsa65, kmx, PrivateKeyInfo, der);
MAKE_ENCODER(, mldsa65, kmx, PrivateKeyInfo, pem);
MAKE_ENCODER(, mldsa65, kmx, SubjectPublicKeyInfo, der);
MAKE_ENCODER(, mldsa65, kmx, SubjectPublicKeyInfo, pem);
MAKE_TEXT_ENCODER(, mldsa65);

MAKE_ENCODER(, mldsa87, kmx, EncryptedPrivateKeyInfo, der);
MAKE_ENCODER(, mldsa87, kmx, EncryptedPrivateKeyInfo, pem);
MAKE_ENCODER(, mldsa87, kmx, PrivateKeyInfo, der);
MAKE_ENCODER(, mldsa87, kmx, PrivateKeyInfo, pem);
MAKE_ENCODER(, mldsa87, kmx, SubjectPublicKeyInfo, der);
MAKE_ENCODER(, mldsa87, kmx, SubjectPublicKeyInfo, pem);
MAKE_TEXT_ENCODER(, mldsa87);

MAKE_ENCODER(, sphincssha2128fsimple, kmx, EncryptedPrivateKeyInfo, der);
MAKE_ENCODER(, sphincssha2128fsimple, kmx, EncryptedPrivateKeyInfo, pem);
MAKE_ENCODER(, sphincssha2128fsimple, kmx, PrivateKeyInfo, der);
MAKE_ENCODER(, sphincssha2128fsimple, kmx, PrivateKeyInfo, pem);
MAKE_ENCODER(, sphincssha2128fsimple, kmx, SubjectPublicKeyInfo, der);
MAKE_ENCODER(, sphincssha2128fsimple, kmx, SubjectPublicKeyInfo, pem);
MAKE_TEXT_ENCODER(, sphincssha2128fsimple);

MAKE_ENCODER(, sphincssha2128ssimple, kmx, EncryptedPrivateKeyInfo, der);
MAKE_ENCODER(, sphincssha2128ssimple, kmx, EncryptedPrivateKeyInfo, pem);
MAKE_ENCODER(, sphincssha2128ssimple, kmx, PrivateKeyInfo, der);
MAKE_ENCODER(, sphincssha2128ssimple, kmx, PrivateKeyInfo, pem);
MAKE_ENCODER(, sphincssha2128ssimple, kmx, SubjectPublicKeyInfo, der);
MAKE_ENCODER(, sphincssha2128ssimple, kmx, SubjectPublicKeyInfo, pem);
MAKE_TEXT_ENCODER(, sphincssha2128ssimple);

MAKE_ENCODER(, sphincssha2192fsimple, kmx, EncryptedPrivateKeyInfo, der);
MAKE_ENCODER(, sphincssha2192fsimple, kmx, EncryptedPrivateKeyInfo, pem);
MAKE_ENCODER(, sphincssha2192fsimple, kmx, PrivateKeyInfo, der);
MAKE_ENCODER(, sphincssha2192fsimple, kmx, PrivateKeyInfo, pem);
MAKE_ENCODER(, sphincssha2192fsimple, kmx, SubjectPublicKeyInfo, der);
MAKE_ENCODER(, sphincssha2192fsimple, kmx, SubjectPublicKeyInfo, pem);
MAKE_TEXT_ENCODER(, sphincssha2192fsimple);

MAKE_ENCODER(, sphincsshake128fsimple, kmx, EncryptedPrivateKeyInfo, der);
MAKE_ENCODER(, sphincsshake128fsimple, kmx, EncryptedPrivateKeyInfo, pem);
MAKE_ENCODER(, sphincsshake128fsimple, kmx, PrivateKeyInfo, der);
MAKE_ENCODER(, sphincsshake128fsimple, kmx, PrivateKeyInfo, pem);
MAKE_ENCODER(, sphincsshake128fsimple, kmx, SubjectPublicKeyInfo, der);
MAKE_ENCODER(, sphincsshake128fsimple, kmx, SubjectPublicKeyInfo, pem);
MAKE_TEXT_ENCODER(, sphincsshake128fsimple);
///// KM_TEMPLATE_FRAGMENT_ENCODER_MAKE_END