// SPDX-License-Identifier: Apache-2.0 AND MIT
// KM OpenSSL 3 provider

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rsa.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <string.h>

#include "oqs/sig.h"
#include "provider.h"

/* ============================================================
 * Konstanta & Logging
 * ============================================================ */
#define OSSL_MAX_NAME_SIZE       50
#define OSSL_MAX_PROPQUERY_SIZE  256
#define COMPOSITE_OID_PREFIX_LEN 26

#ifdef NDEBUG
#  define KMSIG_LOG0(msg)               do{}while(0)
#  define KMSIG_LOG1(fmt,a)             do{}while(0)
#  define KMSIG_LOG2(fmt,a,b)           do{}while(0)
#else
static int kmsig_log_on(void){ return getenv("KMSIG") != NULL; }
#  define KMSIG_LOG0(msg)               do{ if(kmsig_log_on()) printf("%s",(msg)); }while(0)
#  define KMSIG_LOG1(fmt,a)             do{ if(kmsig_log_on()) printf((fmt),(a)); }while(0)
#  define KMSIG_LOG2(fmt,a,b)           do{ if(kmsig_log_on()) printf((fmt),(a),(b)); }while(0)
#endif

/* ============================================================
 * ASN.1 CompositeSignature (tetap kompatibel)
 * ============================================================ */
DECLARE_ASN1_FUNCTIONS(CompositeSignature)
ASN1_NDEF_SEQUENCE(CompositeSignature) = {
    ASN1_SIMPLE(CompositeSignature, sig1, ASN1_BIT_STRING),
    ASN1_SIMPLE(CompositeSignature, sig2, ASN1_BIT_STRING),
} ASN1_NDEF_SEQUENCE_END(CompositeSignature)
IMPLEMENT_ASN1_FUNCTIONS(CompositeSignature)

/* ============================================================
 * Forward decl OSSL hooks
 * ============================================================ */
static OSSL_FUNC_signature_newctx_fn                km_sig_newctx;
static OSSL_FUNC_signature_sign_init_fn             km_sig_sign_init;
static OSSL_FUNC_signature_verify_init_fn           km_sig_verify_init;
static OSSL_FUNC_signature_sign_fn                  km_sig_sign;
static OSSL_FUNC_signature_verify_fn                km_sig_verify;
static OSSL_FUNC_signature_digest_sign_init_fn      km_sig_digest_sign_init;
static OSSL_FUNC_signature_digest_sign_update_fn    km_sig_digest_signverify_update;
static OSSL_FUNC_signature_digest_sign_final_fn     km_sig_digest_sign_final;
static OSSL_FUNC_signature_digest_verify_init_fn    km_sig_digest_verify_init;
static OSSL_FUNC_signature_digest_verify_update_fn  km_sig_digest_signverify_update;
static OSSL_FUNC_signature_digest_verify_final_fn   km_sig_digest_verify_final;
static OSSL_FUNC_signature_freectx_fn               km_sig_freectx;
static OSSL_FUNC_signature_dupctx_fn                km_sig_dupctx;
static OSSL_FUNC_signature_get_ctx_params_fn        km_sig_get_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn   km_sig_gettable_ctx_params;
static OSSL_FUNC_signature_set_ctx_params_fn        km_sig_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn   km_sig_settable_ctx_params;
static OSSL_FUNC_signature_get_ctx_md_params_fn     km_sig_get_ctx_md_params;
static OSSL_FUNC_signature_gettable_ctx_md_params_fn km_sig_gettable_ctx_md_params;
static OSSL_FUNC_signature_set_ctx_md_params_fn     km_sig_set_ctx_md_params;
static OSSL_FUNC_signature_settable_ctx_md_params_fn km_sig_settable_ctx_md_params;

/* ============================================================
 * Context
 * ============================================================ */
typedef struct {
    OSSL_LIB_CTX *libctx;
    char         *propq;
    KMX_KEY      *sig;

    /* boleh ganti MD hanya sebelum ada data */
    unsigned int  flag_allow_md : 1;

    char          mdname[OSSL_MAX_NAME_SIZE];
    unsigned char *aid;      /* AlgorithmIdentifier terenkode DER */
    size_t         aid_len;

    EVP_MD     *md;
    EVP_MD_CTX *mdctx;

    /* buffer collector saat tanpa MD streaming */
    unsigned char *mddata;
    size_t         mdsize;

    int            operation; /* EVP_PKEY_OP_SIGN / VERIFY */
} PROV_KMSIG_CTX;

/* ============================================================
 * OID / util
 * ============================================================ */
static int get_aid(unsigned char **oidbuf, const char *tls_name) {
    X509_ALGOR *alg = X509_ALGOR_new();
    if (!alg) return 0;
    X509_ALGOR_set0(alg, OBJ_txt2obj(tls_name, 0), V_ASN1_UNDEF, NULL);
    int len = i2d_X509_ALGOR(alg, oidbuf);
    X509_ALGOR_free(alg);
    return len;
}

/* daftar OID prefix untuk composite — urutan dipertahankan */
static const unsigned char *composite_OID_prefix[] = {
    (const unsigned char *)"060B6086480186FA6B50080101", /* mldsa44_pss2048 */
    (const unsigned char *)"060B6086480186FA6B50080102", /* mldsa44_rsa2048 */
    (const unsigned char *)"060B6086480186FA6B50080103", /* mldsa44_ed25519 */
    (const unsigned char *)"060B6086480186FA6B50080104", /* mldsa44_p256 */
    (const unsigned char *)"060B6086480186FA6B50080105", /* mldsa44_bp256 */
    (const unsigned char *)"060B6086480186FA6B50080106", /* mldsa65_pss3072 */
    (const unsigned char *)"060B6086480186FA6B50080107", /* mldsa65_rsa3072 */
    (const unsigned char *)"060B6086480186FA6B50080108", /* mldsa65_p256 */
    (const unsigned char *)"060B6086480186FA6B50080109", /* mldsa65_bp256 */
    (const unsigned char *)"060B6086480186FA6B5008010A", /* mldsa65_ed25519 */
    (const unsigned char *)"060B6086480186FA6B5008010B", /* mldsa87_p384 */
    (const unsigned char *)"060B6086480186FA6B5008010C", /* mldsa87_bp384 */
    (const unsigned char *)"060B6086480186FA6B5008010D", /* mldsa87_ed448 */
    (const unsigned char *)"060B6086480186FA6B5008010E", /* falcon512_p256 */
    (const unsigned char *)"060B6086480186FA6B5008010F", /* falcon512_bp256 */
    (const unsigned char *)"060B6086480186FA6B50080110", /* falcon512_ed25519 */
};

static void hex_prefix_to_bin(unsigned char *out, const unsigned char *hex) {
    for (int i = 0; i < COMPOSITE_OID_PREFIX_LEN/2; i++) {
        int hi = OPENSSL_hexchar2int(hex[2*i]);
        int lo = OPENSSL_hexchar2int(hex[2*i+1]);
        out[i] = (unsigned char)((hi<<4) | lo);
    }
}

/* pilih digest klasik berdasarkan level PQ */
static const EVP_MD *select_classical_md(const OQS_SIG *pq_sig, int *out_len) {
    switch (pq_sig->claimed_nist_level) {
        case 1: *out_len = SHA256_DIGEST_LENGTH; return EVP_sha256();
        case 2:
        case 3: *out_len = SHA384_DIGEST_LENGTH; return EVP_sha384();
        case 4:
        case 5:
        default: *out_len = SHA512_DIGEST_LENGTH; return EVP_sha512();
    }
}

/* set padding RSA/RSASSA-PSS sesuai nama TLS (pss2048/pss3072) */
static int setup_rsa_padding(EVP_PKEY_CTX *pctx, int is_pss, const char *name) {
    if (!is_pss)
        return EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) > 0;

    int salt = 0;
    const EVP_MD *mgf1 = NULL;
    if (!strncmp(name, "pss3072", 7)) { salt = 64; mgf1 = EVP_sha512(); }
    else if (!strncmp(name, "pss2048", 7)) { salt = 32; mgf1 = EVP_sha256(); }
    else return 0;

    return EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0
        && EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, salt) > 0
        && EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, mgf1) > 0;
}

/* siapkan prehash untuk composite: prefix OID + hash(TBS) */
static unsigned char *make_composite_prehash(const unsigned char *oid_hex_prefix,
                                             const unsigned char *tbs, size_t tbslen,
                                             size_t *out_len, int sha512_mode) {
    int hlen = sha512_mode ? SHA512_DIGEST_LENGTH : SHA256_DIGEST_LENGTH;
    *out_len = (COMPOSITE_OID_PREFIX_LEN/2) + hlen;

    unsigned char *buf = OPENSSL_malloc(*out_len);
    if (!buf) return NULL;

    hex_prefix_to_bin(buf, oid_hex_prefix);

    unsigned char *hptr = buf + (COMPOSITE_OID_PREFIX_LEN/2);
    if (sha512_mode) SHA512(tbs, tbslen, hptr);
    else             SHA256(tbs, tbslen, hptr);

    return buf;
}

/* ============================================================
 * Ctx helpers
 * ============================================================ */
static int km_sig_setup_md(PROV_KMSIG_CTX *ctx, const char *mdname, const char *mdprops) {
    KMSIG_LOG2("setup_md: %s (alg=%s)\n", mdname ? mdname : "(null)", ctx->sig ? ctx->sig->tls_name : "(nil)");
    if (mdprops == NULL) mdprops = ctx->propq;
    if (!mdname) return 1;

    EVP_MD *md = EVP_MD_fetch(ctx->libctx, mdname, mdprops);
    if (!md || EVP_MD_nid(md) == NID_undef) {
        if (!md) ERR_raise_data(ERR_LIB_USER, KMPROV_R_INVALID_DIGEST, "%s could not be fetched", mdname);
        EVP_MD_free(md);
        return 0;
    }

    EVP_MD_CTX_free(ctx->mdctx);  ctx->mdctx = NULL;
    EVP_MD_free(ctx->md);         ctx->md    = NULL;

    OPENSSL_free(ctx->aid);       ctx->aid   = NULL;
    ctx->aid_len = get_aid(&ctx->aid, ctx->sig->tls_name);

    ctx->md = md;
    OPENSSL_strlcpy(ctx->mdname, mdname, sizeof(ctx->mdname));
    return 1;
}

static int km_sig_signverify_init_common(void *vctx, void *vkey, int op) {
    PROV_KMSIG_CTX *c = (PROV_KMSIG_CTX *)vctx;
    if (!c || !vkey || !kmx_key_up_ref(vkey)) return 0;
    kmx_key_free(c->sig);
    c->sig = (KMX_KEY *)vkey;
    c->operation = op;
    c->flag_allow_md = 1;

    if ((op == EVP_PKEY_OP_SIGN   && !c->sig->privkey) ||
        (op == EVP_PKEY_OP_VERIFY && !c->sig->pubkey)) {
        ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_KEY);
        return 0;
    }
    return 1;
}

/* ============================================================
 * NEWCTX / DUP / FREE
 * ============================================================ */
static void *km_sig_newctx(void *provctx, const char *propq) {
    PROV_KMSIG_CTX *c = OPENSSL_zalloc(sizeof(*c));
    KMSIG_LOG1("newctx propq=%s\n", propq ? propq : "(null)");
    if (!c) return NULL;

    c->libctx = ((PROV_KM_CTX *)provctx)->libctx;
    if (propq) {
        c->propq = OPENSSL_strdup(propq);
        if (!c->propq) { OPENSSL_free(c); ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE); return NULL; }
    }
    return c;
}

static void km_sig_freectx(void *vctx) {
    PROV_KMSIG_CTX *c = (PROV_KMSIG_CTX *)vctx;
    if (!c) return;
    KMSIG_LOG0("freectx\n");
    OPENSSL_free(c->propq);
    EVP_MD_CTX_free(c->mdctx);
    EVP_MD_free(c->md);
    kmx_key_free(c->sig);
    OPENSSL_free(c->mddata);
    OPENSSL_free(c->aid);
    OPENSSL_free(c);
}

static void *km_sig_dupctx(void *vctx) {
    PROV_KMSIG_CTX *src = (PROV_KMSIG_CTX *)vctx;
    PROV_KMSIG_CTX *dst = OPENSSL_zalloc(sizeof(*dst));
    KMSIG_LOG0("dupctx\n");
    if (!dst) return NULL;

    *dst = *src;
    dst->sig = NULL; dst->md = NULL; dst->mdctx = NULL; dst->propq = NULL; dst->aid = NULL; dst->mddata = NULL;

    if (src->sig && !kmx_key_up_ref(src->sig)) goto err;
    dst->sig = src->sig;

    if (src->md && !EVP_MD_up_ref(src->md)) goto err;
    dst->md = src->md;

    if (src->mdctx) {
        dst->mdctx = EVP_MD_CTX_new();
        if (!dst->mdctx || !EVP_MD_CTX_copy_ex(dst->mdctx, src->mdctx)) goto err;
    }

    if (src->mddata) {
        dst->mddata = OPENSSL_memdup(src->mddata, src->mdsize);
        if (!dst->mddata) goto err;
        dst->mdsize = src->mdsize;
    }

    if (src->aid) {
        dst->aid = OPENSSL_memdup(src->aid, src->aid_len);
        if (!dst->aid) goto err;
        dst->aid_len = src->aid_len;
    }

    if (src->propq) {
        dst->propq = OPENSSL_strdup(src->propq);
        if (!dst->propq) goto err;
    }
    return dst;

err:
    km_sig_freectx(dst);
    return NULL;
}

/* ============================================================
 * INIT (sign/verify) & variant digest_*
 * ============================================================ */
static int km_sig_sign_init(void *vctx, void *vkey, const OSSL_PARAM params[]) {
    (void)params; KMSIG_LOG0("sign_init\n");
    return km_sig_signverify_init_common(vctx, vkey, EVP_PKEY_OP_SIGN);
}
static int km_sig_verify_init(void *vctx, void *vkey, const OSSL_PARAM params[]) {
    (void)params; KMSIG_LOG0("verify_init\n");
    return km_sig_signverify_init_common(vctx, vkey, EVP_PKEY_OP_VERIFY);
}

static int km_sig_digest_signverify_init(void *vctx, const char *mdname, void *vkey, int op) {
    PROV_KMSIG_CTX *c = (PROV_KMSIG_CTX *)vctx;
    KMSIG_LOG1("digest_*_init md=%s\n", mdname ? mdname : "(null)");

    c->flag_allow_md = 1;
    if (!km_sig_signverify_init_common(vctx, vkey, op)) return 0;
    if (!km_sig_setup_md(c, mdname, NULL)) return 0;

    if (mdname) {
        c->mdctx = EVP_MD_CTX_new();
        if (!c->mdctx || !EVP_DigestInit_ex(c->mdctx, c->md, NULL)) {
            EVP_MD_CTX_free(c->mdctx); c->mdctx = NULL;
            EVP_MD_free(c->md);        c->md    = NULL;
            KMSIG_LOG0("digest_*_init FAILED\n");
            return 0;
        }
    }
    return 1;
}
static int km_sig_digest_sign_init(void *vctx, const char *mdname, void *vkey, const OSSL_PARAM params[]) {
    (void)params; return km_sig_digest_signverify_init(vctx, mdname, vkey, EVP_PKEY_OP_SIGN);
}
static int km_sig_digest_verify_init(void *vctx, const char *mdname, void *vkey, const OSSL_PARAM params[]) {
    (void)params; return km_sig_digest_signverify_init(vctx, mdname, vkey, EVP_PKEY_OP_VERIFY);
}
int km_sig_digest_signverify_update(void *vctx, const unsigned char *data, size_t len) {
    PROV_KMSIG_CTX *c = (PROV_KMSIG_CTX *)vctx;
    if (!c) return 0;
    c->flag_allow_md = 0; /* setelah update, digest tidak boleh diganti */

    if (c->mdctx) return EVP_DigestUpdate(c->mdctx, data, len);

    /* kumpulkan data mentah */
    if (c->mddata) {
        unsigned char *p = OPENSSL_realloc(c->mddata, c->mdsize + len);
        if (!p) return 0;
        memcpy(p + c->mdsize, data, len);
        c->mddata = p;
        c->mdsize += len;
    } else {
        c->mddata = OPENSSL_malloc(len);
        if (!c) return 0;
        memcpy(c->mddata, data, len);
        c->mdsize = len;
    }
    KMSIG_LOG1("digest_update collected=%lu\n",(unsigned long)c->mdsize);
    return 1;
}
int km_sig_digest_sign_final(void *vctx, unsigned char *sig, size_t *siglen, size_t sigsize) {
    (void)sigsize;
    PROV_KMSIG_CTX *c = (PROV_KMSIG_CTX *)vctx;
    unsigned char md[EVP_MAX_MD_SIZE]; unsigned int mdlen = 0;
    if (!c) return 0;
    if (sig && c->mdctx && !EVP_DigestFinal_ex(c->mdctx, md, &mdlen)) return 0;
    c->flag_allow_md = 1;
    return c->mdctx ? km_sig_sign(vctx, sig, siglen, 0, md, (size_t)mdlen)
                    : km_sig_sign(vctx, sig, siglen, 0, c->mddata, c->mdsize);
}
int km_sig_digest_verify_final(void *vctx, const unsigned char *sig, size_t siglen) {
    PROV_KMSIG_CTX *c = (PROV_KMSIG_CTX *)vctx;
    unsigned char md[EVP_MAX_MD_SIZE]; unsigned int mdlen = 0;
    if (!c) return 0;

    if (c->mdctx) {
        if (!EVP_DigestFinal_ex(c->mdctx, md, &mdlen)) return 0;
        c->flag_allow_md = 1;
        return km_sig_verify(vctx, sig, siglen, md, (size_t)mdlen);
    }
    return km_sig_verify(vctx, sig, siglen, c->mddata, c->mdsize);
}

/* ============================================================
 * SIGN & VERIFY
 * ============================================================ */
static int km_sig_sign(void *vctx, unsigned char *sig, size_t *siglen,
                       size_t sigsize, const unsigned char *tbs, size_t tbslen) {
    (void)sigsize;
    PROV_KMSIG_CTX *c = (PROV_KMSIG_CTX *)vctx;
    KMX_KEY *k = c->sig;
    OQS_SIG *pq = k->kmx_provider_ctx.kmx_qs_ctx.sig;
    EVP_PKEY *klass = k->classical_pkey;
    EVP_PKEY_CTX *klass_ctx = NULL;

    const int is_hybrid    = (k->keytype == KEY_TYPE_HYB_SIG);
    const int is_composite = (k->keytype == KEY_TYPE_CMP_SIG);

    size_t max_len = 0, pq_len = 0, klass_len = 0, idx = 0;
    int ok = 0;

    KMSIG_LOG1("sign: tbs=%lu\n",(unsigned long)tbslen);
    if (!k || !k->privkey || (!pq && !klass)) { ERR_raise(ERR_LIB_USER, KMPROV_R_NO_PRIVATE_KEY); return 0; }

    max_len = is_composite ? kmx_key_maxsize(k) : pq->length_signature;
    if (is_hybrid) max_len += SIZE_OF_UINT32 + k->evp_info->length_signature;

    if (!sig) { *siglen = max_len; KMSIG_LOG1("sign(size only)=%lu\n",(unsigned long)*siglen); return 1; }
    if (*siglen < max_len) { ERR_raise(ERR_LIB_USER, KMPROV_R_BUFFER_LENGTH_WRONG); return 0; }

    /* === HYBRID: tandatangan klasik + PQ === */
    if (is_hybrid) {
        klass_ctx = EVP_PKEY_CTX_new(klass, NULL);
        if (!klass_ctx || EVP_PKEY_sign_init(klass_ctx) <= 0) { ERR_raise(ERR_LIB_USER, ERR_R_FATAL); goto end; }

        /* setup padding jika RSA atau PSS */
        if (k->evp_info->keytype == EVP_PKEY_RSA) {
            if (!setup_rsa_padding(klass_ctx, 0, "rsa")) { ERR_raise(ERR_LIB_USER, ERR_R_FATAL); goto end; }
        }

        /* Digest-kan tbs sesuai level PQ */
        int dlen = 0; unsigned char dig[SHA512_DIGEST_LENGTH];
        const EVP_MD *klass_md = select_classical_md(pq, &dlen);
        if      (dlen == SHA256_DIGEST_LENGTH) SHA256(tbs, tbslen, dig);
        else if (dlen == SHA384_DIGEST_LENGTH) SHA384(tbs, tbslen, dig);
        else                                   SHA512(tbs, tbslen, dig);

        if (EVP_PKEY_CTX_set_signature_md(klass_ctx, klass_md) <= 0 ||
            EVP_PKEY_sign(klass_ctx, sig + SIZE_OF_UINT32, &klass_len, dig, dlen) <= 0) {
            ERR_raise(ERR_LIB_USER, ERR_R_FATAL); goto end;
        }
        if (klass_len > k->evp_info->length_signature) { ERR_raise(ERR_LIB_USER, KMPROV_R_BUFFER_LENGTH_WRONG); goto end; }
        ENCODE_UINT32(sig, klass_len);
        idx += (SIZE_OF_UINT32 + klass_len);
    }

    /* === COMPOSITE: bangun ASN.1 dengan 2 komponen === */
    if (is_composite) {
        int nid = OBJ_sn2nid(k->tls_name);
        int comp_idx = get_composite_idx(get_kmalg_idx(nid));
        if (comp_idx == -1) goto end;

        const unsigned char *pref = composite_OID_prefix[comp_idx - 1];

        /* pilih mode hash untuk prehash: SHA256 (default) atau SHA512 untuk ML-DSA tinggi / Ed* */
        int sha512_mode = 0;
        for (int i = 0; i < k->numkeys; i++) {
            char *part = get_cmpname(nid, i);
            if (!part) { ERR_raise(ERR_LIB_USER, ERR_R_FATAL); goto end; }
            char *pqname = get_kmname_fromtls(part);
            if ( (pqname && (!strcmp(pqname, OQS_SIG_alg_ml_dsa_65) || !strcmp(pqname, OQS_SIG_alg_ml_dsa_87))) ||
                 part[0] == 'e') sha512_mode = 1;
            OPENSSL_free(part);
            if (sha512_mode) break;
        }

        size_t prelen = 0;
        unsigned char *pretbs = make_composite_prehash(pref, tbs, tbslen, &prelen, sha512_mode);
        if (!pretbs) { ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE); goto end; }

        CompositeSignature *cs = CompositeSignature_new();
        if (!cs) { OPENSSL_free(pretbs); goto end; }

        for (int i = 0; i < k->numkeys; i++) {
            unsigned char *buf = NULL; size_t blen = 0;
            char *name = get_cmpname(nid, i);
            if (!name) { ERR_raise(ERR_LIB_USER, ERR_R_FATAL); CompositeSignature_free(cs); OPENSSL_free(pretbs); goto end; }

            if (get_kmname_fromtls(name)) {
                /* PQ part */
                blen = k->kmx_provider_ctx.kmx_qs_ctx.sig->length_signature;
                buf = OPENSSL_malloc(blen);
                if (!buf || OQS_SIG_sign(k->kmx_provider_ctx.kmx_qs_ctx.sig, buf, &blen, pretbs, prelen, k->comp_privkey[i]) != OQS_SUCCESS) {
                    ERR_raise(ERR_LIB_USER, KMPROV_R_SIGNING_FAILED);
                    OPENSSL_free(buf); OPENSSL_free(name); CompositeSignature_free(cs); OPENSSL_free(pretbs); goto end;
                }
            } else {
                /* classical part */
                EVP_PKEY *klass_key = k->classical_pkey;
                blen = k->kmx_provider_ctx.kmx_evp_ctx->evp_info->length_signature;
                buf = OPENSSL_malloc(blen);
                if (!buf) { OPENSSL_free(name); CompositeSignature_free(cs); OPENSSL_free(pretbs); goto end; }

                if (name[0] == 'e') { /* Ed25519/Ed448 */
                    EVP_MD_CTX *m = EVP_MD_CTX_new();
                    if (!m ||
                        EVP_DigestSignInit(m, NULL, NULL, NULL, klass_key) <= 0 ||
                        EVP_DigestSign(m, buf, &blen, pretbs, prelen) <= 0) {
                        ERR_raise(ERR_LIB_USER, ERR_R_FATAL);
                        EVP_MD_CTX_free(m); OPENSSL_free(name); OPENSSL_free(buf); CompositeSignature_free(cs); OPENSSL_free(pretbs); goto end;
                    }
                    EVP_MD_CTX_free(m);
                } else {
                    EVP_PKEY_CTX *pc = EVP_PKEY_CTX_new(klass_key, NULL);
                    if (!pc || EVP_PKEY_sign_init(pc) <= 0) { ERR_raise(ERR_LIB_USER, ERR_R_FATAL); EVP_PKEY_CTX_free(pc); OPENSSL_free(name); OPENSSL_free(buf); CompositeSignature_free(cs); OPENSSL_free(pretbs); goto end; }
                    int is_pss = !strncmp(name, "pss", 3);
                    if (!setup_rsa_padding(pc, is_pss, name)) {
                        ERR_raise(ERR_LIB_USER, ERR_R_FATAL); EVP_PKEY_CTX_free(pc); OPENSSL_free(name); OPENSSL_free(buf); CompositeSignature_free(cs); OPENSSL_free(pretbs); goto end;
                    }

                    int dlen = sha512_mode ? SHA512_DIGEST_LENGTH : SHA256_DIGEST_LENGTH;
                    unsigned char dig[SHA512_DIGEST_LENGTH];
                    if (sha512_mode) SHA512(pretbs, prelen, dig); else SHA256(pretbs, prelen, dig);

                    const EVP_MD *md = sha512_mode ? EVP_sha512() : EVP_sha256();
                    if (EVP_PKEY_CTX_set_signature_md(pc, md) <= 0 ||
                        EVP_PKEY_sign(pc, buf, &blen, dig, dlen) <= 0) {
                        ERR_raise(ERR_LIB_USER, ERR_R_FATAL);
                        EVP_PKEY_CTX_free(pc); OPENSSL_free(name); OPENSSL_free(buf); CompositeSignature_free(cs); OPENSSL_free(pretbs); goto end;
                    }
                    EVP_PKEY_CTX_free(pc);
                    if (blen > k->kmx_provider_ctx.kmx_evp_ctx->evp_info->length_signature) {
                        ERR_raise(ERR_LIB_USER, KMPROV_R_BUFFER_LENGTH_WRONG);
                        OPENSSL_free(name); OPENSSL_free(buf); CompositeSignature_free(cs); OPENSSL_free(pretbs); goto end;
                    }
                }
            }

            ASN1_BIT_STRING *dst = (i==0) ? cs->sig1 : cs->sig2;
            dst->data   = OPENSSL_memdup(buf, blen);
            dst->length = (int)blen;
            dst->flags  = 8; /* skip bit-unused checks */
            OPENSSL_free(buf);
            OPENSSL_free(name);
        }

        pq_len = i2d_CompositeSignature(cs, &sig);
        CompositeSignature_free(cs);
        OPENSSL_free(pretbs);
    } else {
        /* === PQ tunggal (atau bagian PQ dari hybrid) === */
        if (OQS_SIG_sign(pq, sig + idx, &pq_len, tbs, tbslen, k->comp_privkey[k->numkeys-1]) != OQS_SUCCESS) {
            ERR_raise(ERR_LIB_USER, KMPROV_R_SIGNING_FAILED); goto end;
        }
    }

    *siglen = idx + pq_len;
    KMSIG_LOG1("sign out=%lu\n",(unsigned long)*siglen);
    ok = 1;

end:
    EVP_PKEY_CTX_free(klass_ctx);
    return ok;
}

static int km_sig_verify(void *vctx, const unsigned char *sig, size_t siglen,
                         const unsigned char *tbs, size_t tbslen) {
    PROV_KMSIG_CTX *c = (PROV_KMSIG_CTX *)vctx;
    KMX_KEY *k = c->sig;
    OQS_SIG *pq = k->kmx_provider_ctx.kmx_qs_ctx.sig;
    EVP_PKEY_CTX *vctx_classic = NULL;

    const int is_hybrid    = (k->keytype == KEY_TYPE_HYB_SIG);
    const int is_composite = (k->keytype == KEY_TYPE_CMP_SIG);

    size_t klass_len = 0, idx = 0;
    int ok = 0;

    KMSIG_LOG2("verify sig=%lu tbs=%lu\n",(unsigned long)siglen,(unsigned long)tbslen);
    if (!k || !pq || !k->pubkey || !sig || (!tbs && tbslen>0)) { ERR_raise(ERR_LIB_USER, KMPROV_R_WRONG_PARAMETERS); return 0; }

    if (is_hybrid) {
        /* layout: [u32 klass_len][klass_sig][pq_sig] */
        if (siglen <= SIZE_OF_UINT32) { ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING); return 0; }

        uint32_t klass_sz = 0; DECODE_UINT32(klass_sz, sig);
        size_t pq_sz = siglen - SIZE_OF_UINT32 - klass_sz;
        if (siglen <= SIZE_OF_UINT32 + klass_sz ||
            klass_sz > k->kmx_provider_ctx.kmx_evp_ctx->evp_info->length_signature ||
            pq_sz    > pq->length_signature) {
            ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING); return 0;
        }

        int dlen = 0; unsigned char dig[SHA512_DIGEST_LENGTH];
        const EVP_MD *md = select_classical_md(pq, &dlen);
        if      (dlen == SHA256_DIGEST_LENGTH) SHA256(tbs, tbslen, dig);
        else if (dlen == SHA384_DIGEST_LENGTH) SHA384(tbs, tbslen, dig);
        else                                   SHA512(tbs, tbslen, dig);

        vctx_classic = EVP_PKEY_CTX_new(k->classical_pkey, NULL);
        if (!vctx_classic || EVP_PKEY_verify_init(vctx_classic) <= 0) { ERR_raise(ERR_LIB_USER, KMPROV_R_VERIFY_ERROR); goto end; }
        if (k->evp_info->keytype == EVP_PKEY_RSA &&
            EVP_PKEY_CTX_set_rsa_padding(vctx_classic, RSA_PKCS1_PADDING) <= 0) {
            ERR_raise(ERR_LIB_USER, KMPROV_R_WRONG_PARAMETERS); goto end;
        }
        if (EVP_PKEY_CTX_set_signature_md(vctx_classic, md) <= 0 ||
            EVP_PKEY_verify(vctx_classic, sig + SIZE_OF_UINT32, klass_sz, dig, dlen) <= 0) {
            ERR_raise(ERR_LIB_USER, KMPROV_R_VERIFY_ERROR); goto end;
        }
        klass_len = SIZE_OF_UINT32 + klass_sz;
        idx += klass_len;
    }

    if (is_composite) {
        int nid = OBJ_sn2nid(k->tls_name);
        int comp_idx = get_composite_idx(get_kmalg_idx(nid));
        if (comp_idx == -1) goto end;

        const unsigned char *pref = composite_OID_prefix[comp_idx - 1];
        CompositeSignature *cs = d2i_CompositeSignature(NULL, &sig, siglen);
        if (!cs) { ERR_raise(ERR_LIB_USER, KMPROV_R_VERIFY_ERROR); goto end; }

        /* deteksi mode hash prehash seperti sign() */
        int sha512_mode = 0;
        for (int i = 0; i < k->numkeys; i++) {
            char *part = get_cmpname(nid, i);
            if (!part) { CompositeSignature_free(cs); ERR_raise(ERR_LIB_USER, ERR_R_FATAL); goto end; }
            char *pqname = get_kmname_fromtls(part);
            if ((pqname && (!strcmp(pqname, OQS_SIG_alg_ml_dsa_65) || !strcmp(pqname, OQS_SIG_alg_ml_dsa_87))) ||
                 part[0] == 'e') sha512_mode = 1;
            OPENSSL_free(part);
            if (sha512_mode) break;
        }

        size_t prelen = 0;
        unsigned char *pretbs = make_composite_prehash(pref, tbs, tbslen, &prelen, sha512_mode);
        if (!pretbs) { CompositeSignature_free(cs); ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE); goto end; }

        for (int i = 0; i < k->numkeys; i++) {
            unsigned char *buf; size_t blen;
            if (i==0) { buf = cs->sig1->data; blen = cs->sig1->length; }
            else      { buf = cs->sig2->data; blen = cs->sig2->length; }

            char *name = get_cmpname(nid, i);
            if (!name) { ERR_raise(ERR_LIB_USER, KMPROV_R_VERIFY_ERROR); OPENSSL_free(pretbs); CompositeSignature_free(cs); goto end; }

            if (get_kmname_fromtls(name)) {
                if (OQS_SIG_verify(pq, pretbs, prelen, buf, blen, k->comp_pubkey[i]) != OQS_SUCCESS) {
                    ERR_raise(ERR_LIB_USER, KMPROV_R_VERIFY_ERROR); OPENSSL_free(name); OPENSSL_free(pretbs); CompositeSignature_free(cs); goto end;
                }
            } else {
                if (name[0] == 'e') {
                    EVP_MD_CTX *m = EVP_MD_CTX_new();
                    if (!m || EVP_DigestVerifyInit(m, NULL, NULL, NULL, k->classical_pkey) <= 0 ||
                        EVP_DigestVerify(m, buf, blen, pretbs, prelen) <= 0) {
                        ERR_raise(ERR_LIB_USER, KMPROV_R_VERIFY_ERROR);
                        EVP_MD_CTX_free(m); OPENSSL_free(name); OPENSSL_free(pretbs); CompositeSignature_free(cs); goto end;
                    }
                    EVP_MD_CTX_free(m);
                } else {
                    EVP_PKEY_CTX *pc = EVP_PKEY_CTX_new(k->classical_pkey, NULL);
                    if (!pc || EVP_PKEY_verify_init(pc) <= 0) { ERR_raise(ERR_LIB_USER, KMPROV_R_VERIFY_ERROR); EVP_PKEY_CTX_free(pc); OPENSSL_free(name); OPENSSL_free(pretbs); CompositeSignature_free(cs); goto end; }
                    int is_pss = !strncmp(name, "pss", 3);
                    if (!setup_rsa_padding(pc, is_pss, name)) { ERR_raise(ERR_LIB_USER, KMPROV_R_WRONG_PARAMETERS); EVP_PKEY_CTX_free(pc); OPENSSL_free(name); OPENSSL_free(pretbs); CompositeSignature_free(cs); goto end; }

                    int dlen = sha512_mode ? SHA512_DIGEST_LENGTH : SHA256_DIGEST_LENGTH;
                    unsigned char dig[SHA512_DIGEST_LENGTH];
                    if (sha512_mode) SHA512(pretbs, prelen, dig); else SHA256(pretbs, prelen, dig);

                    const EVP_MD *md = sha512_mode ? EVP_sha512() : EVP_sha256();
                    if (EVP_PKEY_CTX_set_signature_md(pc, md) <= 0 ||
                        EVP_PKEY_verify(pc, buf, blen, dig, dlen) <= 0) {
                        ERR_raise(ERR_LIB_USER, KMPROV_R_VERIFY_ERROR);
                        EVP_PKEY_CTX_free(pc); OPENSSL_free(name); OPENSSL_free(pretbs); CompositeSignature_free(cs); goto end;
                    }
                    EVP_PKEY_CTX_free(pc);
                }
            }
            OPENSSL_free(name);
        }
        OPENSSL_free(pretbs);
        CompositeSignature_free(cs);
    } else {
        /* PQ tunggal (atau sisa hybrid setelah klasik) */
        if (!k->comp_pubkey[k->numkeys-1]) { ERR_raise(ERR_LIB_USER, KMPROV_R_WRONG_PARAMETERS); goto end; }
        if (OQS_SIG_verify(pq, tbs, tbslen, sig + idx, siglen - idx, k->comp_pubkey[k->numkeys-1]) != OQS_SUCCESS) {
            ERR_raise(ERR_LIB_USER, KMPROV_R_VERIFY_ERROR); goto end;
        }
    }

    ok = 1;
end:
    EVP_PKEY_CTX_free(vctx_classic);
    KMSIG_LOG1("verify rv=%d\n", ok);
    return ok;
}

/* ============================================================
 * GET/SET PARAMS
 * ============================================================ */
static int km_sig_get_ctx_params(void *vctx, OSSL_PARAM *params) {
    PROV_KMSIG_CTX *c = (PROV_KMSIG_CTX *)vctx;
    if (!c || !params) return 0;

    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (c->aid == NULL) c->aid_len = get_aid(&c->aid, c->sig->tls_name);
    if (p && !OSSL_PARAM_set_octet_string(p, c->aid, c->aid_len)) return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p && !OSSL_PARAM_set_utf8_string(p, c->mdname)) return 0;

    return 1;
}
static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM *km_sig_gettable_ctx_params(void *vctx, void *provctx) {
    (void)vctx; (void)provctx; return known_gettable_ctx_params;
}

static int km_sig_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    PROV_KMSIG_CTX *c = (PROV_KMSIG_CTX *)vctx;
    if (!c || !params) return 0;

    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p && !c->flag_allow_md) return 0;
    if (p) {
        char mdname[OSSL_MAX_NAME_SIZE] = "", *pmd = mdname;
        char mdprops[OSSL_MAX_PROPQUERY_SIZE] = "", *pprops = mdprops;
        const OSSL_PARAM *pp = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PROPERTIES);

        if (!OSSL_PARAM_get_utf8_string(p, &pmd, sizeof(mdname))) return 0;
        if (pp && !OSSL_PARAM_get_utf8_string(pp, &pprops, sizeof(mdprops))) return 0;
        if (!km_sig_setup_md(c, mdname, mdprops)) return 0;
    }
    return 1;
}
static const OSSL_PARAM known_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM *km_sig_settable_ctx_params(void *vctx, void *provctx) {
    (void)vctx; (void)provctx; return known_settable_ctx_params;
}

static int km_sig_get_ctx_md_params(void *vctx, OSSL_PARAM *params) {
    PROV_KMSIG_CTX *c = (PROV_KMSIG_CTX *)vctx;
    if (!c->mdctx) return 0;
    return EVP_MD_CTX_get_params(c->mdctx, params);
}
static const OSSL_PARAM *km_sig_gettable_ctx_md_params(void *vctx) {
    PROV_KMSIG_CTX *c = (PROV_KMSIG_CTX *)vctx;
    if (!c->md) return 0;
    return EVP_MD_gettable_ctx_params(c->md);
}
static int km_sig_set_ctx_md_params(void *vctx, const OSSL_PARAM params[]) {
    PROV_KMSIG_CTX *c = (PROV_KMSIG_CTX *)vctx;
    if (!c->mdctx) return 0;
    return EVP_MD_CTX_set_params(c->mdctx, params);
}
static const OSSL_PARAM *km_sig_settable_ctx_md_params(void *vctx) {
    PROV_KMSIG_CTX *c = (PROV_KMSIG_CTX *)vctx;
    if (!c->md) return 0;
    return EVP_MD_settable_ctx_params(c->md);
}

/* ============================================================
 * DISPATCH TABLE — tetap sama
 * ============================================================ */
const OSSL_DISPATCH km_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,               (void(*)(void))km_sig_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,           (void(*)(void))km_sig_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN,                (void(*)(void))km_sig_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,         (void(*)(void))km_sig_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY,              (void(*)(void))km_sig_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,    (void(*)(void))km_sig_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,  (void(*)(void))km_sig_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,   (void(*)(void))km_sig_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,  (void(*)(void))km_sig_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,(void(*)(void))km_sig_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void(*)(void))km_sig_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_FREECTX,             (void(*)(void))km_sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX,              (void(*)(void))km_sig_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,      (void(*)(void))km_sig_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void(*)(void))km_sig_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,      (void(*)(void))km_sig_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void(*)(void))km_sig_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,   (void(*)(void))km_sig_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,(void(*)(void))km_sig_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,   (void(*)(void))km_sig_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,(void(*)(void))km_sig_settable_ctx_md_params },
    { 0, NULL }
};
