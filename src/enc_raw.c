#include "km_provider.h"
#include "km_util_io.h"
#include "km_kem.h"      /* agar kenal KM_KEM_KEY */
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h> /* EVP_EncodeBlock */
#include <stdio.h>
#include <string.h>

/* ctx encoder minimal */
typedef struct {
    KM_PROVCTX *provctx;
} KM_ENC_CTX;

static void *km_enc_newctx(void *vprovctx) {
    KM_ENC_CTX *c = OPENSSL_zalloc(sizeof(*c));
    if (!c) return NULL;
    c->provctx = (KM_PROVCTX*)vprovctx;
    return c;
}
static void km_enc_freectx(void *v) { OPENSSL_free(v); }

static int km_enc_does_selection(void *v, int selection) {
    (void)v;
    return (selection & (OSSL_KEYMGMT_SELECT_PUBLIC_KEY|OSSL_KEYMGMT_SELECT_PRIVATE_KEY)) ? 1 : 0;
}

/* ambil raw dari SIG/KEM key */
static int km_extract_raw(const void *obj, int selection,
                          const unsigned char **data, size_t *dlen,
                          const char **alg_label, int *is_priv)
{
    if (!obj || !data || !dlen) return 0;
    *data = NULL; *dlen = 0; *is_priv = 0;

    const KM_SIG_KEY *sk = (const KM_SIG_KEY*)obj;
    const KM_KEM_KEY *kk = (const KM_KEM_KEY*)obj;

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        if (sk && sk->priv && sk->privlen) { *data=sk->priv; *dlen=sk->privlen; *is_priv=1; *alg_label=km_label_for_alg(sk->alg_name); return 1; }
        if (kk && kk->priv && kk->privlen) { *data=kk->priv; *dlen=kk->privlen; *is_priv=1; *alg_label=km_label_for_alg(kk->alg_name); return 1; }
        return 0;
    }
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        if (sk && sk->pub && sk->publen)   { *data=sk->pub; *dlen=sk->publen; *is_priv=0; *alg_label=km_label_for_alg(sk->alg_name); return 1; }
        if (kk && kk->pub && kk->publen)   { *data=kk->pub; *dlen=kk->publen; *is_priv=0; *alg_label=km_label_for_alg(kk->alg_name); return 1; }
        return 0;
    }
    return 0;
}

static int core_write_all(KM_PROVCTX *prov, OSSL_CORE_BIO *b, const void *buf, size_t len) {
    if (!prov || !prov->core_bio_write_ex) return 0;
    size_t off = 0, w = 0;
    while (off < len) {
        if (!prov->core_bio_write_ex(b, (const unsigned char*)buf + off, len - off, &w) || w == 0)
            return 0;
        off += w;
    }
    return 1;
}

/* ============= ENCODE DER (raw bytes) ============= */
static int km_enc_encode_der(void *v,
                             OSSL_CORE_BIO *cout,
                             const void *obj, const OSSL_PARAM keyparams[],
                             int selection,
                             OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pwarg)
{
    (void)keyparams; (void)pw_cb; (void)pwarg;
    KM_ENC_CTX *c = (KM_ENC_CTX*)v;
    const unsigned char *buf=NULL; size_t blen=0; const char *al="UNKNOWN"; int is_priv=0;
    if (!km_extract_raw(obj, selection, &buf, &blen, &al, &is_priv)) return 0;
    return core_write_all(c->provctx, cout, buf, blen);
}

/* ============= ENCODE PEM (ASCII, base64) ============= */
static int km_enc_encode_pem(void *v,
                             OSSL_CORE_BIO *cout,
                             const void *obj, const OSSL_PARAM keyparams[],
                             int selection,
                             OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pwarg)
{
    (void)keyparams; (void)pw_cb; (void)pwarg;
    KM_ENC_CTX *c = (KM_ENC_CTX*)v;
    const unsigned char *buf=NULL; size_t blen=0; const char *al="UNKNOWN"; int is_priv=0;
    if (!km_extract_raw(obj, selection, &buf, &blen, &al, &is_priv)) return 0;

    char header[96], footer[96];
    snprintf(header, sizeof(header), "-----BEGIN %s %s KEY-----\n", al, is_priv ? "PRIVATE" : "PUBLIC");
    snprintf(footer, sizeof(footer), "-----END %s %s KEY-----\n",   al, is_priv ? "PRIVATE" : "PUBLIC");

    if (!core_write_all(c->provctx, cout, header, strlen(header))) return 0;

    size_t b64cap = 4 * ((blen + 2) / 3) + 4;
    unsigned char *b64 = OPENSSL_malloc(b64cap);
    if (!b64) return 0;
    int enclen = EVP_EncodeBlock(b64, buf, (int)blen);
    if (enclen <= 0) { OPENSSL_free(b64); return 0; }

    /* pecah per 64 kolom */
    for (int i = 0; i < enclen; i += 64) {
        int chunk = (enclen - i > 64) ? 64 : (enclen - i);
        if (!core_write_all(c->provctx, cout, b64 + i, (size_t)chunk)) { OPENSSL_free(b64); return 0; }
        if (!core_write_all(c->provctx, cout, "\n", 1)) { OPENSSL_free(b64); return 0; }
    }
    OPENSSL_free(b64);

    return core_write_all(c->provctx, cout, footer, strlen(footer));
}

/* Dua tabel fungsi—sama, beda ENCODE-nya */
static const OSSL_DISPATCH km_encoder_der_fns[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (void (*)(void))km_enc_newctx },
    { OSSL_FUNC_ENCODER_FREECTX,        (void (*)(void))km_enc_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))km_enc_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE,         (void (*)(void))km_enc_encode_der },
    { 0, NULL }
};
static const OSSL_DISPATCH km_encoder_pem_fns[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (void (*)(void))km_enc_newctx },
    { OSSL_FUNC_ENCODER_FREECTX,        (void (*)(void))km_enc_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))km_enc_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE,         (void (*)(void))km_enc_encode_pem },
    { 0, NULL }
};

/* Daftarkan dua output via properties (OpenSSL 3.0) */
const OSSL_ALGORITHM km_algs_encoder[] = {
    /* DER/raw */
    { "mldsa44",  "output=DER,structure=raw", km_encoder_der_fns },
    { "mldsa65",  "output=DER,structure=raw", km_encoder_der_fns },
    { "mldsa87",  "output=DER,structure=raw", km_encoder_der_fns },
    { "MLKEM512", "output=DER,structure=raw", km_encoder_der_fns },
    { "MLKEM768", "output=DER,structure=raw", km_encoder_der_fns },
    { "MLKEM1024","output=DER,structure=raw", km_encoder_der_fns },
    /* PEM/raw */
    { "mldsa44",  "output=PEM,structure=raw", km_encoder_pem_fns },
    { "mldsa65",  "output=PEM,structure=raw", km_encoder_pem_fns },
    { "mldsa87",  "output=PEM,structure=raw", km_encoder_pem_fns },
    { "MLKEM512", "output=PEM,structure=raw", km_encoder_pem_fns },
    { "MLKEM768", "output=PEM,structure=raw", km_encoder_pem_fns },
    { "MLKEM1024","output=PEM,structure=raw", km_encoder_pem_fns },
    { NULL, NULL, NULL }
};
