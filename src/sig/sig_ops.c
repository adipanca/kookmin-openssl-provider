#include "km_provider.h"
#include <string.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

/* Context SIGNATURE */
typedef struct {
    KM_PROVCTX *provctx;
    KM_SIG_KEY *key; /* tidak dimiliki; life-cycle dikelola KEYMGMT */
} KM_SIG_CTX;

/* --- lifecycle ctx --- */
static void *km_sig_newctx(void *vprovctx, const char *propq) {
    (void)propq;
    KM_SIG_CTX *c = OPENSSL_zalloc(sizeof(*c));
    if (!c) return NULL;
    c->provctx = (KM_PROVCTX*)vprovctx;
    return c;
}

static void km_sig_freectx(void *vctx) {
    KM_SIG_CTX *c = (KM_SIG_CTX*)vctx;
    OPENSSL_free(c);
}

static void *km_sig_dupctx(void *vctx) {
    KM_SIG_CTX *c = (KM_SIG_CTX*)vctx;
    if (!c) return NULL;
    KM_SIG_CTX *n = OPENSSL_memdup(c, sizeof(*c));
    return n;
}

/* --- init --- */
static int km_sig_sign_init(void *vctx, void *vkey, const OSSL_PARAM params[]) {
    (void)params;
    KM_SIG_CTX *c = (KM_SIG_CTX*)vctx;
    c->key = (KM_SIG_KEY*)vkey;
    return c->key && c->key->priv && c->key->privlen;
}

static int km_sig_verify_init(void *vctx, void *vkey, const OSSL_PARAM params[]) {
    (void)params;
    KM_SIG_CTX *c = (KM_SIG_CTX*)vctx;
    c->key = (KM_SIG_KEY*)vkey;
    return c->key && c->key->pub && c->key->publen;
}

/* --- sign/verify “pure” (tanpa digest) --- */
static int km_sig_sign(void *vctx,
                       unsigned char *sig, size_t *siglen, size_t sigsize,
                       const unsigned char *tbs, size_t tbslen) {
    KM_SIG_CTX *c = (KM_SIG_CTX*)vctx;
    if (!c || !c->key || !c->key->sig) return 0;

    size_t need = c->key->sig->length_signature;

    if (sig == NULL) { /* query size */
        *siglen = need;
        return 1;
    }
    if (sigsize < need) return 0;

    if (OQS_SIG_sign(c->key->sig, sig, siglen, tbs, tbslen, c->key->priv) != OQS_SUCCESS)
        return 0;

    return 1;
}

static int km_sig_verify(void *vctx,
                         const unsigned char *sig, size_t siglen,
                         const unsigned char *tbs, size_t tbslen) {
    KM_SIG_CTX *c = (KM_SIG_CTX*)vctx;
    if (!c || !c->key || !c->key->sig) return 0;
    return OQS_SIG_verify(c->key->sig, tbs, tbslen, sig, siglen, c->key->pub) == OQS_SUCCESS;
}

/* --- ctx params (tidak ada parameter khusus) --- */
static int km_sig_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
    (void)vctx; (void)params;
    return 1;
}

static const OSSL_PARAM *km_sig_gettable_ctx_params(void *vctx, void *provctx) {
    (void)vctx; (void)provctx;
    static const OSSL_PARAM gettable[] = { OSSL_PARAM_END };
    return gettable;
}

/* --- dispatch table --- */
static const OSSL_DISPATCH km_sig_fns[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,              (void (*)(void))km_sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX,             (void (*)(void))km_sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX,              (void (*)(void))km_sig_dupctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,           (void (*)(void))km_sig_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN,                (void (*)(void))km_sig_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,         (void (*)(void))km_sig_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY,              (void (*)(void))km_sig_verify },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,      (void (*)(void))km_sig_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))km_sig_gettable_ctx_params },
    { 0, NULL }
};

/* Penting: field kedua (property) = NULL (atau mis. "oqs=yes"), 
   JANGAN gabungkan property ke nama algoritma. */
/* daftar algoritma SIGNATURE */
const OSSL_ALGORITHM km_algs_signature[] = {
    { "mldsa44", NULL, km_sig_fns },
    { "mldsa65", NULL, km_sig_fns },
    { "mldsa87", NULL, km_sig_fns },
    { NULL, NULL, NULL }
};

