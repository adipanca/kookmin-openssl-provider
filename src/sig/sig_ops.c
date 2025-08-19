#include "km_provider.h"
#include <string.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

typedef struct {
    KM_PROVCTX *provctx;
    KM_SIG_KEY *key;
} KM_SIG_CTX;

static void *km_sig_newctx(void *vprovctx, const char *propq){
    (void)propq;
    KM_SIG_CTX *c = OPENSSL_zalloc(sizeof(*c));
    if (!c) return NULL;
    c->provctx = (KM_PROVCTX*)vprovctx;
    return c;
}
static void km_sig_freectx(void *vctx){ OPENSSL_free(vctx); }
static void *km_sig_dupctx(void *vctx){
    KM_SIG_CTX *c = (KM_SIG_CTX*)vctx;
    return c ? OPENSSL_memdup(c, sizeof(*c)) : NULL;
}

static int km_sig_sign_init(void *vctx, void *vkey, const OSSL_PARAM params[]){
    (void)params;
    KM_SIG_CTX *c = (KM_SIG_CTX*)vctx;
    c->key = (KM_SIG_KEY*)vkey;
    return c->key && c->key->priv && c->key->privlen;
}
static int km_sig_verify_init(void *vctx, void *vkey, const OSSL_PARAM params[]){
    (void)params;
    KM_SIG_CTX *c = (KM_SIG_CTX*)vctx;
    c->key = (KM_SIG_KEY*)vkey;
    return c->key && c->key->pub && c->key->publen;
}

static int km_sig_sign(void *vctx, unsigned char *sig, size_t *siglen, size_t sigsize,
                       const unsigned char *tbs, size_t tbslen){
    KM_SIG_CTX *c = (KM_SIG_CTX*)vctx;
    if (!c || !c->key || !c->key->sig) return 0;
    size_t need = c->key->sig->length_signature;
    if (!sig) { *siglen = need; return 1; }
    if (sigsize < need) return 0;
    return (OQS_SIG_sign(c->key->sig, sig, siglen, tbs, tbslen, c->key->priv) == OQS_SUCCESS);
}
static int km_sig_verify(void *vctx, const unsigned char *sig, size_t siglen,
                         const unsigned char *tbs, size_t tbslen){
    KM_SIG_CTX *c = (KM_SIG_CTX*)vctx;
    if (!c || !c->key || !c->key->sig) return 0;
    return (OQS_SIG_verify(c->key->sig, tbs, tbslen, sig, siglen, c->key->pub) == OQS_SUCCESS);
}

/* ---- ctx params ---- */
static int km_sig_get_ctx_params(void *vctx, OSSL_PARAM params[]){ (void)vctx; (void)params; return 1; }
static const OSSL_PARAM *km_sig_gettable_ctx_params(void *vctx, void *provctx){
    (void)vctx; (void)provctx;
    static const OSSL_PARAM tl[] = { OSSL_PARAM_END };
    return tl;
}

/* NEW: allow digestless (accept DIGEST if absent or empty) */
static int km_sig_set_ctx_params(void *vctx, const OSSL_PARAM params[]){
    (void)vctx;
    if (!params) return 1;
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (!p) return 1; /* no digest requested -> fine (pure) */
    const char *mdname = NULL;
    if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdname)) return 0;
    /* reject if non-empty digest requested */
    return (mdname == NULL || mdname[0] == '\0');
}
static const OSSL_PARAM *km_sig_settable_ctx_params(void *vctx, void *provctx){
    (void)vctx; (void)provctx;
    static const OSSL_PARAM tl[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_END
    };
    return tl;
}

/* dispatch */
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
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,      (void (*)(void))km_sig_set_ctx_params },      /* NEW */
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))km_sig_settable_ctx_params }, /* NEW */
    { 0, NULL }
};

const OSSL_ALGORITHM km_algs_signature[] = {
    { "mldsa44", NULL, km_sig_fns },
    { "mldsa65", NULL, km_sig_fns },
    { "mldsa87", NULL, km_sig_fns },
    { NULL, NULL, NULL }
};
