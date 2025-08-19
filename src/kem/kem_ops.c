#include "km_kem.h"
#include <openssl/params.h>
#include <string.h>

/* ctx KEM */
typedef struct {
    KM_PROVCTX *provctx;
    KM_KEM_KEY  *key;   /* bukan pemilik */
} KM_KEM_CTX;

static void *kem_newctx(void *vprovctx) {
    KM_KEM_CTX *c = OPENSSL_zalloc(sizeof(*c));
    if (!c) return NULL;
    c->provctx = (KM_PROVCTX*)vprovctx;
    return c;
}
static void kem_freectx(void *v) {
    KM_KEM_CTX *c = (KM_KEM_CTX*)v; OPENSSL_free(c);
}
static void *kem_dupctx(void *v) {
    KM_KEM_CTX *c = (KM_KEM_CTX*)v; if (!c) return NULL;
    return OPENSSL_memdup(c, sizeof(*c));
}

/* init */
static int kem_encaps_init(void *vctx, void *vkey, const OSSL_PARAM params[]) {
    (void)params;
    KM_KEM_CTX *c = (KM_KEM_CTX*)vctx;
    c->key = (KM_KEM_KEY*)vkey;
    return c->key && km_kem_ensure(c->key) && c->key->pub && c->key->publen;
}
static int kem_decaps_init(void *vctx, void *vkey, const OSSL_PARAM params[]) {
    (void)params;
    KM_KEM_CTX *c = (KM_KEM_CTX*)vctx;
    c->key = (KM_KEM_KEY*)vkey;
    return c->key && km_kem_ensure(c->key) && c->key->priv && c->key->privlen;
}

/* ops */
static int kem_encaps(void *vctx,
                      unsigned char *ct, size_t *ctlen,
                      unsigned char *secret, size_t *secretlen) {
    KM_KEM_CTX *c = (KM_KEM_CTX*)vctx;
    if (!c || !c->key || !c->key->kem) return 0;

    size_t need_ct = c->key->kem->length_ciphertext;
    size_t need_ss = c->key->kem->length_shared_secret;

    if (!ct || !secret) { if (ctlen) *ctlen = need_ct; if (secretlen) *secretlen = need_ss; return 1; }
    if (*ctlen < need_ct || *secretlen < need_ss) return 0;

    if (OQS_KEM_encaps(c->key->kem, ct, secret, c->key->pub) != OQS_SUCCESS) return 0;
    *ctlen = need_ct; *secretlen = need_ss;
    return 1;
}

static int kem_decaps(void *vctx,
                      unsigned char *secret, size_t *secretlen,
                      const unsigned char *ct, size_t ctlen) {
    KM_KEM_CTX *c = (KM_KEM_CTX*)vctx;
    if (!c || !c->key || !c->key->kem) return 0;

    size_t need_ct = c->key->kem->length_ciphertext;
    size_t need_ss = c->key->kem->length_shared_secret;

    if (!secret) { if (secretlen) *secretlen = need_ss; return 1; }
    if (ctlen != need_ct || *secretlen < need_ss) return 0;

    if (OQS_KEM_decaps(c->key->kem, secret, ct, c->key->priv) != OQS_SUCCESS) return 0;
    *secretlen = need_ss;
    return 1;
}

/* (tidak pakai params khusus) */
static int kem_get_ctx_params(void *v, OSSL_PARAM params[]) { (void)v; (void)params; return 1; }
static const OSSL_PARAM *kem_gettable_ctx_params(void *v, void *p) { (void)v; (void)p; static const OSSL_PARAM t[] = { OSSL_PARAM_END }; return t; }
static int kem_set_ctx_params(void *v, const OSSL_PARAM params[]) { (void)v; (void)params; return 1; }
static const OSSL_PARAM *kem_settable_ctx_params(void *v, void *p) { (void)v; (void)p; static const OSSL_PARAM t[] = { OSSL_PARAM_END }; return t; }

/* satu tabel fungsi untuk semua MLKEM* */
static const OSSL_DISPATCH km_kem_fns[] = {
    { OSSL_FUNC_KEM_NEWCTX,                (void (*)(void))kem_newctx },
    { OSSL_FUNC_KEM_FREECTX,               (void (*)(void))kem_freectx },
    { OSSL_FUNC_KEM_DUPCTX,                (void (*)(void))kem_dupctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT,      (void (*)(void))kem_encaps_init },
    { OSSL_FUNC_KEM_ENCAPSULATE,           (void (*)(void))kem_encaps },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT,      (void (*)(void))kem_decaps_init },
    { OSSL_FUNC_KEM_DECAPSULATE,           (void (*)(void))kem_decaps },
    { OSSL_FUNC_KEM_GET_CTX_PARAMS,        (void (*)(void))kem_get_ctx_params },
    { OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS,   (void (*)(void))kem_gettable_ctx_params },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS,        (void (*)(void))kem_set_ctx_params },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,   (void (*)(void))kem_settable_ctx_params },
    { 0, NULL }
};

/* daftar algoritma KEM, di-export ke provider_core.c */
const OSSL_ALGORITHM km_algs_kem[] = {
    { "MLKEM512",  NULL, km_kem_fns },
    { "MLKEM768",  NULL, km_kem_fns },
    { "MLKEM1024", NULL, km_kem_fns },
    { NULL, NULL, NULL }
};
