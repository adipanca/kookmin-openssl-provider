#include "km_provider.h"
#include "km_util.h"
#include <string.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

/* ---------- MAP NAMA EVP -> NAMA OQS ---------- */
static const char *oqs_name_from_alg(const char *alg) {
    if (!alg) return NULL;
    if (strcmp(alg, "mldsa44") == 0) return "ML-DSA-44";
    if (strcmp(alg, "mldsa65") == 0) return "ML-DSA-65";
    if (strcmp(alg, "mldsa87") == 0) return "ML-DSA-87";
    return NULL;
}

static int ensure_sig(KM_SIG_KEY *k) {
    if (k->sig) return 1;
    const char *oqs = oqs_name_from_alg(k->alg_name);
    if (!oqs) return 0;
    k->sig = OQS_SIG_new(oqs);
    return k->sig != NULL;
}

/* ---------- KEYMGMT NEW/FREE (per algoritma) ---------- */
static KM_SIG_KEY *km_sig_keymgmt_new_common(void *vprovctx, const char *algname) {
    KM_PROVCTX *prov = (KM_PROVCTX*)vprovctx;
    KM_SIG_KEY *k = OPENSSL_zalloc(sizeof(*k));
    if (!k) return NULL;
    k->provctx = prov;
    OPENSSL_strlcpy(k->alg_name, algname, sizeof(k->alg_name));
    /* pub/priv/sig diinisialisasi saat import/gen */
    return k;
}

static void *km_sig_keymgmt_new_mldsa44(void *v) { return km_sig_keymgmt_new_common(v, "mldsa44"); }
static void *km_sig_keymgmt_new_mldsa65(void *v) { return km_sig_keymgmt_new_common(v, "mldsa65"); }
static void *km_sig_keymgmt_new_mldsa87(void *v) { return km_sig_keymgmt_new_common(v, "mldsa87"); }

static void km_sig_keymgmt_free(void *vkey) {
    KM_SIG_KEY *k = (KM_SIG_KEY*)vkey;
    if (!k) return;
    if (k->sig) OQS_SIG_free(k->sig);
    OPENSSL_free(k->pub);
    OPENSSL_free(k->priv);
    OPENSSL_free(k);
}

/* ---------- KEYGEN ---------- */
/* Kita tidak butuh genctx; gunakan provctx dan tentukan algoritma lewat *_new_common */
static int km_sig_keymgmt_gen_init(void *vctx, int selection, const OSSL_PARAM params[]) {
    (void)vctx; (void)selection; (void)params; return 1;
}

static void *km_sig_keymgmt_gen_do(void *vprovctx, const char *algname) {
    KM_SIG_KEY *k = km_sig_keymgmt_new_common(vprovctx, algname);
    if (!k) return NULL;
    if (!ensure_sig(k)) { km_sig_keymgmt_free(k); return NULL; }

    k->publen = k->sig->length_public_key;
    k->privlen = k->sig->length_secret_key;

    k->pub  = OPENSSL_malloc(k->publen);
    k->priv = OPENSSL_malloc(k->privlen);
    if (!k->pub || !k->priv) { km_sig_keymgmt_free(k); return NULL; }

    if (OQS_SIG_keypair(k->sig, k->pub, k->priv) != OQS_SUCCESS) {
        km_sig_keymgmt_free(k); return NULL;
    }
    return k;
}

static void *km_sig_keymgmt_gen_mldsa44(void *vctx, OSSL_CALLBACK *cb, void *cbarg) {
    (void)cb; (void)cbarg; return km_sig_keymgmt_gen_do(vctx, "mldsa44");
}
static void *km_sig_keymgmt_gen_mldsa65(void *vctx, OSSL_CALLBACK *cb, void *cbarg) {
    (void)cb; (void)cbarg; return km_sig_keymgmt_gen_do(vctx, "mldsa65");
}
static void *km_sig_keymgmt_gen_mldsa87(void *vctx, OSSL_CALLBACK *cb, void *cbarg) {
    (void)cb; (void)cbarg; return km_sig_keymgmt_gen_do(vctx, "mldsa87");
}

static void km_sig_keymgmt_gen_cleanup(void *vctx) { (void)vctx; }

/* ---------- IMPORT / EXPORT ---------- */
static int km_sig_keymgmt_has(const void *vkey, int selection) {
    const KM_SIG_KEY *k = (const KM_SIG_KEY*)vkey;
    int ok = 1;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)  && !(k->pub  && k->publen)) ok = 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && !(k->priv && k->privlen)) ok = 0;
    return ok;
}

static const OSSL_PARAM *km_sig_keymgmt_imexport_types(int selector) {
    static const OSSL_PARAM types_pub[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    static const OSSL_PARAM types_priv[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    switch (selector) {
        case OSSL_KEYMGMT_SELECT_PUBLIC_KEY:  return types_pub;
        case OSSL_KEYMGMT_SELECT_PRIVATE_KEY: return types_priv;
        default: return types_pub;
    }
}

static int km_sig_keymgmt_import(void *vkey, int selector, const OSSL_PARAM params[]) {
    KM_SIG_KEY *k = (KM_SIG_KEY*)vkey;
    if (!ensure_sig(k)) return 0;

    if (selector & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        unsigned char *p = NULL; size_t n = 0;
        if (!km_param_get_octet_string(params, OSSL_PKEY_PARAM_PUB_KEY, &p, &n)) return 0;
        OPENSSL_free(k->pub);
        k->pub = OPENSSL_malloc(n);
        if (!k->pub) { OPENSSL_free(p); return 0; }
        memcpy(k->pub, p, n); k->publen = n;
        OPENSSL_free(p);
    }
    if (selector & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        unsigned char *p = NULL; size_t n = 0;
        if (!km_param_get_octet_string(params, OSSL_PKEY_PARAM_PRIV_KEY, &p, &n)) return 0;
        OPENSSL_free(k->priv);
        k->priv = OPENSSL_malloc(n);
        if (!k->priv) { OPENSSL_free(p); return 0; }
        memcpy(k->priv, p, n); k->privlen = n;
        OPENSSL_free(p);
    }
    return 1;
}

static int km_sig_keymgmt_export(void *vkey, int selector, OSSL_CALLBACK *cb, void *cbarg) {
    KM_SIG_KEY *k = (KM_SIG_KEY*)vkey;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *out = NULL;
    int ok = 0;
    if (!bld) return 0;

    if (!km_param_build_pubpriv(bld,
        (selector & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)  ? k->pub  : NULL,
        (selector & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)  ? k->publen : 0,
        (selector & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) ? k->priv : NULL,
        (selector & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) ? k->privlen : 0,
        &out)) goto end;

    ok = cb(out, cbarg);

end:
    OSSL_PARAM_free(out);
    OSSL_PARAM_BLD_free(bld);
    return ok;
}

static int km_sig_keymgmt_get_params(void *vkey, OSSL_PARAM *params) {
    KM_SIG_KEY *k = (KM_SIG_KEY*)vkey;
    if (!ensure_sig(k)) return 0;
    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p) OSSL_PARAM_set_size_t(p, k->sig->length_public_key * 8);
    return 1;
}

/* ---------- DISPATCH TABLES (per algoritma) ---------- */
const OSSL_DISPATCH km_sig_keymgmt_fns_mldsa44[] = {
    { OSSL_FUNC_KEYMGMT_NEW,            (void (*)(void))km_sig_keymgmt_new_mldsa44 },
    { OSSL_FUNC_KEYMGMT_FREE,           (void (*)(void))km_sig_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_GEN_INIT,       (void (*)(void))km_sig_keymgmt_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN,            (void (*)(void))km_sig_keymgmt_gen_mldsa44 },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,    (void (*)(void))km_sig_keymgmt_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_HAS,            (void (*)(void))km_sig_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_IMPORT,         (void (*)(void))km_sig_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,   (void (*)(void))km_sig_keymgmt_imexport_types },
    { OSSL_FUNC_KEYMGMT_EXPORT,         (void (*)(void))km_sig_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,   (void (*)(void))km_sig_keymgmt_imexport_types },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,     (void (*)(void))km_sig_keymgmt_get_params },
    { 0, NULL }
};

const OSSL_DISPATCH km_sig_keymgmt_fns_mldsa65[] = {
    { OSSL_FUNC_KEYMGMT_NEW,            (void (*)(void))km_sig_keymgmt_new_mldsa65 },
    { OSSL_FUNC_KEYMGMT_FREE,           (void (*)(void))km_sig_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_GEN_INIT,       (void (*)(void))km_sig_keymgmt_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN,            (void (*)(void))km_sig_keymgmt_gen_mldsa65 },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,    (void (*)(void))km_sig_keymgmt_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_HAS,            (void (*)(void))km_sig_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_IMPORT,         (void (*)(void))km_sig_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,   (void (*)(void))km_sig_keymgmt_imexport_types },
    { OSSL_FUNC_KEYMGMT_EXPORT,         (void (*)(void))km_sig_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,   (void (*)(void))km_sig_keymgmt_imexport_types },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,     (void (*)(void))km_sig_keymgmt_get_params },
    { 0, NULL }
};

const OSSL_DISPATCH km_sig_keymgmt_fns_mldsa87[] = {
    { OSSL_FUNC_KEYMGMT_NEW,            (void (*)(void))km_sig_keymgmt_new_mldsa87 },
    { OSSL_FUNC_KEYMGMT_FREE,           (void (*)(void))km_sig_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_GEN_INIT,       (void (*)(void))km_sig_keymgmt_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN,            (void (*)(void))km_sig_keymgmt_gen_mldsa87 },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,    (void (*)(void))km_sig_keymgmt_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_HAS,            (void (*)(void))km_sig_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_IMPORT,         (void (*)(void))km_sig_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,   (void (*)(void))km_sig_keymgmt_imexport_types },
    { OSSL_FUNC_KEYMGMT_EXPORT,         (void (*)(void))km_sig_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,   (void (*)(void))km_sig_keymgmt_imexport_types },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,     (void (*)(void))km_sig_keymgmt_get_params },
    { 0, NULL }
};
