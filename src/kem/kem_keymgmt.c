#include "km_kem.h"
#include "km_util.h"
#include <string.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

/* map EVP name -> liboqs name */
static const char *oqs_kem_from_alg(const char *alg) {
    if (!alg) return NULL;
    if (strcmp(alg, "MLKEM512")  == 0) return "ML-KEM-512";
    if (strcmp(alg, "MLKEM768")  == 0) return "ML-KEM-768";
    if (strcmp(alg, "MLKEM1024") == 0) return "ML-KEM-1024";
    return NULL;
}

int km_kem_ensure(KM_KEM_KEY *k) {
    if (k->kem) return 1;
    const char *oqs = oqs_kem_from_alg(k->alg_name);
    if (!oqs) return 0;
    k->kem = OQS_KEM_new(oqs);
    return k->kem != NULL;
}

/* ---------- NEW/FREE per varian (set alg_name) ---------- */
static KM_KEM_KEY *kem_new_common(void *vprovctx, const char *name) {
    KM_KEM_KEY *k = OPENSSL_zalloc(sizeof(*k));
    if (!k) return NULL;
    k->provctx = (KM_PROVCTX*)vprovctx;
    OPENSSL_strlcpy(k->alg_name, name, sizeof(k->alg_name));
    return k;
}
static void *kem_new_512(void *v)  { return kem_new_common(v, "MLKEM512"); }
static void *kem_new_768(void *v)  { return kem_new_common(v, "MLKEM768"); }
static void *kem_new_1024(void *v) { return kem_new_common(v, "MLKEM1024"); }

static void kem_free(void *vk) {
    KM_KEM_KEY *k = (KM_KEM_KEY*)vk;
    if (!k) return;
    if (k->kem) OQS_KEM_free(k->kem);
    OPENSSL_free(k->pub);
    OPENSSL_free(k->priv);
    OPENSSL_free(k);
}

/* ---------- GEN ---------- */
static int kem_gen_init(void *vctx, int sel, const OSSL_PARAM p[]) {
    (void)vctx; (void)sel; (void)p; return 1;
}

static void *kem_gen(void *vctx, OSSL_CALLBACK *cb, void *cbarg) {
    (void)cb; (void)cbarg;
    /* vctx = provctx di desain kita (sama pola dengan SIG) */
    KM_KEM_KEY *k = (KM_KEM_KEY*)vctx;
    /* Tapi untuk konsistensi, buat key baru sesuai alg_name dari 'k' kalau ada.
       Di sini lebih aman: treat vctx sbg KEM_KEY skeleton (dari NEW). */
    KM_KEM_KEY *out = kem_new_common(k ? k->provctx : NULL, k ? k->alg_name : NULL);
    if (!out) return NULL;
    if (!km_kem_ensure(out)) { kem_free(out); return NULL; }

    out->publen = out->kem->length_public_key;
    out->privlen = out->kem->length_secret_key;
    out->pub  = OPENSSL_malloc(out->publen);
    out->priv = OPENSSL_malloc(out->privlen);
    if (!out->pub || !out->priv) { kem_free(out); return NULL; }

    if (OQS_KEM_keypair(out->kem, out->pub, out->priv) != OQS_SUCCESS) { kem_free(out); return NULL; }
    return out;
}

static void kem_gen_cleanup(void *vctx) { (void)vctx; }

/* ---------- IMPORT/EXPORT ---------- */
static int kem_has(const void *vk, int sel) {
    const KM_KEM_KEY *k = (const KM_KEM_KEY*)vk;
    int ok = 1;
    if ((sel & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)  && !(k->pub  && k->publen)) ok = 0;
    if ((sel & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && !(k->priv && k->privlen)) ok = 0;
    return ok;
}

static const OSSL_PARAM *kem_imexport_types(int selector) {
    static const OSSL_PARAM pub[]  = { OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,  NULL, 0), OSSL_PARAM_END };
    static const OSSL_PARAM priv[] = { OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0), OSSL_PARAM_END };
    return (selector & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) ? priv : pub;
}

static int kem_import(void *vk, int selector, const OSSL_PARAM params[]) {
    KM_KEM_KEY *k = (KM_KEM_KEY*)vk;
    if (!km_kem_ensure(k)) return 0;

    if (selector & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        unsigned char *p=NULL; size_t n=0;
        if (!km_param_get_octet_string(params, OSSL_PKEY_PARAM_PUB_KEY, &p, &n)) return 0;
        OPENSSL_free(k->pub); k->pub = OPENSSL_malloc(n); if (!k->pub){OPENSSL_free(p);return 0;}
        memcpy(k->pub, p, n); k->publen = n; OPENSSL_free(p);
    }
    if (selector & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        unsigned char *p=NULL; size_t n=0;
        if (!km_param_get_octet_string(params, OSSL_PKEY_PARAM_PRIV_KEY, &p, &n)) return 0;
        OPENSSL_free(k->priv); k->priv = OPENSSL_malloc(n); if (!k->priv){OPENSSL_free(p);return 0;}
        memcpy(k->priv, p, n); k->privlen = n; OPENSSL_free(p);
    }
    return 1;
}

static int kem_export(void *vk, int selector, OSSL_CALLBACK *cb, void *cbarg) {
    KM_KEM_KEY *k = (KM_KEM_KEY*)vk;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new(); OSSL_PARAM *out=NULL; int ok=0;
    if (!bld) return 0;

    if (!km_param_build_pubpriv(bld,
        (selector & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)  ? k->pub  : NULL,
        (selector & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)  ? k->publen : 0,
        (selector & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) ? k->priv : NULL,
        (selector & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) ? k->privlen : 0,
        &out)) goto end;

    ok = cb(out, cbarg);

end:
    OSSL_PARAM_free(out); OSSL_PARAM_BLD_free(bld); return ok;
}

static int kem_get_params(void *vk, OSSL_PARAM *params) {
    KM_KEM_KEY *k = (KM_KEM_KEY*)vk;
    if (!km_kem_ensure(k)) return 0;
    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p) OSSL_PARAM_set_size_t(p, k->kem->length_public_key * 8);
    return 1;
}

/* ---------- DISPATCH per varian ---------- */
const OSSL_DISPATCH km_kem_keymgmt_fns_mlkem512[] = {
    { OSSL_FUNC_KEYMGMT_NEW,            (void (*)(void))kem_new_512 },
    { OSSL_FUNC_KEYMGMT_FREE,           (void (*)(void))kem_free },
    { OSSL_FUNC_KEYMGMT_GEN_INIT,       (void (*)(void))kem_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN,            (void (*)(void))kem_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,    (void (*)(void))kem_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_HAS,            (void (*)(void))kem_has },
    { OSSL_FUNC_KEYMGMT_IMPORT,         (void (*)(void))kem_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,   (void (*)(void))kem_imexport_types },
    { OSSL_FUNC_KEYMGMT_EXPORT,         (void (*)(void))kem_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,   (void (*)(void))kem_imexport_types },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,     (void (*)(void))kem_get_params },
    { 0, NULL }
};
const OSSL_DISPATCH km_kem_keymgmt_fns_mlkem768[]  = {
    { OSSL_FUNC_KEYMGMT_NEW,            (void (*)(void))kem_new_768 },
    { OSSL_FUNC_KEYMGMT_FREE,           (void (*)(void))kem_free },
    { OSSL_FUNC_KEYMGMT_GEN_INIT,       (void (*)(void))kem_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN,            (void (*)(void))kem_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,    (void (*)(void))kem_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_HAS,            (void (*)(void))kem_has },
    { OSSL_FUNC_KEYMGMT_IMPORT,         (void (*)(void))kem_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,   (void (*)(void))kem_imexport_types },
    { OSSL_FUNC_KEYMGMT_EXPORT,         (void (*)(void))kem_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,   (void (*)(void))kem_imexport_types },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,     (void (*)(void))kem_get_params },
    { 0, NULL }
};
const OSSL_DISPATCH km_kem_keymgmt_fns_mlkem1024[] = {
    { OSSL_FUNC_KEYMGMT_NEW,            (void (*)(void))kem_new_1024 },
    { OSSL_FUNC_KEYMGMT_FREE,           (void (*)(void))kem_free },
    { OSSL_FUNC_KEYMGMT_GEN_INIT,       (void (*)(void))kem_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN,            (void (*)(void))kem_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,    (void (*)(void))kem_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_HAS,            (void (*)(void))kem_has },
    { OSSL_FUNC_KEYMGMT_IMPORT,         (void (*)(void))kem_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,   (void (*)(void))kem_imexport_types },
    { OSSL_FUNC_KEYMGMT_EXPORT,         (void (*)(void))kem_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,   (void (*)(void))kem_imexport_types },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,     (void (*)(void))kem_get_params },
    { 0, NULL }
};
