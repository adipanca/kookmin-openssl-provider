#include "km_provider.h"
#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>

/* ---------- forward ---------- */
extern const OSSL_ALGORITHM km_algs_signature[];   /* sig_ops.c */
extern const OSSL_ALGORITHM km_algs_kem[];         /* kem_ops.c */
extern const OSSL_ALGORITHM km_algs_encoder[];
extern const OSSL_ALGORITHM km_algs_decoder[];

extern const OSSL_DISPATCH km_sig_keymgmt_fns_mldsa44[]; /* sig_keymgmt.c */
extern const OSSL_DISPATCH km_sig_keymgmt_fns_mldsa65[];
extern const OSSL_DISPATCH km_sig_keymgmt_fns_mldsa87[];

extern const OSSL_DISPATCH km_kem_keymgmt_fns_mlkem512[]; /* kem_keymgmt.c */
extern const OSSL_DISPATCH km_kem_keymgmt_fns_mlkem768[];
extern const OSSL_DISPATCH km_kem_keymgmt_fns_mlkem1024[];

/* gabungan KEYMGMT: SIG + KEM */
static const OSSL_ALGORITHM km_algs_keymgmt_all[] = {
    { "mldsa44",   NULL, km_sig_keymgmt_fns_mldsa44 },
    { "mldsa65",   NULL, km_sig_keymgmt_fns_mldsa65 },
    { "mldsa87",   NULL, km_sig_keymgmt_fns_mldsa87 },
    { "MLKEM512",  NULL, km_kem_keymgmt_fns_mlkem512 },
    { "MLKEM768",  NULL, km_kem_keymgmt_fns_mlkem768 },
    { "MLKEM1024", NULL, km_kem_keymgmt_fns_mlkem1024 },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *km_query_operation(void *provctx, int op, int *no_cache) {
    (void)provctx; (void)no_cache;
    *no_cache = 0; // Set untuk semua operasi
    switch (op) {
        case OSSL_OP_SIGNATURE: return km_algs_signature;
        case OSSL_OP_KEM:       return km_algs_kem;          /* <-- baru */
        case OSSL_OP_KEYMGMT:   return km_algs_keymgmt_all;  /* <-- gabungan */
        case OSSL_OP_ENCODER:   return km_algs_encoder;   // <— baru
        case OSSL_OP_DECODER:   return km_algs_decoder;   // <— baru
        default:                return NULL;
    }
}

static const OSSL_PARAM *km_gettable_params(void *provctx) {
    (void)provctx;
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
        OSSL_PARAM_END
    };
    return gettable;
}

static int km_get_params(void *provctx, OSSL_PARAM params[]) {
    (void)provctx;
    OSSL_PARAM *p;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p && !OSSL_PARAM_set_utf8_ptr(p, "kookminlib")) return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p && !OSSL_PARAM_set_utf8_ptr(p, "0.1.0")) return 0;
    return 1;
}

KM_PROVCTX *km_provctx_new(const OSSL_CORE_HANDLE *handle) {
    KM_PROVCTX *p = OPENSSL_zalloc(sizeof(*p));
    if (!p) return NULL;
    p->handle = handle;
    p->libctx = NULL;
    return p;
}
void km_provctx_free(KM_PROVCTX *p) { OPENSSL_free(p); }
static void km_teardown(void *vprovctx) { km_provctx_free((KM_PROVCTX*)vprovctx); }

static const OSSL_DISPATCH km_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))km_query_operation },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))km_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,      (void (*)(void))km_get_params },
    { OSSL_FUNC_PROVIDER_TEARDOWN,        (void (*)(void))km_teardown },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx) {
    fprintf(stderr, "[DEBUG] Provider init called\n");
    (void)in;
    KM_PROVCTX *p = km_provctx_new(handle);
    if (!p) return 0;
    /* Ambil fungsi Core BIO yang tersedia di 3.0 */
    for (const OSSL_DISPATCH *f = in; f && f->function_id != 0; f++) {
        switch (f->function_id) {
        case OSSL_FUNC_BIO_WRITE_EX:
            p->core_bio_write_ex = OSSL_FUNC_BIO_write_ex(f);
            break;
        case OSSL_FUNC_BIO_READ_EX:
            p->core_bio_read_ex  = OSSL_FUNC_BIO_read_ex(f);
            break;
        default:
            break;
        }
    }
    *provctx = p;
    *out = km_dispatch_table;
    fprintf(stderr, "[DEBUG] Provider init successful\n");
    return 1;
}
