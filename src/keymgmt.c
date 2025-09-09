// SPDX-License-Identifier: Apache-2.0 AND MIT
// KM OpenSSL 3 provider

#include <assert.h>
#include <stdarg.h>
#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/bio.h>

#include "openssl/param_build.h"
#include "provider.h"

/* =========================================================================
 * Logging (opt-in via env var KMKM) & small utils
 * ========================================================================= */
#if defined(NDEBUG)
#  define KM_LOG0(msg)            do {} while (0)
#  define KM_LOG1(fmt,a)          do {} while (0)
#  define KM_LOG2(fmt,a,b)        do {} while (0)
#else
static int km_log_enabled(void) { return getenv("KMKM") != NULL; }
#  define KM_LOG0(msg)            do { if (km_log_enabled()) printf("%s", (msg)); } while (0)
#  define KM_LOG1(fmt,a)          do { if (km_log_enabled()) printf((fmt), (a)); } while (0)
#  define KM_LOG2(fmt,a,b)        do { if (km_log_enabled()) printf((fmt), (a), (b)); } while (0)
#endif

/* Centralized non-OpenSSL error space for this provider */
enum {
    KM_ERR_UNEXPECTED_NULL = 1
};

/* ----------------------------------------------------------------------------
 * Wrapper: set octet string either via builder or direct param array.
 * (mengganti fungsi lama kmx_param_build_set_octet_string, tapi kompatibel)
 * ---------------------------------------------------------------------------- */
static int km_param_set_octets(OSSL_PARAM_BLD *bld, OSSL_PARAM *params,
                               const char *key,
                               const unsigned char *data, size_t len)
{
    if (bld != NULL)
        return OSSL_PARAM_BLD_push_octet_string(bld, key, data, len);

    OSSL_PARAM *p = OSSL_PARAM_locate(params, key);
    if (p != NULL)
        return OSSL_PARAM_set_octet_string(p, data, len);

    /* Tidak ada param dengan key tsb: bukan error fatal (tetap sukses) */
    return 1;
}

/* =========================================================================
 * Keymgmt forward decls (OpenSSL dispatch typedefs)
 * ========================================================================= */
static OSSL_FUNC_keymgmt_gen_cleanup_fn        kmx_gen_cleanup;
static OSSL_FUNC_keymgmt_load_fn               kmx_load;
static OSSL_FUNC_keymgmt_get_params_fn         kmx_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn    km_gettable_params;
static OSSL_FUNC_keymgmt_set_params_fn         kmx_set_params;
static OSSL_FUNC_keymgmt_settable_params_fn    kmx_settable_params;
static OSSL_FUNC_keymgmt_has_fn                kmx_has;
static OSSL_FUNC_keymgmt_match_fn              kmx_match;
static OSSL_FUNC_keymgmt_import_fn             kmx_import;
static OSSL_FUNC_keymgmt_import_types_fn       km_imexport_types;
static OSSL_FUNC_keymgmt_export_fn             kmx_export;
static OSSL_FUNC_keymgmt_export_types_fn       km_imexport_types;

/* =========================================================================
 * Key generation context
 * ========================================================================= */
struct kmx_gen_ctx {
    OSSL_LIB_CTX *libctx;
    char *propq;
    char *km_name;
    char *cmp_name;     /* kept for API parity */
    char *tls_name;
    int   primitive;
    int   selection;
    int   bit_security;
    int   alg_idx;
    int   reverse_share;
};

/* =========================================================================
 * Helpers: selection/availability, hybrid handling
 * ========================================================================= */
static int kmx_has(const void *keydata, int selection)
{
    const KMX_KEY *key = (const KMX_KEY *)keydata;
    int ok = 0;

    KM_LOG0("KMKEYMGMT: has\n");
    if (key != NULL) {
        ok = 1;
        if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
            ok = ok && (key->pubkey != NULL);
        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
            ok = ok && (key->privkey != NULL);
    }
    if (!ok) KM_LOG1("KMKEYMGMT: has -> FALSE (sel=%02x)\n", selection);
    return ok;
}

/* Tentukan urutan indeks komponen hibrida (klasik vs PQ) */
static void kmx_comp_pick_indices(const KMX_KEY *key, int *idx_classic, int *idx_pq)
{
    const int reverse_share = ( (key->keytype == KEY_TYPE_ECP_HYB_KEM
                              || key->keytype == KEY_TYPE_ECX_HYB_KEM) )
                              && key->reverse_share;

    if (reverse_share) {
        if (idx_classic) *idx_classic = key->numkeys - 1;
        if (idx_pq)      *idx_pq      = 0;
    } else {
        if (idx_classic) *idx_classic = 0;
        if (idx_pq)      *idx_pq      = key->numkeys - 1;
    }
}

/* Apakah key adalah hybrid? */
static int kmx_key_is_hybrid(const KMX_KEY *k)
{
    const int is_h =
        (k->keytype == KEY_TYPE_ECP_HYB_KEM ||
         k->keytype == KEY_TYPE_ECX_HYB_KEM ||
         k->keytype == KEY_TYPE_HYB_SIG) &&
        k->numkeys == 2 && k->classical_pkey != NULL;

    if (is_h) KM_LOG0("KMKEYMGMT: hybrid=1\n");
    return is_h ? 1 : 0;
}

/* =========================================================================
 * Match logic: sama seperti sebelumnya, tapi dirapikan
 * ========================================================================= */
static int kmx_match(const void *keydata1, const void *keydata2, int selection)
{
    const KMX_KEY *k1 = (const KMX_KEY *)keydata1;
    const KMX_KEY *k2 = (const KMX_KEY *)keydata2;
    int ok = 1;

    KM_LOG2("KMKEYMGMT: match sel=%d, k1=%p/k2=%p\n", selection, keydata2);

    if (k1 == NULL || k2 == NULL) {
        ERR_raise(ERR_LIB_USER, KMPROV_R_WRONG_PARAMETERS);
        return 0;
    }

    /* Private-only match */
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) &&
       !(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)) {

        if ((k1->privkey == NULL) != (k2->privkey == NULL) ||
            ((k1->tls_name && k2->tls_name) && strcmp(k1->tls_name, k2->tls_name) != 0)) {
            ok = 0;
        } else {
            ok = ((k1->privkey == NULL && k2->privkey == NULL) ||
                  (k1->privkey && CRYPTO_memcmp(k1->privkey, k2->privkey, k1->privkeylen) == 0));
        }
    }

    /* Public match (dengan “proxy” private jika diminta domain params) */
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        if ((k1->pubkey == NULL) != (k2->pubkey == NULL) ||
            ((k1->tls_name && k2->tls_name) && strcmp(k1->tls_name, k2->tls_name) != 0)) {
            ok = ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) &&
                 (k1->privkey && k2->privkey) &&
                 (CRYPTO_memcmp(k1->privkey, k2->privkey, k1->privkeylen) == 0));
        } else {
            ok = ok && ((k1->pubkey == NULL && k2->pubkey == NULL) ||
                        (k1->pubkey && CRYPTO_memcmp(k1->pubkey, k2->pubkey, k1->pubkeylen) == 0));
        }
    }

    if (!ok) KM_LOG0("KMKEYMGMT: match failed\n");
    return ok;
}

/* =========================================================================
 * Import / Export
 * ========================================================================= */
static int kmx_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    KMX_KEY *key = (KMX_KEY *)keydata;
    KM_LOG0("KMKEYMGMT: import\n");

    if (key == NULL) {
        ERR_raise(ERR_LIB_USER, KM_ERR_UNEXPECTED_NULL);
        return 0;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) && kmx_key_fromdata(key, params, 1))
        return 1;

    return 0;
}

static int kmx_key_to_params(const KMX_KEY *key, OSSL_PARAM_BLD *bld,
                             OSSL_PARAM params[], int include_private)
{
    if (key == NULL) return 0;

    if (key->pubkey) {
        if (key->pubkeylen == 0 ||
            !km_param_set_octets(bld, params, OSSL_PKEY_PARAM_PUB_KEY,
                                 key->pubkey, key->pubkeylen))
            return 0;
    }

    if (include_private && key->privkey) {
        if (key->privkeylen == 0 ||
            !km_param_set_octets(bld, params, OSSL_PKEY_PARAM_PRIV_KEY,
                                 key->privkey, key->privkeylen))
            return 0;
    }
    return 1;
}

/* Hybrid params writer; return 0 on success (ikut kontrak lama) */
static int kmx_put_hybrid_params(KMX_KEY *key, OSSL_PARAM params[])
{
    if (!kmx_key_is_hybrid(key))
        return 0;

    if (key->numkeys != 2) {
        KM_LOG1("KMKEYMGMT: hybrid but numkeys=%zu\n", key->numkeys);
        ERR_raise(ERR_LIB_PROV, KMPROV_R_INTERNAL_ERROR);
        return -1;
    }

    int i_c=0, i_pq=0;
    kmx_comp_pick_indices(key, &i_c, &i_pq);

    const void *c_pub = NULL, *c_priv = NULL, *pq_pub = NULL, *pq_priv = NULL;
    uint32_t c_pub_len = 0, c_priv_len = 0;
    int pq_pub_len = 0, pq_priv_len = 0;

    if (key->comp_pubkey && key->pubkey && key->comp_pubkey[i_c]) {
        c_pub = key->comp_pubkey[i_c];
        DECODE_UINT32(c_pub_len, key->pubkey);
    }
    if (key->comp_privkey && key->privkey && key->comp_privkey[i_c]) {
        c_priv = key->comp_privkey[i_c];
        DECODE_UINT32(c_priv_len, key->privkey);
    }
    if (key->comp_pubkey && key->comp_pubkey[i_pq]) {
        pq_pub = key->comp_pubkey[i_pq];
        pq_pub_len = (int)key->pubkeylen - (int)c_pub_len - (int)SIZE_OF_UINT32;
    }
    if (key->comp_privkey) {
        pq_priv = key->comp_privkey[i_pq];
        pq_priv_len = (int)key->privkeylen - (int)c_priv_len - (int)SIZE_OF_UINT32;
    }

    OSSL_PARAM *p;
    if ((p = OSSL_PARAM_locate(params, KM_HYBRID_PKEY_PARAM_CLASSICAL_PUB_KEY)) &&
        !OSSL_PARAM_set_octet_string(p, c_pub, c_pub_len)) return -1;
    if ((p = OSSL_PARAM_locate(params, KM_HYBRID_PKEY_PARAM_CLASSICAL_PRIV_KEY)) &&
        !OSSL_PARAM_set_octet_string(p, c_priv, c_priv_len)) return -1;
    if ((p = OSSL_PARAM_locate(params, KM_HYBRID_PKEY_PARAM_PQ_PUB_KEY)) &&
        !OSSL_PARAM_set_octet_string(p, pq_pub, pq_pub_len)) return -1;
    if ((p = OSSL_PARAM_locate(params, KM_HYBRID_PKEY_PARAM_PQ_PRIV_KEY)) &&
        !OSSL_PARAM_set_octet_string(p, pq_priv, pq_priv_len)) return -1;

    return 0;
}

static int kmx_export(void *keydata, int selection, OSSL_CALLBACK *cb, void *cbarg)
{
    KMX_KEY *key = (KMX_KEY *)keydata;
    KM_LOG0("KMKEYMGMT: export\n");

    if (key == NULL || cb == NULL) {
        ERR_raise(ERR_LIB_USER, KMPROV_R_WRONG_PARAMETERS);
        return 0;
    }

    OSSL_PARAM_BLD *b = OSSL_PARAM_BLD_new();
    if (b == NULL) {
        ERR_raise(ERR_LIB_USER, KM_ERR_UNEXPECTED_NULL);
        return 0;
    }

    int ok = 1;
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) {
        const int inc_priv = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) ? 1 : 0;
        ok = kmx_key_to_params(key, b, NULL, inc_priv);
    }

    OSSL_PARAM *ps = ok ? OSSL_PARAM_BLD_to_param(b) : NULL;
    if (ps == NULL) { ok = 0; }

    if (ok) {
        ok = cb(ps, cbarg);
        OSSL_PARAM_free(ps);
    }
    OSSL_PARAM_BLD_free(b);
    return ok;
}

/* =========================================================================
 * Get/Set params
 * ========================================================================= */
static int kmx_get_params(void *key_ptr, OSSL_PARAM params[])
{
    KMX_KEY *k = (KMX_KEY *)key_ptr;
    if (k == NULL || params == NULL) {
        ERR_raise(ERR_LIB_USER, KMPROV_R_WRONG_PARAMETERS);
        return 0;
    }

    KM_LOG1("KMKEYMGMT: get_params for %s\n", params[0].key);

    OSSL_PARAM *p;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) &&
        !OSSL_PARAM_set_int(p, kmx_key_secbits(k))) return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) &&
        !OSSL_PARAM_set_int(p, kmx_key_secbits(k))) return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) &&
        !OSSL_PARAM_set_int(p, kmx_key_maxsize(k))) return 0;

    /* Workaround digest fields */
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST)) &&
        !OSSL_PARAM_set_utf8_string(p, SN_undef)) return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST)) &&
        !OSSL_PARAM_set_utf8_string(p, SN_undef)) return 0;

    /* Encoded public key: untuk hybrid, sembunyikan prefix length klasik */
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY))) {
        if (k->keytype == KEY_TYPE_ECP_HYB_KEM || k->keytype == KEY_TYPE_ECX_HYB_KEM) {
            if (!OSSL_PARAM_set_octet_string(p,
                    (char *)k->pubkey + SIZE_OF_UINT32,
                    k->pubkeylen - SIZE_OF_UINT32)) return 0;
        } else {
            if (!OSSL_PARAM_set_octet_string(p, k->pubkey, k->pubkeylen)) return 0;
        }
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY)) &&
        !OSSL_PARAM_set_octet_string(p, k->pubkey, k->pubkeylen)) return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY)) &&
        !OSSL_PARAM_set_octet_string(p, k->privkey, k->privkeylen)) return 0;

    if (kmx_put_hybrid_params(k, params)) return 0;

    return 1;
}

static const OSSL_PARAM kmx_gettable_params_static[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    /* Also expose raw pub/priv + hybrid parts */
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(KM_HYBRID_PKEY_PARAM_CLASSICAL_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(KM_HYBRID_PKEY_PARAM_CLASSICAL_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(KM_HYBRID_PKEY_PARAM_PQ_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(KM_HYBRID_PKEY_PARAM_PQ_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *km_gettable_params(void *provctx)
{
    (void)provctx;
    KM_LOG0("KMKEYMGMT: gettable_params\n");
    return kmx_gettable_params_static;
}

static int kmx_set_property_query(KMX_KEY *k, const char *propq)
{
    OPENSSL_free(k->propq);
    k->propq = NULL;
    if (propq) {
        k->propq = OPENSSL_strdup(propq);
        if (!k->propq) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }
    return 1;
}

static int kmx_set_params(void *key_ptr, const OSSL_PARAM params[])
{
    KMX_KEY *k = (KMX_KEY *)key_ptr;
    KM_LOG0("KMKEYMGMT: set_params\n");
    if (k == NULL) {
        ERR_raise(ERR_LIB_USER, KMPROV_R_WRONG_PARAMETERS);
        return 0;
    }

    const OSSL_PARAM *p;
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p) {
        size_t used = 0;
        if (k->keytype == KEY_TYPE_ECP_HYB_KEM || k->keytype == KEY_TYPE_ECX_HYB_KEM) {
            if (p->data_size != k->pubkeylen - SIZE_OF_UINT32 ||
                !OSSL_PARAM_get_octet_string(p, &k->comp_pubkey[0],
                        k->pubkeylen - SIZE_OF_UINT32, &used)) {
                return 0;
            }
        } else {
            if (p->data_size != k->pubkeylen ||
                !OSSL_PARAM_get_octet_string(p, &k->pubkey, k->pubkeylen, &used)) {
                return 0;
            }
        }
        OPENSSL_clear_free(k->privkey, k->privkeylen);
        k->privkey = NULL;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    if (p) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING || !kmx_set_property_query(k, p->data))
            return 0;
    }
    return 1;
}

static const OSSL_PARAM kmx_settable_params_static[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_utf8_string (OSSL_PKEY_PARAM_PROPERTIES,         NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *kmx_settable_params(void *provctx)
{
    (void)provctx;
    KM_LOG0("KMKEYMGMT: settable_params\n");
    return kmx_settable_params_static;
}

/* =========================================================================
 * Generation (init / set / do / cleanup)
 * ========================================================================= */
static void *kmx_gen_init_common(void *provctx, int selection,
                                 const char *km_name, const char *tls_name,
                                 int primitive, int secbits, int alg_idx,
                                 int reverse_share)
{
    KM_LOG1("KMKEYMGMT: gen_init %s\n", km_name);
    struct kmx_gen_ctx *g = OPENSSL_zalloc(sizeof(*g));
    if (!g) return NULL;

    g->libctx       = PROV_KM_LIBCTX_OF(provctx);
    g->km_name      = OPENSSL_strdup(km_name);
    g->tls_name     = OPENSSL_strdup(tls_name);
    g->primitive    = primitive;
    g->selection    = selection;
    g->bit_security = secbits;
    g->alg_idx      = alg_idx;
    g->reverse_share= reverse_share;

    if (!g->km_name || !g->tls_name) {
        kmx_gen_cleanup(g);
        return NULL;
    }
    return g;
}

static void *kmx_genkey(struct kmx_gen_ctx *g)
{
    if (!g) return NULL;

    KM_LOG2("KMKEYMGMT: gen %s (%s)\n", g->km_name, g->tls_name);
    KMX_KEY *key = kmx_key_new(g->libctx, g->km_name, g->tls_name,
                               g->primitive, g->propq, g->bit_security,
                               g->alg_idx, g->reverse_share);
    if (!key) {
        KM_LOG1("KMKEYMGMT: key_new failed for %s\n", g->tls_name);
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    if (kmx_key_gen(key)) {
        ERR_raise(ERR_LIB_USER, KM_ERR_UNEXPECTED_NULL);
        return NULL;
    }
    return key;
}

static void *kmx_gen(void *genctx, OSSL_CALLBACK *unused, void *unused2)
{
    (void)unused; (void)unused2;
    return kmx_genkey((struct kmx_gen_ctx *)genctx);
}

static void kmx_gen_cleanup(void *genctx)
{
    struct kmx_gen_ctx *g = (struct kmx_gen_ctx *)genctx;
    KM_LOG0("KMKEYMGMT: gen_cleanup\n");
    if (!g) return;
    OPENSSL_free(g->km_name);
    OPENSSL_free(g->tls_name);
    OPENSSL_free(g->propq);
    OPENSSL_free(g);
}

static const OSSL_PARAM *kmx_gen_settable_params(void *provctx)
{
    (void)provctx;
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES,  NULL, 0),
        OSSL_PARAM_END
    };
    return settable;
}

static int kmx_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    struct kmx_gen_ctx *g = (struct kmx_gen_ctx *)genctx;
    KM_LOG0("KMKEYMGMT: gen_set_params\n");
    if (!g) return 0;

    const OSSL_PARAM *p;
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME))) {
        OPENSSL_free(g->tls_name);
        g->tls_name = OPENSSL_strdup((const char *)p->data);
        if (!g->tls_name) return 0;
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PROPERTIES))) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING) return 0;
        OPENSSL_free(g->propq);
        g->propq = OPENSSL_strdup((const char *)p->data);
        if (!g->propq) return 0;
    }
    return 1;
}

/* Load by pointer reference */
static void *kmx_load(const void *reference, size_t reference_sz)
{
    KM_LOG0("KMKEYMGMT: load\n");
    KMX_KEY *key = NULL;
    if (reference_sz == sizeof(key)) {
        key = *(KMX_KEY * const *)reference;
        *(KMX_KEY **)reference = NULL; /* detach */
    }
    return key;
}

/* Import/Export type tables */
#define KM_HYBRID_KEY_TYPES() \
    OSSL_PARAM_octet_string(KM_HYBRID_PKEY_PARAM_CLASSICAL_PUB_KEY,  NULL, 0), \
    OSSL_PARAM_octet_string(KM_HYBRID_PKEY_PARAM_CLASSICAL_PRIV_KEY, NULL, 0), \
    OSSL_PARAM_octet_string(KM_HYBRID_PKEY_PARAM_PQ_PUB_KEY,         NULL, 0), \
    OSSL_PARAM_octet_string(KM_HYBRID_PKEY_PARAM_PQ_PRIV_KEY,        NULL, 0)

#define KM_KEY_TYPES() \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,  NULL, 0), \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0), \
    KM_HYBRID_KEY_TYPES()

static const OSSL_PARAM kmx_key_types[] = { KM_KEY_TYPES(), OSSL_PARAM_END };

static const OSSL_PARAM *km_imexport_types(int selection)
{
    KM_LOG0("KMKEYMGMT: im/export types\n");
    return (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) ? kmx_key_types : NULL;
}

/* =========================================================================
 * Generators for dispatch tables (macros)
 * ========================================================================= */

#define KM_DISPATCH_COMMON \
    { OSSL_FUNC_KEYMGMT_FREE,               (void (*)(void))kmx_key_free }, \
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,         (void (*)(void))kmx_get_params }, \
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,    (void (*)(void))kmx_settable_params }, \
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,    (void (*)(void))km_gettable_params }, \
    { OSSL_FUNC_KEYMGMT_SET_PARAMS,         (void (*)(void))kmx_set_params }, \
    { OSSL_FUNC_KEYMGMT_HAS,                (void (*)(void))kmx_has }, \
    { OSSL_FUNC_KEYMGMT_MATCH,              (void (*)(void))kmx_match }, \
    { OSSL_FUNC_KEYMGMT_IMPORT,             (void (*)(void))kmx_import }, \
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,       (void (*)(void))km_imexport_types }, \
    { OSSL_FUNC_KEYMGMT_EXPORT,             (void (*)(void))kmx_export }, \
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,       (void (*)(void))km_imexport_types }, \
    { OSSL_FUNC_KEYMGMT_GEN,                (void (*)(void))kmx_gen }, \
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,        (void (*)(void))kmx_gen_cleanup }, \
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,     (void (*)(void))kmx_gen_set_params }, \
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,(void (*)(void))kmx_gen_settable_params }, \
    { OSSL_FUNC_KEYMGMT_LOAD,               (void (*)(void))kmx_load }

#define KM_DECLARE_SIG(alg, oqs_name, tls_nm, secb, algidx)                            \
    static void *alg##_new_key(void *provctx) {                                        \
        return kmx_key_new(PROV_KM_LIBCTX_OF(provctx), oqs_name, tls_nm,               \
                           KEY_TYPE_SIG, NULL, secb, algidx, 0);                        \
    }                                                                                   \
    static void *alg##_gen_init(void *provctx, int selection) {                         \
        return kmx_gen_init_common(provctx, selection, oqs_name, tls_nm,                \
                                   KEY_TYPE_SIG, secb, algidx, 0);                      \
    }                                                                                   \
    const OSSL_DISPATCH km_##alg##_keymgmt_functions[] = {                              \
        { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))alg##_new_key },                       \
        KM_DISPATCH_COMMON,                                                             \
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))alg##_gen_init },                 \
        { 0, NULL }                                                                      \
    }

#define KM_DECLARE_KEM(tok, oqs_kem, secb)                                             \
    static void *tok##_new_key(void *provctx) {                                        \
        return kmx_key_new(PROV_KM_LIBCTX_OF(provctx), oqs_kem, #tok,                  \
                           KEY_TYPE_KEM, NULL, secb, -1, 0);                            \
    }                                                                                   \
    static void *tok##_gen_init(void *provctx, int selection) {                         \
        return kmx_gen_init_common(provctx, selection, oqs_kem, #tok,                   \
                                   KEY_TYPE_KEM, secb, -1, 0);                          \
    }                                                                                   \
    const OSSL_DISPATCH km_##tok##_keymgmt_functions[] = {                              \
        { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))tok##_new_key },                       \
        KM_DISPATCH_COMMON,                                                             \
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))tok##_gen_init },                 \
        { 0, NULL }                                                                      \
    }

#define KM_DECLARE_ECP_HYB(tok, oqs_kem, secb)                                         \
    static void *ecp_##tok##_new_key(void *provctx) {                                   \
        return kmx_key_new(PROV_KM_LIBCTX_OF(provctx), oqs_kem, #tok,                  \
                           KEY_TYPE_ECP_HYB_KEM, NULL, secb, -1, 0);                    \
    }                                                                                   \
    static void *ecp_##tok##_gen_init(void *provctx, int selection) {                   \
        return kmx_gen_init_common(provctx, selection, oqs_kem, #tok,                   \
                                   KEY_TYPE_ECP_HYB_KEM, secb, -1, 0);                  \
    }                                                                                   \
    const OSSL_DISPATCH km_ecp_##tok##_keymgmt_functions[] = {                          \
        { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ecp_##tok##_new_key },                 \
        KM_DISPATCH_COMMON,                                                             \
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))ecp_##tok##_gen_init },           \
        { 0, NULL }                                                                      \
    }

#define KM_DECLARE_ECX_HYB(tok, oqs_kem, secb, pqfips)                                  \
    static void *ecx_##tok##_new_key(void *provctx) {                                   \
        return kmx_key_new(PROV_KM_LIBCTX_OF(provctx), oqs_kem, #tok,                  \
                           KEY_TYPE_ECX_HYB_KEM, NULL, secb, -1, pqfips);               \
    }                                                                                   \
    static void *ecx_##tok##_gen_init(void *provctx, int selection) {                   \
        return kmx_gen_init_common(provctx, selection, oqs_kem, #tok,                   \
                                   KEY_TYPE_ECX_HYB_KEM, secb, -1, pqfips);             \
    }                                                                                   \
    const OSSL_DISPATCH km_ecx_##tok##_keymgmt_functions[] = {                          \
        { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ecx_##tok##_new_key },                 \
        KM_DISPATCH_COMMON,                                                             \
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))ecx_##tok##_gen_init },           \
        { 0, NULL }                                                                      \
    }

/* =========================================================================
 * Concrete algorithms (sama set dengan kode Anda)
 * ========================================================================= */
/* Signatures */
KM_DECLARE_SIG(dilithium2,  OQS_SIG_alg_dilithium_2,  "dilithium2", 128, 0);
KM_DECLARE_SIG(dilithium3,  OQS_SIG_alg_dilithium_3,  "dilithium3", 192, 3);
KM_DECLARE_SIG(dilithium5,  OQS_SIG_alg_dilithium_5,  "dilithium5", 256, 5);

KM_DECLARE_SIG(mldsa44,     OQS_SIG_alg_ml_dsa_44,    "mldsa44",    128, 7);
KM_DECLARE_SIG(mldsa65,     OQS_SIG_alg_ml_dsa_65,    "mldsa65",    192, 15);
KM_DECLARE_SIG(mldsa87,     OQS_SIG_alg_ml_dsa_87,    "mldsa87",    256, 22);

KM_DECLARE_SIG(sphincssha2128fsimple,  OQS_SIG_alg_sphincs_sha2_128f_simple,  "sphincssha2128fsimple", 128, 37);
KM_DECLARE_SIG(sphincssha2128ssimple,  OQS_SIG_alg_sphincs_sha2_128s_simple,  "sphincssha2128ssimple", 128, 40);
KM_DECLARE_SIG(sphincssha2192fsimple,  OQS_SIG_alg_sphincs_sha2_192f_simple,  "sphincssha2192fsimple", 192, 43);
KM_DECLARE_SIG(sphincsshake128fsimple, OQS_SIG_alg_sphincs_shake_128f_simple, "sphincsshake128fsimple",128, 45);

/* KEMs */
KM_DECLARE_KEM(kyber512,  OQS_KEM_alg_kyber_512,  128);
KM_DECLARE_ECX_HYB(x25519_kyber512,  OQS_KEM_alg_kyber_512, 128, 0);
KM_DECLARE_KEM(kyber768,  OQS_KEM_alg_kyber_768,  192);
KM_DECLARE_ECX_HYB(x25519_kyber768,  OQS_KEM_alg_kyber_768, 128, 0);
KM_DECLARE_KEM(kyber1024, OQS_KEM_alg_kyber_1024, 256);

KM_DECLARE_KEM(mlkem512,  OQS_KEM_alg_ml_kem_512,  128);
KM_DECLARE_ECX_HYB(x25519_mlkem512,  OQS_KEM_alg_ml_kem_512, 128, 1);
KM_DECLARE_KEM(mlkem768,  OQS_KEM_alg_ml_kem_768,  192);
/* X25519MLKEM768 name preserved as requested */
KM_DECLARE_ECX_HYB(X25519MLKEM768,    OQS_KEM_alg_ml_kem_768, 128, 1);
KM_DECLARE_KEM(mlkem1024, OQS_KEM_alg_ml_kem_1024, 256);
