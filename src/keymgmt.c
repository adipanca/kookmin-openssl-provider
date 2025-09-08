// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * KM OpenSSL 3 provider
 *
 * Code strongly inspired by OpenSSL ecx key management.
 *
 * ToDo: More testing in non-KEM cases
 */

#include <assert.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <string.h>

#include "openssl/param_build.h"
#include "provider.h"

// stolen from openssl/crypto/param_build_set.c as
// ossl_param_build_set_octet_string not public API:

int kmx_param_build_set_octet_string(OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                                      const char *key,
                                      const unsigned char *data,
                                      size_t data_len) {
    if (bld != NULL)
        return OSSL_PARAM_BLD_push_octet_string(bld, key, data, data_len);

    p = OSSL_PARAM_locate(p, key);
    if (p != NULL)
        return OSSL_PARAM_set_octet_string(p, data, data_len);
    return 1;
}

#ifdef NDEBUG
#define KM_KM_PRINTF(a)
#define KM_KM_PRINTF2(a, b)
#define KM_KM_PRINTF3(a, b, c)
#else
#define KM_KM_PRINTF(a)                                                       \
    if (getenv("KMKM"))                                                       \
    printf(a)
#define KM_KM_PRINTF2(a, b)                                                   \
    if (getenv("KMKM"))                                                       \
    printf(a, b)
#define KM_KM_PRINTF3(a, b, c)                                                \
    if (getenv("KMKM"))                                                       \
    printf(a, b, c)
#endif // NDEBUG

// our own error codes:
#define KMPROV_UNEXPECTED_NULL 1

static OSSL_FUNC_keymgmt_gen_cleanup_fn kmx_gen_cleanup;
static OSSL_FUNC_keymgmt_load_fn kmx_load;
static OSSL_FUNC_keymgmt_get_params_fn kmx_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn km_gettable_params;
static OSSL_FUNC_keymgmt_set_params_fn kmx_set_params;
static OSSL_FUNC_keymgmt_settable_params_fn kmx_settable_params;
static OSSL_FUNC_keymgmt_has_fn kmx_has;
static OSSL_FUNC_keymgmt_match_fn kmx_match;
static OSSL_FUNC_keymgmt_import_fn kmx_import;
static OSSL_FUNC_keymgmt_import_types_fn km_imexport_types;
static OSSL_FUNC_keymgmt_export_fn kmx_export;
static OSSL_FUNC_keymgmt_export_types_fn km_imexport_types;

struct kmx_gen_ctx {
    OSSL_LIB_CTX *libctx;
    char *propq;
    char *km_name;
    char *cmp_name;
    char *tls_name;
    int primitive;
    int selection;
    int bit_security;
    int alg_idx;
    int reverse_share;
};

static int kmx_has(const void *keydata, int selection) {
    const KMX_KEY *key = keydata;
    int ok = 0;

    KM_KM_PRINTF("KMKEYMGMT: has called\n");
    if (key != NULL) {
        /*
         * KMX keys always have all the parameters they need (i.e. none).
         * Therefore we always return with 1, if asked about parameters.
         */
        ok = 1;

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            ok = ok && key->pubkey != NULL;

        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok = ok && key->privkey != NULL;
    }
    if (!ok)
        KM_KM_PRINTF2("KMKM: has returning FALSE on selection %2x\n",
                       selection);
    return ok;
}

/* Sets the index of the key components in a comp_privkey or comp_pubkey array
 */
static void kmx_comp_set_idx(const KMX_KEY *key, int *idx_classic,
                              int *idx_pq) {
    int reverse_share = (key->keytype == KEY_TYPE_ECP_HYB_KEM ||
                         key->keytype == KEY_TYPE_ECX_HYB_KEM) &&
                        key->reverse_share;

    if (reverse_share) {
        if (idx_classic)
            *idx_classic = key->numkeys - 1;
        if (idx_pq)
            *idx_pq = 0;
    } else {
        if (idx_classic)
            *idx_classic = 0;
        if (idx_pq)
            *idx_pq = key->numkeys - 1;
    }
}

/*
 * Key matching has a problem in KM world: OpenSSL assumes all keys to (also)
 * contain public key material
 * (https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_eq.html). This is not
 * the case with decoded private keys: Not all algorithms permit re-creating
 * public key material from private keys
 * (https://github.com/PQClean/PQClean/issues/415#issuecomment-910377682). Thus
 * we implement the following logic: 1) Private keys are matched binary if
 * available in both keys; only one key having private key material will be
 * considered a mismatch 2) Public keys are matched binary if available in both
 * keys; only one key having public key material will NOT be considered a
 * mismatch if both private keys are present and match: The latter logic will
 *    only be triggered if domain parameter matching is requested to
 * distinguish between a pure-play public key match/test and one checking
 * OpenSSL-type "EVP-PKEY-equality". This is possible as domain parameters
 * don't really play a role in KM, so we consider them as a proxy for private
 * key matching.
 */

static int kmx_match(const void *keydata1, const void *keydata2,
                      int selection) {
    const KMX_KEY *key1 = keydata1;
    const KMX_KEY *key2 = keydata2;
    int ok = 1;

    KM_KM_PRINTF3("KMKEYMGMT: match called for %p and %p\n", keydata1,
                   keydata2);
    KM_KM_PRINTF2("KMKEYMGMT: match called for selection %d\n", selection);

    if (key1 == NULL || key2 == NULL) {
        ERR_raise(ERR_LIB_USER, KMPROV_R_WRONG_PARAMETERS);
        return 0;
    }

#ifdef NOPUBKEY_IN_PRIVKEY
    /* Now this is a "leap of faith" logic: If a public-only PKEY and a
     * private-only PKEY are tested for equality we cannot do anything other
     * than saying OK (as per
     * https://github.com/PQClean/PQClean/issues/415#issuecomment-910377682) if
     * at least the key type name matches. Potential actual key mismatches will
     * only be discovered later.
     */
    if (((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) &&
        ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)) {
        if ((key1->privkey == NULL && key2->pubkey == NULL) ||
            (key1->pubkey == NULL && key2->privkey == NULL) ||
            ((key1->tls_name != NULL && key2->tls_name != NULL) &&
             !strcmp(key1->tls_name, key2->tls_name))) {
            KM_KM_PRINTF("KMKEYMGMT: leap-of-faith match\n");
            return 1;
        }
    }
#endif

    if (((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) &&
        ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)) {
        if ((key1->privkey == NULL && key2->privkey != NULL) ||
            (key1->privkey != NULL && key2->privkey == NULL) ||
            ((key1->tls_name != NULL && key2->tls_name != NULL) &&
             strcmp(key1->tls_name, key2->tls_name))) {
            ok = 0;
        } else {
            ok = ((key1->privkey == NULL && key2->privkey == NULL) ||
                  ((key1->privkey != NULL) &&
                   CRYPTO_memcmp(key1->privkey, key2->privkey,
                                 key1->privkeylen) == 0));
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if ((key1->pubkey == NULL && key2->pubkey != NULL) ||
            (key1->pubkey != NULL && key2->pubkey == NULL) ||
            ((key1->tls_name != NULL && key2->tls_name != NULL) &&
             strcmp(key1->tls_name, key2->tls_name))) {
            // special case now: If domain parameter matching
            // requested, consider private key match sufficient:
            ok = ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) &&
                 (key1->privkey != NULL && key2->privkey != NULL) &&
                 (CRYPTO_memcmp(key1->privkey, key2->privkey,
                                key1->privkeylen) == 0);
        } else {
            ok = ok && ((key1->pubkey == NULL && key2->pubkey == NULL) ||
                        ((key1->pubkey != NULL) &&
                         CRYPTO_memcmp(key1->pubkey, key2->pubkey,
                                       key1->pubkeylen) == 0));
        }
    }
    if (!ok)
        KM_KM_PRINTF("KMKEYMGMT: match failed!\n");
    return ok;
}

static int kmx_import(void *keydata, int selection,
                       const OSSL_PARAM params[]) {
    KMX_KEY *key = keydata;
    int ok = 0;

    KM_KM_PRINTF("KMKEYMGMT: import called \n");
    if (key == NULL) {
        ERR_raise(ERR_LIB_USER, KMPROV_UNEXPECTED_NULL);
        return ok;
    }

    if (((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0) &&
        (kmx_key_fromdata(key, params, 1)))
        ok = 1;
    return ok;
}

int kmx_key_to_params(const KMX_KEY *key, OSSL_PARAM_BLD *tmpl,
                       OSSL_PARAM params[], int include_private) {
    int ret = 0;

    if (key == NULL)
        return 0;

    if (key->pubkey != NULL) {
        OSSL_PARAM *p = NULL;

        if (tmpl == NULL) {
            p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
        }

        if (p != NULL || tmpl != NULL) {
            if (key->pubkeylen == 0 || !kmx_param_build_set_octet_string(
                                           tmpl, p, OSSL_PKEY_PARAM_PUB_KEY,
                                           key->pubkey, key->pubkeylen))
                goto err;
        }
    }
    if (key->privkey != NULL && include_private) {
        OSSL_PARAM *p = NULL;

        /*
         * Key import/export should never leak the bit length of the secret
         * scalar in the key. Conceptually. KM is not production strength
         * so does not care. TBD.
         *
         */

        if (tmpl == NULL) {
            p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
        }

        if (p != NULL || tmpl != NULL) {
            if (key->privkeylen == 0 || !kmx_param_build_set_octet_string(
                                            tmpl, p, OSSL_PKEY_PARAM_PRIV_KEY,
                                            key->privkey, key->privkeylen))
                goto err;
        }
    }
    // not passing in params to respond to is no error; the response is empty
    ret = 1;
err:
    return ret;
}

static int kmx_export(void *keydata, int selection, OSSL_CALLBACK *param_cb,
                       void *cbarg) {
    KMX_KEY *key = keydata;
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    OSSL_PARAM *p;
    int ok = 1;

    KM_KM_PRINTF("KMKEYMGMT: export called\n");

    /*
     * In this implementation, only public and private keys can be exported,
     * nothing else
     */
    if (key == NULL || param_cb == NULL) {
        ERR_raise(ERR_LIB_USER, KMPROV_R_WRONG_PARAMETERS);
        return 0;
    }

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL) {
        ERR_raise(ERR_LIB_USER, KMPROV_UNEXPECTED_NULL);
        return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int include_private =
            selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;

        ok = ok && kmx_key_to_params(key, tmpl, NULL, include_private);
    }

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL) {
        ok = 0;
        goto err;
    }

    ok = ok & param_cb(params, cbarg);
    OSSL_PARAM_free(params);
err:
    OSSL_PARAM_BLD_free(tmpl);
    return ok;
}

#define KM_HYBRID_KEY_TYPES()                                                 \
    OSSL_PARAM_octet_string(KM_HYBRID_PKEY_PARAM_CLASSICAL_PUB_KEY, NULL, 0), \
        OSSL_PARAM_octet_string(KM_HYBRID_PKEY_PARAM_CLASSICAL_PRIV_KEY,      \
                                NULL, 0),                                      \
        OSSL_PARAM_octet_string(KM_HYBRID_PKEY_PARAM_PQ_PUB_KEY, NULL, 0),    \
        OSSL_PARAM_octet_string(KM_HYBRID_PKEY_PARAM_PQ_PRIV_KEY, NULL, 0)

#define KM_KEY_TYPES()                                                        \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),                 \
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),            \
        KM_HYBRID_KEY_TYPES()

static const OSSL_PARAM kmx_key_types[] = {KM_KEY_TYPES(), OSSL_PARAM_END};
static const OSSL_PARAM *km_imexport_types(int selection) {
    KM_KM_PRINTF("KMKEYMGMT: imexport called\n");
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return kmx_key_types;
    return NULL;
}

// Tells if a key (SIG, KEM, ECP_HYB_KEM, ECX_HYB_KEM or HYB_SIG) is using
// hybrid algorithm.
//
// Returns 1 if hybrid, else 0.
static int kmx_key_is_hybrid(const KMX_KEY *kmxk) {
    if ((kmxk->keytype == KEY_TYPE_ECP_HYB_KEM ||
         kmxk->keytype == KEY_TYPE_ECX_HYB_KEM ||
         kmxk->keytype == KEY_TYPE_HYB_SIG) &&
        kmxk->numkeys == 2 && kmxk->classical_pkey != NULL) {
        KM_KM_PRINTF("KMKEYMGMT: key is hybrid\n");
        return 1;
    }
    return 0;
}

// Gets the classical params of an hybrid key.

// Gets hybrid params.
//
// Returns 0 on success.
static int kmx_get_hybrid_params(KMX_KEY *key, OSSL_PARAM params[]) {
    OSSL_PARAM *p;
    const void *classical_pubkey = NULL;
    const void *classical_privkey = NULL;
    const void *pq_pubkey = NULL;
    const void *pq_privkey = NULL;
    uint32_t classical_pubkey_len = 0;
    uint32_t classical_privkey_len = 0;
    int pq_pubkey_len = 0;
    int pq_privkey_len = 0;
    int idx_classic, idx_pq;

    if (kmx_key_is_hybrid(key) != 1)
        return 0;

    if (key->numkeys != 2) {
        KM_KM_PRINTF2("KMKEYMGMT: key is hybrid but key->numkeys = %zu\n",
                       key->numkeys);
        ERR_raise(ERR_LIB_PROV, KMPROV_R_INTERNAL_ERROR);
        return -1;
    }

    kmx_comp_set_idx(key, &idx_classic, &idx_pq);

    if (key->comp_pubkey != NULL && key->pubkey != NULL &&
        key->comp_pubkey[idx_classic] != NULL) {
        classical_pubkey = key->comp_pubkey[idx_classic];
        DECODE_UINT32(classical_pubkey_len, key->pubkey);
    }
    if (key->comp_privkey != NULL && key->privkey != NULL &&
        key->comp_privkey[idx_classic] != NULL) {
        classical_privkey = key->comp_privkey[idx_classic];
        DECODE_UINT32(classical_privkey_len, key->privkey);
    }

    if (key->comp_pubkey != NULL && key->comp_pubkey[idx_pq] != NULL) {
        pq_pubkey = key->comp_pubkey[idx_pq];
        pq_pubkey_len = key->pubkeylen - classical_pubkey_len - SIZE_OF_UINT32;
    }
    if (key->comp_privkey != NULL && key->comp_privkey != NULL) {
        pq_privkey = key->comp_privkey[idx_pq];
        pq_privkey_len =
            key->privkeylen - classical_privkey_len - SIZE_OF_UINT32;
    }

    if ((p = OSSL_PARAM_locate(
             params, KM_HYBRID_PKEY_PARAM_CLASSICAL_PUB_KEY)) != NULL &&
        !OSSL_PARAM_set_octet_string(p, classical_pubkey, classical_pubkey_len))
        return -1;
    if ((p = OSSL_PARAM_locate(
             params, KM_HYBRID_PKEY_PARAM_CLASSICAL_PRIV_KEY)) != NULL &&
        !OSSL_PARAM_set_octet_string(p, classical_privkey,
                                     classical_privkey_len))
        return -1;
    if ((p = OSSL_PARAM_locate(params, KM_HYBRID_PKEY_PARAM_PQ_PUB_KEY)) !=
            NULL &&
        !OSSL_PARAM_set_octet_string(p, pq_pubkey, pq_pubkey_len))
        return -1;
    if ((p = OSSL_PARAM_locate(params, KM_HYBRID_PKEY_PARAM_PQ_PRIV_KEY)) !=
            NULL &&
        !OSSL_PARAM_set_octet_string(p, pq_privkey, pq_privkey_len))
        return -1;

    return 0;
}

// must handle param requests for KEM and SIG keys...
static int kmx_get_params(void *key, OSSL_PARAM params[]) {
    KMX_KEY *kmxk = key;
    OSSL_PARAM *p;

    if (kmxk == NULL || params == NULL) {
        ERR_raise(ERR_LIB_USER, KMPROV_R_WRONG_PARAMETERS);
        return 0;
    }

    KM_KM_PRINTF2("KMKEYMGMT: get_params called for %s\n", params[0].key);
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL &&
        !OSSL_PARAM_set_int(p, kmx_key_secbits(kmxk)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) !=
            NULL &&
        !OSSL_PARAM_set_int(p, kmx_key_secbits(kmxk)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL &&
        !OSSL_PARAM_set_int(p, kmx_key_maxsize(kmxk)))
        return 0;

    /* add as temporary workaround TBC */
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST)) !=
            NULL &&
        !OSSL_PARAM_set_utf8_string(p, SN_undef))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST)) !=
            NULL &&
        !OSSL_PARAM_set_utf8_string(p, SN_undef))
        return 0;
    /* end workaround */

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) !=
        NULL) {
        // hybrid KEMs are special in that the classic length information
        // shall not be passed out:
        if (kmxk->keytype == KEY_TYPE_ECP_HYB_KEM ||
            kmxk->keytype == KEY_TYPE_ECX_HYB_KEM) {
            if (!OSSL_PARAM_set_octet_string(
                    p, (char *)kmxk->pubkey + SIZE_OF_UINT32,
                    kmxk->pubkeylen - SIZE_OF_UINT32))
                return 0;
        } else {
            if (!OSSL_PARAM_set_octet_string(p, kmxk->pubkey,
                                             kmxk->pubkeylen))
                return 0;
        }
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY)) != NULL) {
        if (!OSSL_PARAM_set_octet_string(p, kmxk->pubkey, kmxk->pubkeylen))
            return 0;
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY)) != NULL) {
        if (!OSSL_PARAM_set_octet_string(p, kmxk->privkey, kmxk->privkeylen))
            return 0;
    }

    if (kmx_get_hybrid_params(kmxk, params))
        return 0;

    // not passing in params to respond to is no error
    return 1;
}

static const OSSL_PARAM kmx_gettable_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    KM_KEY_TYPES(),
    OSSL_PARAM_END};

static const OSSL_PARAM *km_gettable_params(void *provctx) {
    KM_KM_PRINTF("KMKEYMGMT: gettable_params called\n");
    return kmx_gettable_params;
}

static int set_property_query(KMX_KEY *kmxkey, const char *propq) {
    OPENSSL_free(kmxkey->propq);
    kmxkey->propq = NULL;
    KM_KM_PRINTF("KMKEYMGMT: property_query called\n");
    if (propq != NULL) {
        kmxkey->propq = OPENSSL_strdup(propq);
        if (kmxkey->propq == NULL) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }
    return 1;
}

static int kmx_set_params(void *key, const OSSL_PARAM params[]) {
    KMX_KEY *kmxkey = key;
    const OSSL_PARAM *p;

    KM_KM_PRINTF("KMKEYMGMT: set_params called\n");
    if (kmxkey == NULL) {
        ERR_raise(ERR_LIB_USER, KMPROV_R_WRONG_PARAMETERS);
        return 0;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL) {
        size_t used_len;
        int classic_pubkey_len;
        if (kmxkey->keytype == KEY_TYPE_ECP_HYB_KEM ||
            kmxkey->keytype == KEY_TYPE_ECX_HYB_KEM) {
            // classic key len already stored by key setup; only data
            // needs to be filled in
            if (p->data_size != kmxkey->pubkeylen - SIZE_OF_UINT32 ||
                !OSSL_PARAM_get_octet_string(
                    p, &kmxkey->comp_pubkey[0],
                    kmxkey->pubkeylen - SIZE_OF_UINT32, &used_len)) {
                return 0;
            }
        } else {
            if (p->data_size != kmxkey->pubkeylen ||
                !OSSL_PARAM_get_octet_string(p, &kmxkey->pubkey,
                                             kmxkey->pubkeylen, &used_len)) {
                return 0;
            }
        }
        OPENSSL_clear_free(kmxkey->privkey, kmxkey->privkeylen);
        kmxkey->privkey = NULL;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING ||
            !set_property_query(kmxkey, p->data)) {
            return 0;
        }
    }

    // not passing in params to set is no error, just a no-op
    return 1;
}

static const OSSL_PARAM km_settable_params[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM *kmx_settable_params(void *provctx) {
    KM_KM_PRINTF("KMKEYMGMT: settable_params called\n");
    return km_settable_params;
}

static void *kmx_gen_init(void *provctx, int selection, char *km_name,
                           char *tls_name, int primitive, int bit_security,
                           int alg_idx, int reverse_share) {
    OSSL_LIB_CTX *libctx = PROV_KM_LIBCTX_OF(provctx);
    struct kmx_gen_ctx *gctx = NULL;

    KM_KM_PRINTF2("KMKEYMGMT: gen_init called for key %s \n", km_name);

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->libctx = libctx;
        gctx->cmp_name = NULL;
        gctx->km_name = OPENSSL_strdup(km_name);
        gctx->tls_name = OPENSSL_strdup(tls_name);
        gctx->primitive = primitive;
        gctx->selection = selection;
        gctx->bit_security = bit_security;
        gctx->alg_idx = alg_idx;
        gctx->reverse_share = reverse_share;
    }
    return gctx;
}

static void *kmx_genkey(struct kmx_gen_ctx *gctx) {
    KMX_KEY *key;

    if (gctx == NULL)
        return NULL;
    KM_KM_PRINTF3("KMKEYMGMT: gen called for %s (%s)\n", gctx->km_name,
                   gctx->tls_name);
    if ((key = kmx_key_new(gctx->libctx, gctx->km_name, gctx->tls_name,
                            gctx->primitive, gctx->propq, gctx->bit_security,
                            gctx->alg_idx, gctx->reverse_share)) == NULL) {
        KM_KM_PRINTF2("KMKM: Error generating key for %s\n", gctx->tls_name);
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (kmx_key_gen(key)) {
        ERR_raise(ERR_LIB_USER, KMPROV_UNEXPECTED_NULL);
        return NULL;
    }
    return key;
}

static void *kmx_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg) {
    struct kmx_gen_ctx *gctx = genctx;

    KM_KM_PRINTF("KMKEYMGMT: gen called\n");

    return kmx_genkey(gctx);
}

static void kmx_gen_cleanup(void *genctx) {
    struct kmx_gen_ctx *gctx = genctx;

    KM_KM_PRINTF("KMKEYMGMT: gen_cleanup called\n");
    OPENSSL_free(gctx->km_name);
    OPENSSL_free(gctx->tls_name);
    OPENSSL_free(gctx->propq);
    OPENSSL_free(gctx);
}

void *kmx_load(const void *reference, size_t reference_sz) {
    KMX_KEY *key = NULL;

    KM_KM_PRINTF("KMKEYMGMT: load called\n");
    if (reference_sz == sizeof(key)) {
        /* The contents of the reference is the address to our object */
        key = *(KMX_KEY **)reference;
        /* We grabbed, so we detach it */
        *(KMX_KEY **)reference = NULL;
        return key;
    }
    return NULL;
}

static const OSSL_PARAM *kmx_gen_settable_params(void *provctx) {
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END};
    return settable;
}

static int kmx_gen_set_params(void *genctx, const OSSL_PARAM params[]) {
    struct kmx_gen_ctx *gctx = genctx;
    const OSSL_PARAM *p;

    KM_KM_PRINTF("KMKEYMGMT: gen_set_params called\n");
    if (gctx == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL) {
        const char *algname = (char *)p->data;

        OPENSSL_free(gctx->tls_name);
        gctx->tls_name = OPENSSL_strdup(algname);
    }
    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PROPERTIES);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        OPENSSL_free(gctx->propq);
        gctx->propq = OPENSSL_strdup(p->data);
        if (gctx->propq == NULL)
            return 0;
    }
    // not passing in params is no error; subsequent operations may fail,
    // though
    return 1;
}

///// KM_TEMPLATE_FRAGMENT_KEYMGMT_CONSTRUCTORS_START
static void *dilithium2_new_key(void *provctx) {
    return kmx_key_new(PROV_KM_LIBCTX_OF(provctx), OQS_SIG_alg_dilithium_2,
                        "dilithium2", KEY_TYPE_SIG, NULL, 128, 0, 0);
}

static void *dilithium2_gen_init(void *provctx, int selection) {
    return kmx_gen_init(provctx, selection, OQS_SIG_alg_dilithium_2,
                         "dilithium2", 0, 128, 0, 0);
}

static void *dilithium3_new_key(void *provctx) {
    return kmx_key_new(PROV_KM_LIBCTX_OF(provctx), OQS_SIG_alg_dilithium_3,
                        "dilithium3", KEY_TYPE_SIG, NULL, 192, 3, 0);
}

static void *dilithium3_gen_init(void *provctx, int selection) {
    return kmx_gen_init(provctx, selection, OQS_SIG_alg_dilithium_3,
                         "dilithium3", 0, 192, 3, 0);
}


static void *dilithium5_new_key(void *provctx) {
    return kmx_key_new(PROV_KM_LIBCTX_OF(provctx), OQS_SIG_alg_dilithium_5,
                        "dilithium5", KEY_TYPE_SIG, NULL, 256, 5, 0);
}

static void *dilithium5_gen_init(void *provctx, int selection) {
    return kmx_gen_init(provctx, selection, OQS_SIG_alg_dilithium_5,
                         "dilithium5", 0, 256, 5, 0);
}

static void *mldsa44_new_key(void *provctx) {
    return kmx_key_new(PROV_KM_LIBCTX_OF(provctx), OQS_SIG_alg_ml_dsa_44,
                        "mldsa44", KEY_TYPE_SIG, NULL, 128, 7, 0);
}

static void *mldsa44_gen_init(void *provctx, int selection) {
    return kmx_gen_init(provctx, selection, OQS_SIG_alg_ml_dsa_44, "mldsa44",
                         0, 128, 7, 0);
}

static void *mldsa65_new_key(void *provctx) {
    return kmx_key_new(PROV_KM_LIBCTX_OF(provctx), OQS_SIG_alg_ml_dsa_65,
                        "mldsa65", KEY_TYPE_SIG, NULL, 192, 15, 0);
}

static void *mldsa65_gen_init(void *provctx, int selection) {
    return kmx_gen_init(provctx, selection, OQS_SIG_alg_ml_dsa_65, "mldsa65",
                         0, 192, 15, 0);
}


static void *mldsa87_new_key(void *provctx) {
    return kmx_key_new(PROV_KM_LIBCTX_OF(provctx), OQS_SIG_alg_ml_dsa_87,
                        "mldsa87", KEY_TYPE_SIG, NULL, 256, 22, 0);
}

static void *mldsa87_gen_init(void *provctx, int selection) {
    return kmx_gen_init(provctx, selection, OQS_SIG_alg_ml_dsa_87, "mldsa87",
                         0, 256, 22, 0);
}


static void *sphincssha2128fsimple_new_key(void *provctx) {
    return kmx_key_new(
        PROV_KM_LIBCTX_OF(provctx), OQS_SIG_alg_sphincs_sha2_128f_simple,
        "sphincssha2128fsimple", KEY_TYPE_SIG, NULL, 128, 37, 0);
}

static void *sphincssha2128fsimple_gen_init(void *provctx, int selection) {
    return kmx_gen_init(provctx, selection,
                         OQS_SIG_alg_sphincs_sha2_128f_simple,
                         "sphincssha2128fsimple", 0, 128, 37, 0);
}

static void *sphincssha2128ssimple_new_key(void *provctx) {
    return kmx_key_new(
        PROV_KM_LIBCTX_OF(provctx), OQS_SIG_alg_sphincs_sha2_128s_simple,
        "sphincssha2128ssimple", KEY_TYPE_SIG, NULL, 128, 40, 0);
}

static void *sphincssha2128ssimple_gen_init(void *provctx, int selection) {
    return kmx_gen_init(provctx, selection,
                         OQS_SIG_alg_sphincs_sha2_128s_simple,
                         "sphincssha2128ssimple", 0, 128, 40, 0);
}

static void *sphincssha2192fsimple_new_key(void *provctx) {
    return kmx_key_new(
        PROV_KM_LIBCTX_OF(provctx), OQS_SIG_alg_sphincs_sha2_192f_simple,
        "sphincssha2192fsimple", KEY_TYPE_SIG, NULL, 192, 43, 0);
}

static void *sphincssha2192fsimple_gen_init(void *provctx, int selection) {
    return kmx_gen_init(provctx, selection,
                         OQS_SIG_alg_sphincs_sha2_192f_simple,
                         "sphincssha2192fsimple", 0, 192, 43, 0);
}


static void *sphincsshake128fsimple_new_key(void *provctx) {
    return kmx_key_new(
        PROV_KM_LIBCTX_OF(provctx), OQS_SIG_alg_sphincs_shake_128f_simple,
        "sphincsshake128fsimple", KEY_TYPE_SIG, NULL, 128, 45, 0);
}

static void *sphincsshake128fsimple_gen_init(void *provctx, int selection) {
    return kmx_gen_init(provctx, selection,
                         OQS_SIG_alg_sphincs_shake_128f_simple,
                         "sphincsshake128fsimple", 0, 128, 45, 0);
}

///// KM_TEMPLATE_FRAGMENT_KEYMGMT_CONSTRUCTORS_END

#define MAKE_SIG_KEYMGMT_FUNCTIONS(alg)                                        \
                                                                               \
    const OSSL_DISPATCH km_##alg##_keymgmt_functions[] = {                    \
        {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))alg##_new_key},                \
        {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))kmx_key_free},               \
        {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))kmx_get_params},       \
        {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,                                    \
         (void (*)(void))kmx_settable_params},                                \
        {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,                                    \
         (void (*)(void))km_gettable_params},                                 \
        {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))kmx_set_params},       \
        {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))kmx_has},                     \
        {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))kmx_match},                 \
        {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))kmx_import},               \
        {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))km_imexport_types},  \
        {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))kmx_export},               \
        {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))km_imexport_types},  \
        {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))alg##_gen_init},          \
        {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))kmx_gen},                     \
        {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))kmx_gen_cleanup},     \
        {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,                                     \
         (void (*)(void))kmx_gen_set_params},                                 \
        {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,                                \
         (void (*)(void))kmx_gen_settable_params},                            \
        {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))kmx_load},                   \
        {0, NULL}};

#define MAKE_KEM_KEYMGMT_FUNCTIONS(tokalg, tokkmalg, bit_security)            \
                                                                               \
    static void *tokalg##_new_key(void *provctx) {                             \
        return kmx_key_new(PROV_KM_LIBCTX_OF(provctx), tokkmalg,            \
                            "" #tokalg "", KEY_TYPE_KEM, NULL, bit_security,   \
                            -1, 0);                                            \
    }                                                                          \
                                                                               \
    static void *tokalg##_gen_init(void *provctx, int selection) {             \
        return kmx_gen_init(provctx, selection, tokkmalg, "" #tokalg "",     \
                             KEY_TYPE_KEM, bit_security, -1, 0);               \
    }                                                                          \
                                                                               \
    const OSSL_DISPATCH km_##tokalg##_keymgmt_functions[] = {                 \
        {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))tokalg##_new_key},             \
        {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))kmx_key_free},               \
        {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))kmx_get_params},       \
        {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,                                    \
         (void (*)(void))kmx_settable_params},                                \
        {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,                                    \
         (void (*)(void))km_gettable_params},                                 \
        {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))kmx_set_params},       \
        {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))kmx_has},                     \
        {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))kmx_match},                 \
        {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))kmx_import},               \
        {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))km_imexport_types},  \
        {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))kmx_export},               \
        {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))km_imexport_types},  \
        {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))tokalg##_gen_init},       \
        {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))kmx_gen},                     \
        {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))kmx_gen_cleanup},     \
        {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,                                     \
         (void (*)(void))kmx_gen_set_params},                                 \
        {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,                                \
         (void (*)(void))kmx_gen_settable_params},                            \
        {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))kmx_load},                   \
        {0, NULL}};

#define MAKE_KEM_ECP_KEYMGMT_FUNCTIONS(tokalg, tokkmalg, bit_security)        \
                                                                               \
    static void *ecp_##tokalg##_new_key(void *provctx) {                       \
        return kmx_key_new(PROV_KM_LIBCTX_OF(provctx), tokkmalg,            \
                            "" #tokalg "", KEY_TYPE_ECP_HYB_KEM, NULL,         \
                            bit_security, -1, 0);                              \
    }                                                                          \
                                                                               \
    static void *ecp_##tokalg##_gen_init(void *provctx, int selection) {       \
        return kmx_gen_init(provctx, selection, tokkmalg, "" #tokalg "",     \
                             KEY_TYPE_ECP_HYB_KEM, bit_security, -1, 0);       \
    }                                                                          \
                                                                               \
    const OSSL_DISPATCH km_ecp_##tokalg##_keymgmt_functions[] = {             \
        {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ecp_##tokalg##_new_key},       \
        {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))kmx_key_free},               \
        {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))kmx_get_params},       \
        {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,                                    \
         (void (*)(void))kmx_settable_params},                                \
        {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,                                    \
         (void (*)(void))km_gettable_params},                                 \
        {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))kmx_set_params},       \
        {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))kmx_has},                     \
        {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))kmx_match},                 \
        {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))kmx_import},               \
        {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))km_imexport_types},  \
        {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))kmx_export},               \
        {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))km_imexport_types},  \
        {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))ecp_##tokalg##_gen_init}, \
        {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))kmx_gen},                     \
        {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))kmx_gen_cleanup},     \
        {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,                                     \
         (void (*)(void))kmx_gen_set_params},                                 \
        {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,                                \
         (void (*)(void))kmx_gen_settable_params},                            \
        {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))kmx_load},                   \
        {0, NULL}};

#define MAKE_KEM_ECX_KEYMGMT_FUNCTIONS(tokalg, tokkmalg, bit_security,        \
                                       pqfips)                                 \
    static void *ecx_##tokalg##_new_key(void *provctx) {                       \
        return kmx_key_new(PROV_KM_LIBCTX_OF(provctx), tokkmalg,            \
                            "" #tokalg "", KEY_TYPE_ECX_HYB_KEM, NULL,         \
                            bit_security, -1, pqfips);                         \
    }                                                                          \
                                                                               \
    static void *ecx_##tokalg##_gen_init(void *provctx, int selection) {       \
        return kmx_gen_init(provctx, selection, tokkmalg, "" #tokalg "",     \
                             KEY_TYPE_ECX_HYB_KEM, bit_security, -1, pqfips);  \
    }                                                                          \
                                                                               \
    const OSSL_DISPATCH km_ecx_##tokalg##_keymgmt_functions[] = {             \
        {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ecx_##tokalg##_new_key},       \
        {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))kmx_key_free},               \
        {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))kmx_get_params},       \
        {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,                                    \
         (void (*)(void))kmx_settable_params},                                \
        {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,                                    \
         (void (*)(void))km_gettable_params},                                 \
        {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))kmx_set_params},       \
        {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))kmx_has},                     \
        {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))kmx_match},                 \
        {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))kmx_import},               \
        {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))km_imexport_types},  \
        {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))kmx_export},               \
        {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))km_imexport_types},  \
        {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))ecx_##tokalg##_gen_init}, \
        {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))kmx_gen},                     \
        {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))kmx_gen_cleanup},     \
        {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,                                     \
         (void (*)(void))kmx_gen_set_params},                                 \
        {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,                                \
         (void (*)(void))kmx_gen_settable_params},                            \
        {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))kmx_load},                   \
        {0, NULL}};

///// KM_TEMPLATE_FRAGMENT_KEYMGMT_FUNCTIONS_START
MAKE_SIG_KEYMGMT_FUNCTIONS(dilithium2)
MAKE_SIG_KEYMGMT_FUNCTIONS(dilithium3)
MAKE_SIG_KEYMGMT_FUNCTIONS(dilithium5)

MAKE_SIG_KEYMGMT_FUNCTIONS(mldsa44)
MAKE_SIG_KEYMGMT_FUNCTIONS(mldsa65)
MAKE_SIG_KEYMGMT_FUNCTIONS(mldsa87)

MAKE_SIG_KEYMGMT_FUNCTIONS(sphincssha2128fsimple)
MAKE_SIG_KEYMGMT_FUNCTIONS(sphincssha2128ssimple)
MAKE_SIG_KEYMGMT_FUNCTIONS(sphincssha2192fsimple)
MAKE_SIG_KEYMGMT_FUNCTIONS(sphincsshake128fsimple)

MAKE_KEM_KEYMGMT_FUNCTIONS(kyber512, OQS_KEM_alg_kyber_512, 128)
MAKE_KEM_KEYMGMT_FUNCTIONS(kyber768, OQS_KEM_alg_kyber_768, 192)
MAKE_KEM_KEYMGMT_FUNCTIONS(kyber1024, OQS_KEM_alg_kyber_1024, 256)

MAKE_KEM_KEYMGMT_FUNCTIONS(mlkem512, OQS_KEM_alg_ml_kem_512, 128)
MAKE_KEM_KEYMGMT_FUNCTIONS(mlkem768, OQS_KEM_alg_ml_kem_768, 192)
MAKE_KEM_KEYMGMT_FUNCTIONS(mlkem1024, OQS_KEM_alg_ml_kem_1024, 256)
///// KM_TEMPLATE_FRAGMENT_KEYMGMT_FUNCTIONS_END
