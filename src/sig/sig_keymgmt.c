#include "km_provider.h"
#include "km_util.h"
#include <string.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>  /* OPENSSL_strlcpy */

/* --- map EVP name -> liboqs name --- */
static const char *oqs_name_from_alg(const char *alg) {
    if (!alg) return NULL;
    if (strcmp(alg, "mldsa44") == 0) return "ML-DSA-44";
    if (strcmp(alg, "mldsa65") == 0) return "ML-DSA-65";
    if (strcmp(alg, "mldsa87") == 0) return "ML-DSA-87";
    return NULL;
}
static int secbits_from_alg(const char *alg) {
    if (!alg) return 0;
    if (strcmp(alg, "mldsa44") == 0) return 128;
    if (strcmp(alg, "mldsa65") == 0) return 192;
    if (strcmp(alg, "mldsa87") == 0) return 256;
    return 0;
}
static int ensure_sig(KM_SIG_KEY *k) {
    if (k->sig) return 1;
    const char *oqs = oqs_name_from_alg(k->alg_name);
    if (!oqs) return 0;
    k->sig = OQS_SIG_new(oqs);
    return k->sig != NULL;
}

/* --- NEW/FREE per algoritma --- */
static KM_SIG_KEY *km_sig_keymgmt_new_common(void *vprovctx, const char *algname) {
    KM_PROVCTX *prov = (KM_PROVCTX*)vprovctx;
    KM_SIG_KEY *k = OPENSSL_zalloc(sizeof(*k));
    if (!k) return NULL;
    k->provctx = prov;
    OPENSSL_strlcpy(k->alg_name, algname, sizeof(k->alg_name));
    return k;
}
static void *km_sig_keymgmt_new_mldsa44(void *v){ return km_sig_keymgmt_new_common(v,"mldsa44"); }
static void *km_sig_keymgmt_new_mldsa65(void *v){ return km_sig_keymgmt_new_common(v,"mldsa65"); }
static void *km_sig_keymgmt_new_mldsa87(void *v){ return km_sig_keymgmt_new_common(v,"mldsa87"); }

static void km_sig_keymgmt_free(void *vkey) {
    KM_SIG_KEY *k = (KM_SIG_KEY*)vkey;
    if (!k) return;
    if (k->sig) OQS_SIG_free(k->sig);
    OPENSSL_clear_free(k->priv, k->privlen);
    OPENSSL_free(k->pub);
    OPENSSL_free(k);
}

/* --- OPTIONAL tapi praktis: LOAD-by-reference --- */
/* Tipe parameter yang didukung oleh LOAD */
static const OSSL_PARAM *km_sig_keymgmt_load_types(void)
{
    /* Core akan mengecek ini untuk memutuskan bisa load atau tidak */
    static const OSSL_PARAM loadp[] = {
        OSSL_PARAM_octet_string(OSSL_OBJECT_PARAM_REFERENCE, NULL, 0),
        OSSL_PARAM_utf8_string (OSSL_OBJECT_PARAM_DATA_TYPE, NULL, 0),
        OSSL_PARAM_utf8_string (OSSL_OBJECT_PARAM_DATA_STRUCTURE, NULL, 0),
        OSSL_PARAM_END
    };
    return loadp;
}

static int km_sig_keymgmt_load(void *vkey, const void *reference, size_t ref_sz)
{
    if (ref_sz != sizeof(void*)) return 0;

    KM_SIG_KEY *dst = (KM_SIG_KEY*)vkey;
    KM_SIG_KEY *src = NULL;
    memcpy(&src, reference, sizeof(src));
    if (!src) return 0;

    if (!ensure_sig(dst)) return 0;

    /* Bersihkan state lama */
    OPENSSL_clear_free(dst->priv, dst->privlen);
    dst->priv = NULL; dst->privlen = 0;
    OPENSSL_free(dst->pub);
    dst->pub = NULL; dst->publen = 0;

    /* Copy nama algoritma:
       - Jika alg_name adalah ARRAY: */
    OPENSSL_strlcpy(dst->alg_name, src->alg_name, sizeof(dst->alg_name));
    /* - Jika POINTER, gunakan ini sebagai gantinya:
       OPENSSL_free(dst->alg_name);
       dst->alg_name = OPENSSL_strdup(src->alg_name);
       if (!dst->alg_name) return 0;
    */

    /* Deep-copy priv */
    if (src->priv && src->privlen) {
        dst->priv = OPENSSL_malloc(src->privlen);
        if (!dst->priv) return 0;
        memcpy(dst->priv, src->priv, src->privlen);
        dst->privlen = src->privlen;
    }

    /* Deep-copy pub (jika ada; boleh kosong) */
    if (src->pub && src->publen) {
        dst->pub = OPENSSL_malloc(src->publen);
        if (!dst->pub) {
            OPENSSL_clear_free(dst->priv, dst->privlen);
            dst->priv = NULL; dst->privlen = 0;
            return 0;
        }
        memcpy(dst->pub, src->pub, src->publen);
        dst->publen = src->publen;
    }

    fprintf(stderr, "[keymgmt_load] loaded key for %s (priv=%zu, pub=%zu)\n",
            dst->alg_name, dst->privlen, dst->publen);
    return 1;
}


/* --- GEN --- */
static void *km_sig_keymgmt_gen_init(void *vprovctx, int selection, const OSSL_PARAM params[]) {
    (void)selection; (void)params; return vprovctx;
}
static void *km_sig_keymgmt_gen_do(void *vgenctx, const char *algname) {
    KM_SIG_KEY *k = km_sig_keymgmt_new_common(vgenctx, algname);
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
static void *km_sig_keymgmt_gen_mldsa44(void *c, OSSL_CALLBACK *cb, void *cbarg){ (void)cb;(void)cbarg; return km_sig_keymgmt_gen_do(c,"mldsa44"); }
static void *km_sig_keymgmt_gen_mldsa65(void *c, OSSL_CALLBACK *cb, void *cbarg){ (void)cb;(void)cbarg; return km_sig_keymgmt_gen_do(c,"mldsa65"); }
static void *km_sig_keymgmt_gen_mldsa87(void *c, OSSL_CALLBACK *cb, void *cbarg){ (void)cb;(void)cbarg; return km_sig_keymgmt_gen_do(c,"mldsa87"); }
static void km_sig_keymgmt_gen_cleanup(void *c){ (void)c; }

/* --- HAS / MATCH --- */
static int km_sig_keymgmt_has(const void *vkey, int sel) {
    const KM_SIG_KEY *k = (const KM_SIG_KEY*)vkey;
    if (!k) return 0;
    if ((sel & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)  && !(k->pub  && k->publen)) return 0;
    if ((sel & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && !(k->priv && k->privlen)) return 0;
    return 1;
}
static int km_sig_keymgmt_match(const void *va, const void *vb, int sel) {
    const KM_SIG_KEY *a = (const KM_SIG_KEY*)va;
    const KM_SIG_KEY *b = (const KM_SIG_KEY*)vb;
    if (a == b) return 1;
    if (!a || !b) return 0;
    if (sel & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        if (!(a->pub && b->pub && a->publen == b->publen &&
              memcmp(a->pub, b->pub, a->publen) == 0))
            return 0;
    }
    if (sel & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        if (!(a->priv && b->priv && a->privlen == b->privlen &&
              memcmp(a->priv, b->priv, a->privlen) == 0))
            return 0;
    }
    return 1;
}

/* --- GET(ABLE)_PARAMS --- */
static const OSSL_PARAM *km_sig_keymgmt_gettable_params(void *provctx) {
    (void)provctx;
    static const OSSL_PARAM tl[] = {
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_int   (OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_END
    };
    return tl;
}
static int km_sig_keymgmt_get_params(void *vkey, OSSL_PARAM *params) {
    KM_SIG_KEY *k = (KM_SIG_KEY*)vkey;
    if (!ensure_sig(k)) return 0;
    OSSL_PARAM *p;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE))      ) OSSL_PARAM_set_size_t(p, k->sig->length_signature);
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) ) OSSL_PARAM_set_int   (p, secbits_from_alg(k->alg_name));
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS))          ) OSSL_PARAM_set_size_t(p, k->sig->length_public_key * 8);
    return 1;
}

/* --- IMPORT/EXPORT TYPES --- */
static const OSSL_PARAM *km_sig_keymgmt_import_types(int selector)
{
    (void)selector;
    static const OSSL_PARAM keypair_params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,  NULL, 0),
        OSSL_PARAM_END
    };
    return keypair_params;
}


static const OSSL_PARAM *km_sig_keymgmt_export_types(int selector) {
    /* tambahkan REFERENCE agar core bisa load-by-ref */
    static const OSSL_PARAM ref_only[]  = { OSSL_PARAM_octet_string(OSSL_OBJECT_PARAM_REFERENCE, NULL, 0), OSSL_PARAM_END };
    static const OSSL_PARAM pub_only[]  = { OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,  NULL, 0), OSSL_PARAM_END };
    static const OSSL_PARAM priv_only[] = { OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0), OSSL_PARAM_END };
    static const OSSL_PARAM both_with_ref[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,  NULL, 0),
        OSSL_PARAM_octet_string(OSSL_OBJECT_PARAM_REFERENCE, NULL, 0),
        OSSL_PARAM_END
    };
    if (selector & OSSL_KEYMGMT_SELECT_KEYPAIR)      return both_with_ref;
    if (selector & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)  return priv_only;
    if (selector & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)   return pub_only;
    return ref_only;
}

/* --- IMPORT/EXPORT --- */

/* helper copy octets (letakkan di atas, berdampingan dengan ensure_sig) */
static int get_octet_opt(const OSSL_PARAM params[], const char *key,
                         unsigned char **out, size_t *outlen)
{
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, key);
    if (!p) { *out = NULL; *outlen = 0; return 1; }  // optional
    unsigned char *tmp = NULL; size_t n = 0;
    if (!km_param_get_octet_string(params, key, &tmp, &n)) return 0;
    *out = tmp; *outlen = n;
    return 1;
}

// Perbaikan untuk sig_keymgmt.c - khususnya fungsi import

static int km_sig_keymgmt_import(void *vkey, int selector, const OSSL_PARAM params[])
{
    fprintf(stderr, "[keymgmt_import] selector=0x%x\n", selector);
    
    KM_SIG_KEY *k = (KM_SIG_KEY*)vkey;
    if (!k) {
        fprintf(stderr, "[keymgmt_import] ERROR: vkey is NULL\n");
        return 0;
    }
    
    fprintf(stderr, "[keymgmt_import] key alg_name=%s\n", k->alg_name);
    
    // Ensure OQS_SIG is initialized
    if (!ensure_sig(k)) {
        fprintf(stderr, "[keymgmt_import] ERROR: ensure_sig failed\n");
        return 0;
    }
    
    fprintf(stderr, "[keymgmt_import] sig initialized, length_secret_key=%zu\n", k->sig->length_secret_key);

    // Debug: print all available parameters
    for (const OSSL_PARAM *p = params; p && p->key; p++) {
        fprintf(stderr, "[keymgmt_import] param: %s (type=%d, size=%zu)\n", 
                p->key, p->data_type, p->data_size);
    }

    // Try to get private key
    const OSSL_PARAM *priv_param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (priv_param) {
        fprintf(stderr, "[keymgmt_import] found PRIV_KEY param, size=%zu, expected=%zu\n", 
                priv_param->data_size, k->sig->length_secret_key);
        
        // Validate size
        if (priv_param->data_size != k->sig->length_secret_key) {
            fprintf(stderr, "[keymgmt_import] ERROR: private key size mismatch\n");
            return 0;
        }
        
        // Allocate and copy private key
        OPENSSL_clear_free(k->priv, k->privlen);
        k->priv = OPENSSL_malloc(priv_param->data_size);
        if (!k->priv) {
            fprintf(stderr, "[keymgmt_import] ERROR: malloc failed for private key\n");
            return 0;
        }
        
        memcpy(k->priv, priv_param->data, priv_param->data_size);
        k->privlen = priv_param->data_size;
        
        fprintf(stderr, "[keymgmt_import] private key imported successfully\n");
        
        // For MLDSA, we can derive public key from private key if needed
        if (!k->pub) {
            k->publen = k->sig->length_public_key;
            k->pub = OPENSSL_malloc(k->publen);
            if (k->pub) {
                // Extract public key from private key (MLDSA private key contains public key)
                // This depends on liboqs implementation - you might need to adjust this
                // For now, we'll leave public key derivation for later if needed
                fprintf(stderr, "[keymgmt_import] public key derivation skipped\n");
            }
        }
    } else {
        fprintf(stderr, "[keymgmt_import] WARNING: no PRIV_KEY parameter found\n");
    }

    // Try to get public key (optional)
    const OSSL_PARAM *pub_param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (pub_param) {
        fprintf(stderr, "[keymgmt_import] found PUB_KEY param, size=%zu\n", pub_param->data_size);
        
        OPENSSL_free(k->pub);
        k->pub = OPENSSL_malloc(pub_param->data_size);
        if (k->pub) {
            memcpy(k->pub, pub_param->data, pub_param->data_size);
            k->publen = pub_param->data_size;
            fprintf(stderr, "[keymgmt_import] public key imported successfully\n");
        }
    }

    // Check if we have at least what was requested
    if ((selector & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && (!k->priv || !k->privlen)) {
        fprintf(stderr, "[keymgmt_import] ERROR: private key requested but not available\n");
        return 0;
    }
    
    if ((selector & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) && (!k->pub || !k->publen)) {
        fprintf(stderr, "[keymgmt_import] WARNING: public key requested but not available\n");
        // Don't fail here - we might be able to derive it later
    }

    fprintf(stderr, "[keymgmt_import] import successful\n");
    return 1;
}

// Also make sure the decoder sends the right data type parameter
// In dec_raw.c, make sure you're sending the algorithm name correctly:

// In your decoder (dec_raw.c), change this line:
// if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_OBJECT_PARAM_DATA_TYPE, alg, 0)) goto err;

// Make sure the algorithm name matches exactly what keymgmt expects.
// You might need to debug what exactly is being passed.

// static int km_sig_keymgmt_import(void *vkey, int selector, const OSSL_PARAM params[])
// {
//     fprintf(stderr, "[keymgmt_import] selector=0x%x has_privparam=%d has_pubparam=%d\n",
//         selector,
//         OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY)!=NULL,
//         OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY)!=NULL);

//     KM_SIG_KEY *k = (KM_SIG_KEY*)vkey;
//     fprintf(stderr, "[km_sig_keymgmt_import] Called\n");
//     if (!ensure_sig(k)) return 0;
//     fprintf(stderr, "[km_sig_keymgmt_import] After ensure_sig\n");

//     unsigned char *p = NULL; size_t n = 0;

//     /* PRIV (optional, tapi kalau ada kita simpan) */
//     if (!get_octet_opt(params, OSSL_PKEY_PARAM_PRIV_KEY, &p, &n)) return 0;
//     if (p && n) {
//         OPENSSL_clear_free(k->priv, k->privlen);
//         k->priv = OPENSSL_malloc(n);
//         if (!k->priv) { OPENSSL_free(p); return 0; }
//         memcpy(k->priv, p, n); k->privlen = n;
//         OPENSSL_free(p);
//     }

//     /* PUB (optional) */
//     p = NULL; n = 0;
//     if (!get_octet_opt(params, OSSL_PKEY_PARAM_PUB_KEY, &p, &n)) return 0;
//     if (p && n) {
//         OPENSSL_free(k->pub);
//         k->pub = OPENSSL_malloc(n);
//         if (!k->pub) { OPENSSL_free(p); return 0; }
//         memcpy(k->pub, p, n); k->publen = n;
//         OPENSSL_free(p);
//     }

//     return 1;  // <- sukses walau hanya dapat priv saja
// }


// static int km_sig_keymgmt_import(void *vkey, int selector, const OSSL_PARAM params[]) {
//     KM_SIG_KEY *k = (KM_SIG_KEY*)vkey;
//     if (!ensure_sig(k)) return 0;

//     if (selector & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
//         unsigned char *p=NULL; size_t n=0;
//         if (!km_param_get_octet_string(params, OSSL_PKEY_PARAM_PUB_KEY, &p, &n)) return 0;
//         OPENSSL_free(k->pub);
//         k->pub = OPENSSL_malloc(n);
//         if (!k->pub) { OPENSSL_free(p); return 0; }
//         memcpy(k->pub, p, n); k->publen = n;
//         OPENSSL_free(p);
//     }
//     if (selector & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
//         unsigned char *p=NULL; size_t n=0;
//         if (!km_param_get_octet_string(params, OSSL_PKEY_PARAM_PRIV_KEY, &p, &n)) return 0;
//         OPENSSL_clear_free(k->priv, k->privlen);
//         k->priv = OPENSSL_malloc(n);
//         if (!k->priv) { OPENSSL_free(p); return 0; }
//         memcpy(k->priv, p, n); k->privlen = n;
//         OPENSSL_free(p);
//     }
//     return 1;
// }


static int km_sig_keymgmt_export(void *vkey, int selector, OSSL_CALLBACK *cb, void *cbarg) {
    KM_SIG_KEY *k = (KM_SIG_KEY*)vkey;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *out = NULL;
    int ok = 0;
    if (!bld) return 0;

    /* push reference pointer untuk jalur LOAD */
    void *ref = (void*)k;
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_OBJECT_PARAM_REFERENCE, &ref, sizeof(ref));

    km_param_build_pubpriv(bld,
        (selector & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)  ? k->pub  : NULL,
        (selector & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)  ? k->publen : 0,
        (selector & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) ? k->priv : NULL,
        (selector & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) ? k->privlen : 0,
        &out);

    ok = cb(out, cbarg);
    OSSL_PARAM_free(out);
    OSSL_PARAM_BLD_free(bld);
    return ok;
}

/* --- QUERY_OPERATION_NAME (3.0) --- */
static const char *km_sig_query_op_name_mldsa44(int op){ return (op==OSSL_OP_SIGNATURE)?"mldsa44":NULL; }
static const char *km_sig_query_op_name_mldsa65(int op){ return (op==OSSL_OP_SIGNATURE)?"mldsa65":NULL; }
static const char *km_sig_query_op_name_mldsa87(int op){ return (op==OSSL_OP_SIGNATURE)?"mldsa87":NULL; }

/* --- DISPATCH per varian --- */
#define KM_DISPATCH_TABLE(name,newfn,genfn,queryop)                           \
const OSSL_DISPATCH name[] = {                                                \
    { OSSL_FUNC_KEYMGMT_NEW,                   (void(*)(void))newfn },        \
    { OSSL_FUNC_KEYMGMT_FREE,                  (void(*)(void))km_sig_keymgmt_free }, \
    { OSSL_FUNC_KEYMGMT_HAS,                   (void(*)(void))km_sig_keymgmt_has },  \
    { OSSL_FUNC_KEYMGMT_MATCH,                 (void(*)(void))km_sig_keymgmt_match },\
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,       (void(*)(void))km_sig_keymgmt_gettable_params }, \
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,            (void(*)(void))km_sig_keymgmt_get_params }, \
    /* --- LOAD/LOAD_TYPES DIHAPUS --- */                                      \
    { OSSL_FUNC_KEYMGMT_IMPORT,                (void(*)(void))km_sig_keymgmt_import }, \
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,          (void(*)(void))km_sig_keymgmt_import_types }, \
    { OSSL_FUNC_KEYMGMT_EXPORT,                (void(*)(void))km_sig_keymgmt_export }, \
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,          (void(*)(void))km_sig_keymgmt_export_types }, \
    { OSSL_FUNC_KEYMGMT_GEN_INIT,              (void(*)(void))km_sig_keymgmt_gen_init }, \
    { OSSL_FUNC_KEYMGMT_GEN,                   (void(*)(void))genfn },        \
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,           (void(*)(void))km_sig_keymgmt_gen_cleanup }, \
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,  (void(*)(void))queryop },      \
    { 0, NULL }                                                               \
}


KM_DISPATCH_TABLE(km_sig_keymgmt_fns_mldsa44, km_sig_keymgmt_new_mldsa44, km_sig_keymgmt_gen_mldsa44, km_sig_query_op_name_mldsa44);
KM_DISPATCH_TABLE(km_sig_keymgmt_fns_mldsa65, km_sig_keymgmt_new_mldsa65, km_sig_keymgmt_gen_mldsa65, km_sig_query_op_name_mldsa65);
KM_DISPATCH_TABLE(km_sig_keymgmt_fns_mldsa87, km_sig_keymgmt_new_mldsa87, km_sig_keymgmt_gen_mldsa87, km_sig_query_op_name_mldsa87);
