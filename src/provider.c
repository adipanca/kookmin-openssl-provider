// SPDX-License-Identifier: Apache-2.0 AND MIT
// KM OpenSSL 3 provider

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>   // getenv, strtol
#include <limits.h>   // INT_MAX
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#include "provider.h"

/* ===========================================================
 * Logging (variadic) — enabled when KMPROV env is set
 * ===========================================================
 */
#ifndef NDEBUG
#  define KM_LOG_ENABLED() (getenv("KMPROV") != NULL)
#  define KM_LOG(fmt, ...) do { if (KM_LOG_ENABLED()) printf(fmt, ##__VA_ARGS__); } while(0)
#else
#  define KM_LOG_ENABLED() (0)
#  define KM_LOG(fmt, ...) do {} while(0)
#endif

/* ===========================================================
 * Forward decls (provider interface)
 * ===========================================================
 */
static OSSL_FUNC_provider_gettable_params_fn kmprovider_gettable_params;
static OSSL_FUNC_provider_get_params_fn      kmprovider_get_params;
static OSSL_FUNC_provider_query_operation_fn kmprovider_query;
extern OSSL_FUNC_provider_get_capabilities_fn km_provider_get_readiness;

/* ===========================================================
 * OID table & patching (env-driven)
 * ===========================================================
 *
 * Alternating [oid, shortname, oid, shortname, ...]
 * Sisa elemen akan diisi NULL secara default (C zero-init).
 */
#define KM_OID_CNT 220

static const char *km_oid_alg_list[KM_OID_CNT] = {
    /* KEM OIDs */
    "1.3.6.1.4.1.2.267.8.2.2", "kyber512",
    NULL, "x25519_kyber512",
    "1.3.6.1.4.1.2.267.8.3.3", "kyber768",
    NULL,"x25519_kyber768",
    "1.3.6.1.4.1.2.267.8.4.4", "kyber1024",
    "2.16.840.1.101.3.4.4.1",  "mlkem512",
    "1.3.6.1.4.1.22554.5.8.1","x25519_mlkem512",
    "2.16.840.1.101.3.4.4.2",  "mlkem768",
    NULL,"X25519MLKEM768",
    "2.16.840.1.101.3.4.4.3",  "mlkem1024",

    /* Signature OIDs */
    "1.3.6.1.4.1.2.267.7.4.4",  "dilithium2",
    "1.3.6.1.4.1.2.267.7.6.5",  "dilithium3",
    "1.3.6.1.4.1.2.267.7.8.7",  "dilithium5",
    "1.3.6.1.4.1.2.267.12.4.4", "mldsa44",
    "1.3.6.1.4.1.2.267.12.6.5", "mldsa65",
    "1.3.6.1.4.1.2.267.12.8.7", "mldsa87",
    "1.3.9999.6.4.13",          "sphincssha2128fsimple",
    "1.3.9999.6.4.16",          "sphincssha2128ssimple",
    "1.3.9999.6.5.10",          "sphincssha2192fsimple",
    "1.3.9999.6.7.13",          "sphincsshake128fsimple",
};

/* Pemetaan ENV → indeks OID di km_oid_alg_list (index OID saja, bukan nama) */
typedef struct {
    const char *envkey;
    int         idx;
} km_oid_envmap_t;

#define KM_KEMOID_BASE 0
#define KM_SIGOID_BASE 12  /* 6 KEM * 2 (oid+name) = 12 elemen awal */

static const km_oid_envmap_t km_oid_envmap[] = {
    /* KEM overrides */
    { "KM_OID_KYBER512",   KM_KEMOID_BASE + 0  },
    { "KM_OID_KYBER768",   KM_KEMOID_BASE + 2  },
    { "KM_OID_KYBER1024",  KM_KEMOID_BASE + 4  },
    { "KM_OID_MLKEM512",   KM_KEMOID_BASE + 6  },
    { "KM_OID_MLKEM768",   KM_KEMOID_BASE + 8  },
    { "KM_OID_MLKEM1024",  KM_KEMOID_BASE + 10 },

    /* Signature overrides */
    { "KM_OID_DILITHIUM2", KM_SIGOID_BASE + 0  },
    { "KM_OID_DILITHIUM3", KM_SIGOID_BASE + 2  },
    { "KM_OID_DILITHIUM5", KM_SIGOID_BASE + 4  },
    { "KM_OID_MLDSA44",    KM_SIGOID_BASE + 6  },
    { "KM_OID_MLDSA65",    KM_SIGOID_BASE + 8  },
    { "KM_OID_MLDSA87",    KM_SIGOID_BASE + 10 },
    { "KM_OID_SPHINCSSHA2128FSIMPLE", KM_SIGOID_BASE + 12 },
    { "KM_OID_SPHINCSSHA2128SSIMPLE", KM_SIGOID_BASE + 14 },
    { "KM_OID_SPHINCSSHA2192FSIMPLE", KM_SIGOID_BASE + 16 },
    { "KM_OID_SPHINCSSHAKE128FSIMPLE",KM_SIGOID_BASE + 18 },
};

static int km_patch_oids(void) {
    for (size_t i = 0; i < sizeof(km_oid_envmap)/sizeof(km_oid_envmap[0]); ++i) {
        const char *val = getenv(km_oid_envmap[i].envkey);
        if (val && *val) {
            int pos = km_oid_envmap[i].idx;
            if (pos >= 0 && pos < KM_OID_CNT && (pos % 2 == 0)) {
                km_oid_alg_list[pos] = val;
                KM_LOG("KM PROV: OID patched %s -> %s\n", km_oid_envmap[i].envkey, val);
            }
        }
    }
    return 1;
}

/* Ambil komponen terakhir dari sebuah OID (angka setelah '.' terakhir) */
int get_composite_idx(int idx) {  /* 0..(KM_OID_CNT/2 - 1) */
    int pos = idx * 2;
    if (pos < 0 || pos + 1 >= KM_OID_CNT) return -1;

    const char *s = km_oid_alg_list[pos];
    if (!s) return -1;

    const char *lastdot = strrchr(s, '.');
    if (!lastdot || !*(lastdot + 1)) return -1;

    errno = 0;
    long v = strtol(lastdot + 1, NULL, 10);
    if (errno == ERANGE || v < 0 || v > INT_MAX) return -1;
    return (int)v;
}

/* ===========================================================
 * Macros: algorithm registration (makro TANPA koma; koma di pemanggilan)
 * ===========================================================
 */
#define SIGALG(NAMES, SECBITS, FUNC) \
    { NAMES, "provider=kookminlib,kookminlib.security_bits=" #SECBITS, FUNC }

#define KEMBASEALG(NAMES, SECBITS) \
    { #NAMES, "provider=kookminlib,kookminlib.security_bits=" #SECBITS, km_generic_kem_functions }

#define KEMKMALG(NAMES, SECBITS) \
    { #NAMES, "provider=kookminlib,kookminlib.security_bits=" #SECBITS, km_##NAMES##_keymgmt_functions }

#define KEMHYBALG(NAMES, SECBITS) \
    { #NAMES, "provider=kookminlib,kookminlib.security_bits=" #SECBITS, km_hybrid_kem_functions }

#define KEMKMHYBALG(NAMES, SECBITS, HYBTYPE) \
    { #NAMES, "provider=oqsprovider,oqsprovider.security_bits=" #SECBITS, km_##HYBTYPE##_##NAMES##_keymgmt_functions }


/* ===========================================================
 * Core getter pointers
 * ===========================================================
 */
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn      *c_get_params      = NULL;

/* ===========================================================
 * Provider params to core
 * ===========================================================
 */
static const OSSL_PARAM kmprovider_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME,      OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION,   OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS,    OSSL_PARAM_INTEGER,  NULL, 0),
    OSSL_PARAM_END
};

/* ===========================================================
 * Algorithm lists
 * ===========================================================
 */
static const OSSL_ALGORITHM kmprovider_signatures[] = {
    SIGALG("dilithium2",             128, km_signature_functions),
    SIGALG("dilithium3",             192, km_signature_functions),
    SIGALG("dilithium5",             256, km_signature_functions),
    SIGALG("mldsa44",                128, km_signature_functions),
    SIGALG("mldsa65",                192, km_signature_functions),
    SIGALG("mldsa87",                256, km_signature_functions),
    SIGALG("sphincssha2128fsimple",  128, km_signature_functions),
    SIGALG("sphincssha2128ssimple",  128, km_signature_functions),
    SIGALG("sphincssha2192fsimple",  192, km_signature_functions),
    SIGALG("sphincsshake128fsimple", 128, km_signature_functions),
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM kmprovider_asym_kems[] = {
    KEMBASEALG(kyber512,  128),
    KEMHYBALG(x25519_kyber512, 128),
    KEMBASEALG(kyber768,  192),
    KEMHYBALG(x25519_kyber768, 128),
    KEMBASEALG(kyber1024, 256),
    KEMBASEALG(mlkem512,  128),
    KEMHYBALG(x25519_mlkem512, 128),
    KEMBASEALG(mlkem768,  192),
    KEMHYBALG(X25519MLKEM768, 128),
    KEMBASEALG(mlkem1024, 256),
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM kmprovider_keymgmt[] = {
    SIGALG("dilithium2",             128, km_dilithium2_keymgmt_functions),
    SIGALG("dilithium3",             192, km_dilithium3_keymgmt_functions),
    SIGALG("dilithium5",             256, km_dilithium5_keymgmt_functions),
    SIGALG("mldsa44",                128, km_mldsa44_keymgmt_functions),
    SIGALG("mldsa65",                192, km_mldsa65_keymgmt_functions),
    SIGALG("mldsa87",                256, km_mldsa87_keymgmt_functions),
    SIGALG("sphincssha2128fsimple",  128, km_sphincssha2128fsimple_keymgmt_functions),
    SIGALG("sphincssha2128ssimple",  128, km_sphincssha2128ssimple_keymgmt_functions),
    SIGALG("sphincssha2192fsimple",  192, km_sphincssha2192fsimple_keymgmt_functions),
    SIGALG("sphincsshake128fsimple", 128, km_sphincsshake128fsimple_keymgmt_functions),
    KEMKMALG(kyber512,  128),
    KEMKMHYBALG(x25519_kyber512, 128, ecx),
    KEMKMALG(kyber768,  192),
    KEMKMHYBALG(x25519_kyber768, 128, ecx),
    KEMKMALG(kyber1024, 256),
    KEMKMALG(mlkem512,  128),
    KEMKMHYBALG(x25519_mlkem512, 128, ecx),
    KEMKMALG(mlkem768,  192),
    KEMKMHYBALG(X25519MLKEM768, 128, ecx),
    KEMKMALG(mlkem1024, 256),
    { NULL, NULL, NULL }
};

/* ---------- Encoder/Decoder ---------- */

#define ENCODER_PROVIDER "kookminlib"
#define ENCODER_STRUCTURE_type_specific_keypair   "type-specific"
#define ENCODER_STRUCTURE_type_specific_params    "type-specific"
#define ENCODER_STRUCTURE_type_specific           "type-specific"
#define ENCODER_STRUCTURE_type_specific_no_pub    "type-specific"
#define ENCODER_STRUCTURE_PKCS8                   "pkcs8"
#define ENCODER_STRUCTURE_SubjectPublicKeyInfo    "SubjectPublicKeyInfo"
#define ENCODER_STRUCTURE_PrivateKeyInfo          "PrivateKeyInfo"
#define ENCODER_STRUCTURE_EncryptedPrivateKeyInfo "EncryptedPrivateKeyInfo"

#define ENCODER_TEXT(_name, _sym) \
    { _name, "provider=" ENCODER_PROVIDER ",output=text", (km_##_sym##_to_text_encoder_functions) }

#define ENCODER_w_structure(_name, _sym, _output, _structure) \
    { _name, "provider=" ENCODER_PROVIDER ",output=" #_output ",structure=" ENCODER_STRUCTURE_##_structure, \
      (km_##_sym##_to_##_structure##_##_output##_encoder_functions) }

static const OSSL_ALGORITHM kmprovider_encoder[] = {

    ENCODER_w_structure("kyber512", kyber512, der, PrivateKeyInfo),
    ENCODER_w_structure("kyber512", kyber512, pem, PrivateKeyInfo),
    ENCODER_w_structure("kyber512", kyber512, der, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("kyber512", kyber512, pem, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("kyber512", kyber512, der, SubjectPublicKeyInfo),
    ENCODER_w_structure("kyber512", kyber512, pem, SubjectPublicKeyInfo),
    ENCODER_TEXT("kyber512", kyber512),

    ENCODER_w_structure("x25519_kyber512", x25519_kyber512, der, PrivateKeyInfo),
    ENCODER_w_structure("x25519_kyber512", x25519_kyber512, pem, PrivateKeyInfo),
    ENCODER_w_structure("x25519_kyber512", x25519_kyber512, der, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("x25519_kyber512", x25519_kyber512, pem, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("x25519_kyber512", x25519_kyber512, der, SubjectPublicKeyInfo),
    ENCODER_w_structure("x25519_kyber512", x25519_kyber512, pem, SubjectPublicKeyInfo),
    ENCODER_TEXT("x25519_kyber512", x25519_kyber512),

    ENCODER_w_structure("kyber768", kyber768, der, PrivateKeyInfo),
    ENCODER_w_structure("kyber768", kyber768, pem, PrivateKeyInfo),
    ENCODER_w_structure("kyber768", kyber768, der, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("kyber768", kyber768, pem, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("kyber768", kyber768, der, SubjectPublicKeyInfo),
    ENCODER_w_structure("kyber768", kyber768, pem, SubjectPublicKeyInfo),
    ENCODER_TEXT("kyber768", kyber768),

    ENCODER_w_structure("x25519_kyber768", x25519_kyber768, der, PrivateKeyInfo),
    ENCODER_w_structure("x25519_kyber768", x25519_kyber768, pem, PrivateKeyInfo),
    ENCODER_w_structure("x25519_kyber768", x25519_kyber768, der, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("x25519_kyber768", x25519_kyber768, pem, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("x25519_kyber768", x25519_kyber768, der, SubjectPublicKeyInfo),
    ENCODER_w_structure("x25519_kyber768", x25519_kyber768, pem, SubjectPublicKeyInfo),
    ENCODER_TEXT("x25519_kyber768", x25519_kyber768),

    ENCODER_w_structure("kyber1024", kyber1024, der, PrivateKeyInfo),
    ENCODER_w_structure("kyber1024", kyber1024, pem, PrivateKeyInfo),
    ENCODER_w_structure("kyber1024", kyber1024, der, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("kyber1024", kyber1024, pem, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("kyber1024", kyber1024, der, SubjectPublicKeyInfo),
    ENCODER_w_structure("kyber1024", kyber1024, pem, SubjectPublicKeyInfo),
    ENCODER_TEXT("kyber1024", kyber1024),

    ENCODER_w_structure("mlkem512",  mlkem512,  der, PrivateKeyInfo),
    ENCODER_w_structure("mlkem512",  mlkem512,  pem, PrivateKeyInfo),
    ENCODER_w_structure("mlkem512",  mlkem512,  der, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("mlkem512",  mlkem512,  pem, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("mlkem512",  mlkem512,  der, SubjectPublicKeyInfo),
    ENCODER_w_structure("mlkem512",  mlkem512,  pem, SubjectPublicKeyInfo),
    ENCODER_TEXT       ("mlkem512",  mlkem512),

    ENCODER_w_structure("x25519_mlkem512", x25519_mlkem512, der, PrivateKeyInfo),
    ENCODER_w_structure("x25519_mlkem512", x25519_mlkem512, pem, PrivateKeyInfo),
    ENCODER_w_structure("x25519_mlkem512", x25519_mlkem512, der, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("x25519_mlkem512", x25519_mlkem512, pem, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("x25519_mlkem512", x25519_mlkem512, der, SubjectPublicKeyInfo),
    ENCODER_w_structure("x25519_mlkem512", x25519_mlkem512, pem, SubjectPublicKeyInfo),
    ENCODER_TEXT("x25519_mlkem512", x25519_mlkem512),

    ENCODER_w_structure("mlkem768",  mlkem768,  der, PrivateKeyInfo),
    ENCODER_w_structure("mlkem768",  mlkem768,  pem, PrivateKeyInfo),
    ENCODER_w_structure("mlkem768",  mlkem768,  der, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("mlkem768",  mlkem768,  pem, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("mlkem768",  mlkem768,  der, SubjectPublicKeyInfo),
    ENCODER_w_structure("mlkem768",  mlkem768,  pem, SubjectPublicKeyInfo),
    ENCODER_TEXT       ("mlkem768",  mlkem768),

    ENCODER_w_structure("X25519MLKEM768", X25519MLKEM768, der, PrivateKeyInfo),
    ENCODER_w_structure("X25519MLKEM768", X25519MLKEM768, pem, PrivateKeyInfo),
    ENCODER_w_structure("X25519MLKEM768", X25519MLKEM768, der, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("X25519MLKEM768", X25519MLKEM768, pem, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("X25519MLKEM768", X25519MLKEM768, der, SubjectPublicKeyInfo),
    ENCODER_w_structure("X25519MLKEM768", X25519MLKEM768, pem, SubjectPublicKeyInfo),
    ENCODER_TEXT("X25519MLKEM768", X25519MLKEM768),

    ENCODER_w_structure("mlkem1024", mlkem1024, der, PrivateKeyInfo),
    ENCODER_w_structure("mlkem1024", mlkem1024, pem, PrivateKeyInfo),
    ENCODER_w_structure("mlkem1024", mlkem1024, der, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("mlkem1024", mlkem1024, pem, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("mlkem1024", mlkem1024, der, SubjectPublicKeyInfo),
    ENCODER_w_structure("mlkem1024", mlkem1024, pem, SubjectPublicKeyInfo),
    ENCODER_TEXT       ("mlkem1024", mlkem1024),

    ENCODER_w_structure("mldsa44",   mldsa44,   der, PrivateKeyInfo),
    ENCODER_w_structure("mldsa44",   mldsa44,   pem, PrivateKeyInfo),
    ENCODER_w_structure("mldsa44",   mldsa44,   der, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("mldsa44",   mldsa44,   pem, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("mldsa44",   mldsa44,   der, SubjectPublicKeyInfo),
    ENCODER_w_structure("mldsa44",   mldsa44,   pem, SubjectPublicKeyInfo),
    ENCODER_TEXT       ("mldsa44",   mldsa44),

    ENCODER_w_structure("mldsa65",   mldsa65,   der, PrivateKeyInfo),
    ENCODER_w_structure("mldsa65",   mldsa65,   pem, PrivateKeyInfo),
    ENCODER_w_structure("mldsa65",   mldsa65,   der, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("mldsa65",   mldsa65,   pem, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("mldsa65",   mldsa65,   der, SubjectPublicKeyInfo),
    ENCODER_w_structure("mldsa65",   mldsa65,   pem, SubjectPublicKeyInfo),
    ENCODER_TEXT       ("mldsa65",   mldsa65),

    ENCODER_w_structure("mldsa87",   mldsa87,   der, PrivateKeyInfo),
    ENCODER_w_structure("mldsa87",   mldsa87,   pem, PrivateKeyInfo),
    ENCODER_w_structure("mldsa87",   mldsa87,   der, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("mldsa87",   mldsa87,   pem, EncryptedPrivateKeyInfo),
    ENCODER_w_structure("mldsa87",   mldsa87,   der, SubjectPublicKeyInfo),
    ENCODER_w_structure("mldsa87",   mldsa87,   pem, SubjectPublicKeyInfo),
    ENCODER_TEXT       ("mldsa87",   mldsa87),

    { NULL, NULL, NULL }
};

#define DECODER_PROVIDER "kookminlib"
#define DECODER_STRUCTURE_type_specific_keypair "type-specific"
#define DECODER_STRUCTURE_type_specific_params  "type-specific"
#define DECODER_STRUCTURE_type_specific         "type-specific"
#define DECODER_STRUCTURE_type_specific_no_pub  "type-specific"
#define DECODER_STRUCTURE_PKCS8                 "pkcs8"
#define DECODER_STRUCTURE_SubjectPublicKeyInfo  "SubjectPublicKeyInfo"
#define DECODER_STRUCTURE_PrivateKeyInfo        "PrivateKeyInfo"

#define DECODER_w_structure(_name, _input, _structure, _output) \
    { _name, "provider=" DECODER_PROVIDER ",input=" #_input ",structure=" DECODER_STRUCTURE_##_structure, \
      (km_##_structure##_##_input##_to_##_output##_decoder_functions) }

static const OSSL_ALGORITHM kmprovider_decoder[] = {

    DECODER_w_structure("kyber512", der, PrivateKeyInfo, kyber512),
    DECODER_w_structure("kyber512", der, SubjectPublicKeyInfo, kyber512),
    DECODER_w_structure("x25519_kyber512", der, PrivateKeyInfo, x25519_kyber512),
    DECODER_w_structure("x25519_kyber512", der, SubjectPublicKeyInfo, x25519_kyber512),

    DECODER_w_structure("kyber768", der, PrivateKeyInfo, kyber768),
    DECODER_w_structure("kyber768", der, SubjectPublicKeyInfo, kyber768),
    DECODER_w_structure("x25519_kyber768", der, PrivateKeyInfo, x25519_kyber768),
    DECODER_w_structure("x25519_kyber768", der, SubjectPublicKeyInfo, x25519_kyber768),

    DECODER_w_structure("kyber1024", der, PrivateKeyInfo, kyber1024),
    DECODER_w_structure("kyber1024", der, SubjectPublicKeyInfo, kyber1024),

    DECODER_w_structure("mlkem512",  der, PrivateKeyInfo,       mlkem512),
    DECODER_w_structure("mlkem512",  der, SubjectPublicKeyInfo, mlkem512),
    DECODER_w_structure("x25519_mlkem512", der, PrivateKeyInfo, x25519_mlkem512),
    DECODER_w_structure("x25519_mlkem512", der, SubjectPublicKeyInfo, x25519_mlkem512),

    DECODER_w_structure("mlkem768",  der, PrivateKeyInfo,       mlkem768),
    DECODER_w_structure("mlkem768",  der, SubjectPublicKeyInfo, mlkem768),
    DECODER_w_structure("X25519MLKEM768", der, PrivateKeyInfo, X25519MLKEM768),
    DECODER_w_structure("X25519MLKEM768", der, SubjectPublicKeyInfo, X25519MLKEM768),

    DECODER_w_structure("mlkem1024", der, PrivateKeyInfo,       mlkem1024),
    DECODER_w_structure("mlkem1024", der, SubjectPublicKeyInfo, mlkem1024),

    DECODER_w_structure("mldsa44",   der, PrivateKeyInfo,       mldsa44),
    DECODER_w_structure("mldsa44",   der, SubjectPublicKeyInfo, mldsa44),
    DECODER_w_structure("mldsa65",   der, PrivateKeyInfo,       mldsa65),
    DECODER_w_structure("mldsa65",   der, SubjectPublicKeyInfo, mldsa65),
    DECODER_w_structure("mldsa87",   der, PrivateKeyInfo,       mldsa87),
    DECODER_w_structure("mldsa87",   der, SubjectPublicKeyInfo, mldsa87),

    { NULL, NULL, NULL }
};

/* ===========================================================
 * Provider → core params
 * ===========================================================
 */
static const OSSL_PARAM *kmprovider_gettable_params(void *provctx) {
    (void)provctx;
    return kmprovider_param_types;
}

static int kmprovider_get_params(void *provctx, OSSL_PARAM params[]) {
    (void)provctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL KM Provider")) return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    /* If you have a version macro, fill here:
       if (p && !OSSL_PARAM_set_utf8_ptr(p, KM_PROVIDER_VERSION_STR)) return 0; */

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    /* If you have build info macro, fill here:
       if (p && !OSSL_PARAM_set_utf8_ptr(p, KM_PROVIDER_BUILD_INFO_STR)) return 0; */

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p && !OSSL_PARAM_set_int(p, 1)) return 0; /* provider is running */

    return 1;
}

/* ===========================================================
 * Query (operation dispatch)
 * ===========================================================
 */
static const OSSL_ALGORITHM *kmprovider_query(void *provctx, int operation_id, int *no_cache) {
    (void)provctx;
    *no_cache = 0;

    switch (operation_id) {
        case OSSL_OP_SIGNATURE: return kmprovider_signatures;
        case OSSL_OP_KEM:       return kmprovider_asym_kems;
        case OSSL_OP_KEYMGMT:   return kmprovider_keymgmt;
        case OSSL_OP_ENCODER:   return kmprovider_encoder;
        case OSSL_OP_DECODER:   return kmprovider_decoder;
        default:
            KM_LOG("KM PROV: Unknown operation %d requested\n", operation_id);
            return NULL;
    }
}

/* ===========================================================
 * Teardown
 * ===========================================================
 */
static void kmprovider_teardown(void *provctx) {
    kmx_freeprovctx((PROV_KM_CTX *)provctx);
    OQS_destroy();
}

/* ===========================================================
 * Provider dispatch table
 * ===========================================================
 */
static const OSSL_DISPATCH kmprovider_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN,         (void (*)(void))kmprovider_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,  (void (*)(void))kmprovider_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,       (void (*)(void))kmprovider_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION,  (void (*)(void))kmprovider_query },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))km_provider_get_readiness },
    { 0, NULL }
};

#ifdef KM_PROVIDER_STATIC
#  define KM_PROVIDER_ENTRYPOINT_NAME km_provider_init
#else
#  define KM_PROVIDER_ENTRYPOINT_NAME OSSL_provider_init
#endif

/* ===========================================================
 * Provider entrypoint
 * ===========================================================
 */
int KM_PROVIDER_ENTRYPOINT_NAME(const OSSL_CORE_HANDLE *handle,
                                const OSSL_DISPATCH *in,
                                const OSSL_DISPATCH **out,
                                void **provctx) {
    const OSSL_DISPATCH *orig_in = in;
    OSSL_FUNC_core_obj_create_fn    *c_obj_create    = NULL;
    OSSL_FUNC_core_obj_add_sigid_fn *c_obj_add_sigid = NULL;
    BIO_METHOD *corebiometh = NULL;
    OSSL_LIB_CTX *libctx = NULL;

    int ok = 0;
    char *opensslv = NULL;
    const char *ossl_versionp = NULL;
    OSSL_PARAM version_request[] = {
        { "openssl-version", OSSL_PARAM_UTF8_PTR, &opensslv, sizeof(&opensslv), 0 },
        { NULL, 0, NULL, 0, 0 }
    };

    OQS_init();

    if (!km_prov_bio_from_dispatch(in)) goto end;

    if (!km_patch_codepoints()) goto end;
    if (!km_patch_oids())       goto end;

    /* Ambil fungsi inti dari core */
    for (; in->function_id != 0; ++in) {
        switch (in->function_id) {
            case OSSL_FUNC_CORE_GETTABLE_PARAMS: c_gettable_params = OSSL_FUNC_core_gettable_params(in); break;
            case OSSL_FUNC_CORE_GET_PARAMS:      c_get_params      = OSSL_FUNC_core_get_params(in);      break;
            case OSSL_FUNC_CORE_OBJ_CREATE:      c_obj_create      = OSSL_FUNC_core_obj_create(in);      break;
            case OSSL_FUNC_CORE_OBJ_ADD_SIGID:   c_obj_add_sigid   = OSSL_FUNC_core_obj_add_sigid(in);   break;
            default: break; /* ignore unknown */
        }
    }

    if (!c_obj_create || !c_obj_add_sigid || !c_get_params) goto end;

    if (c_get_params(handle, version_request)) {
        ossl_versionp = *(void **)version_request[0].data;
    }

    /* Registrasi semua OID → NID */
    for (int i = 0; i < KM_OID_CNT; i += 2) {
        const char *oid  = km_oid_alg_list[i];
        const char *name = km_oid_alg_list[i+1];

        if (!oid) {
            if (name) KM_LOG("KM PROV: Warning: No OID registered for %s\n", name);
            continue;
        }
        if (!name) continue;

        if (!c_obj_create(handle, oid, name, name)) {
            ERR_raise(ERR_LIB_USER, KMPROV_R_OBJ_CREATE_ERR);
            fprintf(stderr, "KM PROV: error registering NID for %s\n", name);
            goto end;
        }

        /* Workaround: ulangi OBJ_create di luar core untuk beberapa versi */
        if (ossl_versionp && strcmp("3.1.0", ossl_versionp) != 0) {
            ERR_set_mark();
            OBJ_create(oid, name, name);
            ERR_pop_to_mark();
        }

        if (!km_set_nid((char*)name, OBJ_sn2nid(name))) {
            ERR_raise(ERR_LIB_USER, KMPROV_R_OBJ_CREATE_ERR);
            goto end;
        }

        if (!c_obj_add_sigid(handle, name, "", name)) {
            fprintf(stderr, "KM PROV: error registering %s with no hash\n", name);
            ERR_raise(ERR_LIB_USER, KMPROV_R_OBJ_CREATE_ERR);
            goto end;
        }

        int nid = OBJ_sn2nid(name);
        if (nid != 0) {
            KM_LOG("KM PROV: registered %s with NID %d\n", name, nid);
        } else {
            fprintf(stderr, "KM PROV: Impossible error: NID unregistered for %s\n", name);
            ERR_raise(ERR_LIB_USER, KMPROV_R_OBJ_CREATE_ERR);
            goto end;
        }
    }

    /* Context init */
    if ( ((corebiometh = km_bio_prov_init_bio_method()) == NULL) ||
         ((libctx     = OSSL_LIB_CTX_new_child(handle, orig_in)) == NULL) ||
         ((*provctx   = kmx_newprovctx(libctx, handle, corebiometh)) == NULL) ) {
        KM_LOG("KM PROV: error creating provider context\n");
        ERR_raise(ERR_LIB_USER, KMPROV_R_LIB_CREATE_ERR);
        goto end;
    }

    *out = kmprovider_dispatch_table;

    /* Periksa ketersediaan default/FIPS */
    if (!OSSL_PROVIDER_available(libctx, "default") &&
        !OSSL_PROVIDER_available(libctx, "fips")) {
        KM_LOG("KM PROV: Default and FIPS provider not available. Errors may result.\n");
    } else {
        KM_LOG("KM PROV: Default or FIPS provider available.\n");
    }

    ok = 1;

end:
    if (!ok) {
        if (ossl_versionp) KM_LOG("kmprovider init failed for OpenSSL core version %s\n", ossl_versionp);
        else               KM_LOG("kmprovider init failed for OpenSSL\n");
        if (libctx) OSSL_LIB_CTX_free(libctx);
        if (provctx && *provctx) {
            kmprovider_teardown(*provctx);
            *provctx = NULL;
        }
    }
    return ok;
}
