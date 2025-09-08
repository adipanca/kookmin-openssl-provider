// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * KM OpenSSL 3 provider
 *
 * Code strongly inspired by OpenSSL legacy provider.
 *
 */

#include <errno.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

#include "provider.h"

#ifdef NDEBUG
#define KM_PROV_PRINTF(a)
#define KM_PROV_PRINTF2(a, b)
#define KM_PROV_PRINTF3(a, b, c)
#else
#define KM_PROV_PRINTF(a)                                                     \
    if (getenv("KMPROV"))                                                     \
    printf(a)
#define KM_PROV_PRINTF2(a, b)                                                 \
    if (getenv("KMPROV"))                                                     \
    printf(a, b)
#define KM_PROV_PRINTF3(a, b, c)                                              \
    if (getenv("KMPROV"))                                                     \
    printf(a, b, c)
#endif // NDEBUG

/*
 * Forward declarations to ensure that interface functions are correctly
 * defined.
 */
static OSSL_FUNC_provider_gettable_params_fn kmprovider_gettable_params;
static OSSL_FUNC_provider_get_params_fn kmprovider_get_params;
static OSSL_FUNC_provider_query_operation_fn kmprovider_query;
extern OSSL_FUNC_provider_get_capabilities_fn km_provider_get_capabilities;

/*
 * List of all algorithms with given OIDs
 */
///// KM_TEMPLATE_FRAGMENT_ASSIGN_SIG_OIDS_START

#ifdef KM_KEM_ENCODERS
#define KM_OID_CNT 220
#else
#define KM_OID_CNT 114
#endif
const char *km_oid_alg_list[KM_OID_CNT] = {

#ifdef KM_KEM_ENCODERS
    "1.3.6.1.4.1.2.267.8.2.2",
    "kyber512",
    "1.3.6.1.4.1.2.267.8.3.3",
    "kyber768",
    "1.3.6.1.4.1.2.267.8.4.4",
    "kyber1024",
    "2.16.840.1.101.3.4.4.1",
    "mlkem512",
    "2.16.840.1.101.3.4.4.2",
    "mlkem768",
    "2.16.840.1.101.3.4.4.3",
    "mlkem1024",

#endif /* KM_KEM_ENCODERS */

    "1.3.6.1.4.1.2.267.7.4.4",
    "dilithium2",
    "1.3.6.1.4.1.2.267.7.6.5",
    "dilithium3",
    "1.3.6.1.4.1.2.267.7.8.7",
    "dilithium5",
    "1.3.6.1.4.1.2.267.12.4.4",
    "mldsa44",
    "1.3.6.1.4.1.2.267.12.6.5",
    "mldsa65",
    "1.3.6.1.4.1.2.267.12.8.7",
    "mldsa87",
    "1.3.9999.6.4.13",
    "sphincssha2128fsimple",
    "1.3.9999.6.4.16",
    "sphincssha2128ssimple",
    "1.3.9999.6.5.10",
    "sphincssha2192fsimple",
    "1.3.9999.6.7.13",
    "sphincsshake128fsimple",
    ///// KM_TEMPLATE_FRAGMENT_ASSIGN_SIG_OIDS_END
};

int km_patch_oids(void) {
    ///// KM_TEMPLATE_FRAGMENT_OID_PATCHING_START
    {
        const char *envval = NULL;

#ifdef KM_KEM_ENCODERS

        if ((envval = getenv("KM_OID_KYBER512")))
            km_oid_alg_list[0] = envval;
        if ((envval = getenv("KM_OID_KYBER768")))
            km_oid_alg_list[2] = envval;
        if ((envval = getenv("KM_OID_KYBER1024")))
            km_oid_alg_list[4] = envval;

        if ((envval = getenv("KM_OID_MLKEM512")))
            km_oid_alg_list[6] = envval;
        if ((envval = getenv("KM_OID_MLKEM768")))
            km_oid_alg_list[8] = envval;
        if ((envval = getenv("KM_OID_MLKEM1024")))
            km_oid_alg_list[10] = envval;


#define KM_KEMOID_CNT 10 + 2
#else
#define KM_KEMOID_CNT 0
#endif /* KM_KEM_ENCODERS */
        if ((envval = getenv("KM_OID_DILITHIUM2")))
            km_oid_alg_list[0 + KM_KEMOID_CNT] = envval;
        if ((envval = getenv("KM_OID_DILITHIUM3")))
            km_oid_alg_list[2 + KM_KEMOID_CNT] = envval;
        if ((envval = getenv("KM_OID_DILITHIUM5")))
            km_oid_alg_list[4 + KM_KEMOID_CNT] = envval;
        if ((envval = getenv("KM_OID_MLDSA44")))
            km_oid_alg_list[6 + KM_KEMOID_CNT] = envval;
        if ((envval = getenv("KM_OID_MLDSA65")))
            km_oid_alg_list[8 + KM_KEMOID_CNT] = envval;
        if ((envval = getenv("KM_OID_MLDSA87")))
            km_oid_alg_list[10 + KM_KEMOID_CNT] = envval;

        if ((envval = getenv("KM_OID_SPHINCSSHA2128FSIMPLE")))
            km_oid_alg_list[12 + KM_KEMOID_CNT] = envval;
        if ((envval = getenv("KM_OID_SPHINCSSHA2128SSIMPLE")))
            km_oid_alg_list[14 + KM_KEMOID_CNT] = envval;
        if ((envval = getenv("KM_OID_SPHINCSSHA2192FSIMPLE")))
            km_oid_alg_list[16 + KM_KEMOID_CNT] = envval;            
        if ((envval = getenv("KM_OID_SPHINCSSHAKE128FSIMPLE")))
            km_oid_alg_list[18 + KM_KEMOID_CNT] = envval;
    } ///// KM_TEMPLATE_FRAGMENT_OID_PATCHING_END
    return 1;
}

#define SIGALG(NAMES, SECBITS, FUNC)                                           \
    {                                                                          \
        NAMES, "provider=kookminlib,kookminlib.security_bits=" #SECBITS "",  \
            FUNC                                                               \
    }
#define KEMBASEALG(NAMES, SECBITS)                                             \
    {"" #NAMES "",                                                             \
     "provider=kookminlib,kookminlib.security_bits=" #SECBITS "",            \
     km_generic_kem_functions},

#define KEMHYBALG(NAMES, SECBITS)                                              \
    {"" #NAMES "",                                                             \
     "provider=kookminlib,kookminlib.security_bits=" #SECBITS "",            \
     km_hybrid_kem_functions},

#define KEMKMALG(NAMES, SECBITS)                                               \
    {"" #NAMES "",                                                             \
     "provider=kookminlib,kookminlib.security_bits=" #SECBITS "",            \
     km_##NAMES##_keymgmt_functions},

#define KEMKMHYBALG(NAMES, SECBITS, HYBTYPE)                                   \
    {"" #NAMES "",                                                             \
     "provider=kookminlib,kookminlib.security_bits=" #SECBITS "",            \
     km_##HYBTYPE##_##NAMES##_keymgmt_functions},

/* Functions provided by the core */
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

/* Parameters we provide to the core */
static const OSSL_PARAM kmprovider_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_ALGORITHM kmprovider_signatures[] = {
///// KM_TEMPLATE_FRAGMENT_SIG_FUNCTIONS_START
    SIGALG("dilithium2", 128, km_signature_functions),
    SIGALG("dilithium3", 192, km_signature_functions),
    SIGALG("dilithium5", 256, km_signature_functions),
    SIGALG("mldsa44", 128, km_signature_functions),
    SIGALG("mldsa65", 192, km_signature_functions),
    SIGALG("mldsa87", 256, km_signature_functions),
    SIGALG("sphincssha2128fsimple", 128, km_signature_functions),
    SIGALG("sphincssha2128ssimple", 128, km_signature_functions),
    SIGALG("sphincssha2192fsimple", 192, km_signature_functions),
    SIGALG("sphincsshake128fsimple", 128, km_signature_functions),

    ///// KM_TEMPLATE_FRAGMENT_SIG_FUNCTIONS_END
    {NULL, NULL, NULL}};

static const OSSL_ALGORITHM kmprovider_asym_kems[] = {
///// KM_TEMPLATE_FRAGMENT_KEM_FUNCTIONS_START
// clang-format off
    KEMBASEALG(kyber512, 128)
    KEMBASEALG(kyber768, 192)
    KEMBASEALG(kyber1024, 256)
    KEMBASEALG(mlkem512, 128)
    KEMBASEALG(mlkem768, 192)
    KEMBASEALG(mlkem1024, 256)
    // clang-format on
    ///// KM_TEMPLATE_FRAGMENT_KEM_FUNCTIONS_END
    {NULL, NULL, NULL}};

static const OSSL_ALGORITHM kmprovider_keymgmt[] = {
///// KM_TEMPLATE_FRAGMENT_KEYMGMT_FUNCTIONS_START
// clang-format off

    SIGALG("dilithium2", 128, km_dilithium2_keymgmt_functions),
    SIGALG("dilithium3", 192, km_dilithium3_keymgmt_functions),
    SIGALG("dilithium5", 256, km_dilithium5_keymgmt_functions),
    SIGALG("mldsa44", 128, km_mldsa44_keymgmt_functions),
    SIGALG("mldsa65", 192, km_mldsa65_keymgmt_functions),
    SIGALG("mldsa87", 256, km_mldsa87_keymgmt_functions),
    SIGALG("sphincssha2128fsimple", 128, km_sphincssha2128fsimple_keymgmt_functions),
    SIGALG("sphincssha2128ssimple", 128, km_sphincssha2128ssimple_keymgmt_functions),
    SIGALG("sphincssha2192fsimple", 192, km_sphincssha2192fsimple_keymgmt_functions),
    SIGALG("sphincsshake128fsimple", 128, km_sphincsshake128fsimple_keymgmt_functions),
    KEMKMALG(kyber512, 128)
    KEMKMALG(kyber768, 192)
    KEMKMALG(kyber1024, 256)
    KEMKMALG(mlkem512, 128)
    KEMKMALG(mlkem768, 192)
    KEMKMALG(mlkem1024, 256)
    // clang-format on
    ///// KM_TEMPLATE_FRAGMENT_KEYMGMT_FUNCTIONS_END
    {NULL, NULL, NULL}};

static const OSSL_ALGORITHM kmprovider_encoder[] = {
#define ENCODER_PROVIDER "kookminlib"
#ifndef ENCODER_PROVIDER
#    error Macro ENCODER_PROVIDER undefined
#endif

#define ENCODER_STRUCTURE_type_specific_keypair   "type-specific"
#define ENCODER_STRUCTURE_type_specific_params    "type-specific"
#define ENCODER_STRUCTURE_type_specific           "type-specific"
#define ENCODER_STRUCTURE_type_specific_no_pub    "type-specific"
#define ENCODER_STRUCTURE_PKCS8                   "pkcs8"
#define ENCODER_STRUCTURE_SubjectPublicKeyInfo    "SubjectPublicKeyInfo"
#define ENCODER_STRUCTURE_PrivateKeyInfo          "PrivateKeyInfo"
#define ENCODER_STRUCTURE_EncryptedPrivateKeyInfo "EncryptedPrivateKeyInfo"
#define ENCODER_STRUCTURE_PKCS1                   "pkcs1"
#define ENCODER_STRUCTURE_PKCS3                   "pkcs3"

/* Arguments are prefixed with '_' to avoid build breaks on certain platforms */
#define ENCODER_TEXT(_name, _sym)                           \
    {                                                       \
        _name, "provider=" ENCODER_PROVIDER ",output=text", \
            (km_##_sym##_to_text_encoder_functions)        \
    }
#define ENCODER(_name, _sym, _fips, _output)                     \
    {                                                            \
        _name, "provider=" ENCODER_PROVIDER ",output=" #_output, \
            (km_##_sym##_to_##_output##_encoder_functions)      \
    }

#define ENCODER_w_structure(_name, _sym, _output, _structure)              \
    {                                                                      \
        _name,                                                             \
            "provider=" ENCODER_PROVIDER ",output=" #_output               \
            ",structure=" ENCODER_STRUCTURE_##_structure,                  \
            (km_##_sym##_to_##_structure##_##_output##_encoder_functions) \
    }

///// KM_TEMPLATE_FRAGMENT_MAKE_START
#ifdef KM_KEM_ENCODERS
ENCODER_w_structure("mlkem512", mlkem512, der, PrivateKeyInfo),
ENCODER_w_structure("mlkem512", mlkem512, pem, PrivateKeyInfo),
ENCODER_w_structure("mlkem512", mlkem512, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("mlkem512", mlkem512, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("mlkem512", mlkem512, der, SubjectPublicKeyInfo),
ENCODER_w_structure("mlkem512", mlkem512, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("mlkem512", mlkem512),

ENCODER_w_structure("mlkem768", mlkem768, der, PrivateKeyInfo),
ENCODER_w_structure("mlkem768", mlkem768, pem, PrivateKeyInfo),
ENCODER_w_structure("mlkem768", mlkem768, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("mlkem768", mlkem768, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("mlkem768", mlkem768, der, SubjectPublicKeyInfo),
ENCODER_w_structure("mlkem768", mlkem768, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("mlkem768", mlkem768),

ENCODER_w_structure("mlkem1024", mlkem1024, der, PrivateKeyInfo),
ENCODER_w_structure("mlkem1024", mlkem1024, pem, PrivateKeyInfo),
ENCODER_w_structure("mlkem1024", mlkem1024, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("mlkem1024", mlkem1024, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("mlkem1024", mlkem1024, der, SubjectPublicKeyInfo),
ENCODER_w_structure("mlkem1024", mlkem1024, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("mlkem1024", mlkem1024),
#endif /* KM_KEM_ENCODERS */

ENCODER_w_structure("mldsa44", mldsa44, der, PrivateKeyInfo),
ENCODER_w_structure("mldsa44", mldsa44, pem, PrivateKeyInfo),
ENCODER_w_structure("mldsa44", mldsa44, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("mldsa44", mldsa44, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("mldsa44", mldsa44, der, SubjectPublicKeyInfo),
ENCODER_w_structure("mldsa44", mldsa44, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("mldsa44", mldsa44),

ENCODER_w_structure("mldsa65", mldsa65, der, PrivateKeyInfo),
ENCODER_w_structure("mldsa65", mldsa65, pem, PrivateKeyInfo),
ENCODER_w_structure("mldsa65", mldsa65, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("mldsa65", mldsa65, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("mldsa65", mldsa65, der, SubjectPublicKeyInfo),
ENCODER_w_structure("mldsa65", mldsa65, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("mldsa65", mldsa65),

ENCODER_w_structure("mldsa87", mldsa87, der, PrivateKeyInfo),
ENCODER_w_structure("mldsa87", mldsa87, pem, PrivateKeyInfo),
ENCODER_w_structure("mldsa87", mldsa87, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("mldsa87", mldsa87, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("mldsa87", mldsa87, der, SubjectPublicKeyInfo),
ENCODER_w_structure("mldsa87", mldsa87, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("mldsa87", mldsa87),
    {NULL, NULL, NULL}
#undef ENCODER_PROVIDER
};

static const OSSL_ALGORITHM kmprovider_decoder[] = {
#define DECODER_PROVIDER "kookminlib"
#ifndef DECODER_PROVIDER
#    error Macro DECODER_PROVIDER undefined
#endif

#define DECODER_STRUCTURE_type_specific_keypair "type-specific"
#define DECODER_STRUCTURE_type_specific_params  "type-specific"
#define DECODER_STRUCTURE_type_specific         "type-specific"
#define DECODER_STRUCTURE_type_specific_no_pub  "type-specific"
#define DECODER_STRUCTURE_PKCS8                 "pkcs8"
#define DECODER_STRUCTURE_SubjectPublicKeyInfo  "SubjectPublicKeyInfo"
#define DECODER_STRUCTURE_PrivateKeyInfo        "PrivateKeyInfo"

/* Arguments are prefixed with '_' to avoid build breaks on certain platforms */
#define DECODER(_name, _input, _output)                        \
    {                                                          \
        _name, "provider=" DECODER_PROVIDER ",input=" #_input, \
            (km_##_input##_to_##_output##_decoder_functions)  \
    }
#define DECODER_w_structure(_name, _input, _structure, _output)              \
    {                                                                        \
        _name,                                                               \
            "provider=" DECODER_PROVIDER ",input=" #_input                   \
            ",structure=" DECODER_STRUCTURE_##_structure,                    \
            (km_##_structure##_##_input##_to_##_output##_decoder_functions) \
    }

///// KM_TEMPLATE_FRAGMENT_MAKE_START
#ifdef KM_KEM_ENCODERS

DECODER_w_structure("mlkem512", der, PrivateKeyInfo, mlkem512),
DECODER_w_structure("mlkem512", der, SubjectPublicKeyInfo, mlkem512),
DECODER_w_structure("mlkem768", der, PrivateKeyInfo, mlkem768),
DECODER_w_structure("mlkem768", der, SubjectPublicKeyInfo, mlkem768),
DECODER_w_structure("mlkem1024", der, PrivateKeyInfo, mlkem1024),
DECODER_w_structure("mlkem1024", der, SubjectPublicKeyInfo, mlkem1024),

#endif /* KM_KEM_ENCODERS */

DECODER_w_structure("mldsa44", der, PrivateKeyInfo, mldsa44),
DECODER_w_structure("mldsa44", der, SubjectPublicKeyInfo, mldsa44),
DECODER_w_structure("mldsa65", der, PrivateKeyInfo, mldsa65),
DECODER_w_structure("mldsa65", der, SubjectPublicKeyInfo, mldsa65),
DECODER_w_structure("mldsa87", der, PrivateKeyInfo, mldsa87),
DECODER_w_structure("mldsa87", der, SubjectPublicKeyInfo, mldsa87),

///// KM_TEMPLATE_FRAGMENT_MAKE_END
    {NULL, NULL, NULL}
#undef DECODER_PROVIDER
};

// get the last number on the composite OID
int get_composite_idx(int idx) {
    char *s;
    int i, len, ret = -1, count = 0;

    if (2 * idx > KM_OID_CNT)
        return 0;
    s = (char *)km_oid_alg_list[idx * 2];
    len = strlen(s);

    for (i = 0; i < len; i++) {
        if (s[i] == '.') {
            count += 1;
        }
        if (count == 8) { // 8 dots in composite OID
            errno = 0;
            ret = strtol(s + i + 1, NULL, 10);
            if (errno == ERANGE)
                ret = -1;
            break;
        }
    }
    return ret;
}

static const OSSL_PARAM *kmprovider_gettable_params(void *provctx) {
    return kmprovider_param_types;
}

// #define KM_PROVIDER_BASE_BUILD_INFO_STR                                       \
//     "KM Provider v." KM_PROVIDER_VERSION_STR KM_PROVIDER_COMMIT             \
//     " based on liboqs v." KM_VERSION_TEXT

// #ifdef QSC_ENCODING_VERSION_STRING
// #define KM_PROVIDER_BUILD_INFO_STR                                            \
//     KM_PROVIDER_BASE_BUILD_INFO_STR                                           \
//     " using qsc-key-encoder v." QSC_ENCODING_VERSION_STRING
// #else
// #define KM_PROVIDER_BUILD_INFO_STR KM_PROVIDER_BASE_BUILD_INFO_STR
// #endif

static int kmprovider_get_params(void *provctx, OSSL_PARAM params[]) {
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL KM Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    // if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, KM_PROVIDER_VERSION_STR))
    //     return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    // if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, KM_PROVIDER_BUILD_INFO_STR))
    //     return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1)) // provider is always running
        return 0;
    // not passing in params to respond to is no error; response is empty then
    return 1;
}

static const OSSL_ALGORITHM *kmprovider_query(void *provctx, int operation_id,
                                               int *no_cache) {
    *no_cache = 0;

    switch (operation_id) {
    case OSSL_OP_SIGNATURE:
        return kmprovider_signatures;
    case OSSL_OP_KEM:
        return kmprovider_asym_kems;
    case OSSL_OP_KEYMGMT:
        return kmprovider_keymgmt;
    case OSSL_OP_ENCODER:
        return kmprovider_encoder;
    case OSSL_OP_DECODER:
        return kmprovider_decoder;
    default:
        if (getenv("KMPROV"))
            printf("Unknown operation %d requested from KM provider\n",
                   operation_id);
    }
    return NULL;
}

static void kmprovider_teardown(void *provctx) {
    kmx_freeprovctx((PROV_KM_CTX *)provctx);
    OQS_destroy();
}

/* Functions we provide to the core */
static const OSSL_DISPATCH kmprovider_dispatch_table[] = {
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))kmprovider_teardown},
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
     (void (*)(void))kmprovider_gettable_params},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))kmprovider_get_params},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))kmprovider_query},
    {OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
     (void (*)(void))km_provider_get_capabilities},
    {0, NULL}};

#ifdef KM_PROVIDER_STATIC
#define KM_PROVIDER_ENTRYPOINT_NAME km_provider_init
#else
#define KM_PROVIDER_ENTRYPOINT_NAME OSSL_provider_init
#endif // ifdef KM_PROVIDER_STATIC

int KM_PROVIDER_ENTRYPOINT_NAME(const OSSL_CORE_HANDLE *handle,
                                 const OSSL_DISPATCH *in,
                                 const OSSL_DISPATCH **out, void **provctx) {
    const OSSL_DISPATCH *orig_in = in;
    OSSL_FUNC_core_obj_create_fn *c_obj_create = NULL;

    OSSL_FUNC_core_obj_add_sigid_fn *c_obj_add_sigid = NULL;
    BIO_METHOD *corebiometh;
    OSSL_LIB_CTX *libctx = NULL;
    int i, rc = 0;
    char *opensslv;
    const char *ossl_versionp = NULL;
    OSSL_PARAM version_request[] = {{"openssl-version", OSSL_PARAM_UTF8_PTR,
                                     &opensslv, sizeof(&opensslv), 0},
                                    {NULL, 0, NULL, 0, 0}};

    OQS_init();

    if (!km_prov_bio_from_dispatch(in))
        goto end_init;

    if (!km_patch_codepoints())
        goto end_init;

    if (!km_patch_oids())
        goto end_init;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = OSSL_FUNC_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_OBJ_CREATE:
            c_obj_create = OSSL_FUNC_core_obj_create(in);
            break;
        case OSSL_FUNC_CORE_OBJ_ADD_SIGID:
            c_obj_add_sigid = OSSL_FUNC_core_obj_add_sigid(in);
            break;
        /* Just ignore anything we don't understand */
        default:
            break;
        }
    }

    // we need these functions:
    if (c_obj_create == NULL || c_obj_add_sigid == NULL || c_get_params == NULL)
        goto end_init;

    // we need to know the version of the calling core to activate
    // suitable bug workarounds
    if (c_get_params(handle, version_request)) {
        ossl_versionp = *(void **)version_request[0].data;
    }

    // insert all OIDs to the global objects list
    for (i = 0; i < KM_OID_CNT; i += 2) {
        if (km_oid_alg_list[i] == NULL) {
            KM_PROV_PRINTF2("KM PROV: Warning: No OID registered for %s\n",
                             km_oid_alg_list[i + 1]);
        } else {
            if (!c_obj_create(handle, km_oid_alg_list[i],
                              km_oid_alg_list[i + 1],
                              km_oid_alg_list[i + 1])) {
                ERR_raise(ERR_LIB_USER, KMPROV_R_OBJ_CREATE_ERR);
                fprintf(stderr, "error registering NID for %s\n",
                        km_oid_alg_list[i + 1]);
                goto end_init;
            }

            /* create object (NID) again to avoid setup corner case problems
             * see https://github.com/openssl/openssl/discussions/21903
             * Not testing for errors is intentional.
             * At least one core version hangs up; so don't do this there:
             */
            if (strcmp("3.1.0", ossl_versionp)) {
                ERR_set_mark();
                OBJ_create(km_oid_alg_list[i], km_oid_alg_list[i + 1],
                           km_oid_alg_list[i + 1]);
                ERR_pop_to_mark();
            }

            if (!km_set_nid((char *)km_oid_alg_list[i + 1],
                             OBJ_sn2nid(km_oid_alg_list[i + 1]))) {
                ERR_raise(ERR_LIB_USER, KMPROV_R_OBJ_CREATE_ERR);
                goto end_init;
            }

            if (!c_obj_add_sigid(handle, km_oid_alg_list[i + 1], "",
                                 km_oid_alg_list[i + 1])) {
                fprintf(stderr, "error registering %s with no hash\n",
                        km_oid_alg_list[i + 1]);
                ERR_raise(ERR_LIB_USER, KMPROV_R_OBJ_CREATE_ERR);
                goto end_init;
            }

            if (OBJ_sn2nid(km_oid_alg_list[i + 1]) != 0) {
                KM_PROV_PRINTF3(
                    "KM PROV: successfully registered %s with NID %d\n",
                    km_oid_alg_list[i + 1],
                    OBJ_sn2nid(km_oid_alg_list[i + 1]));
            } else {
                fprintf(stderr,
                        "KM PROV: Impossible error: NID unregistered "
                        "for %s.\n",
                        km_oid_alg_list[i + 1]);
                ERR_raise(ERR_LIB_USER, KMPROV_R_OBJ_CREATE_ERR);
                goto end_init;
            }
        }
    }

    // if libctx not yet existing, create a new one
    if (((corebiometh = km_bio_prov_init_bio_method()) == NULL) ||
        ((libctx = OSSL_LIB_CTX_new_child(handle, orig_in)) == NULL) ||
        ((*provctx = kmx_newprovctx(libctx, handle, corebiometh)) == NULL)) {
        KM_PROV_PRINTF("KM PROV: error creating new provider context\n");
        ERR_raise(ERR_LIB_USER, KMPROV_R_LIB_CREATE_ERR);
        goto end_init;
    }

    *out = kmprovider_dispatch_table;

    // finally, warn if neither default nor fips provider are present:
    if (!OSSL_PROVIDER_available(libctx, "default") &&
        !OSSL_PROVIDER_available(libctx, "fips")) {
        KM_PROV_PRINTF(
            "KM PROV: Default and FIPS provider not available. Errors "
            "may result.\n");
    } else {
        KM_PROV_PRINTF("KM PROV: Default or FIPS provider available.\n");
    }
    rc = 1;

end_init:
    if (!rc) {
        if (ossl_versionp) {
            KM_PROV_PRINTF2(
                "kmprovider init failed for OpenSSL core version %s\n",
                ossl_versionp);
        } else
            KM_PROV_PRINTF("kmprovider init failed for OpenSSL\n");
        if (libctx)
            OSSL_LIB_CTX_free(libctx);
        if (provctx && *provctx) {
            kmprovider_teardown(*provctx);
            *provctx = NULL;
        }
    }
    return rc;
}
