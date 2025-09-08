// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * KM OpenSSL 3 provider
 *
 * Code strongly inspired by OpenSSL common provider capabilities.
 *
 * ToDo: Interop testing.
 */

#include <assert.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <string.h>

/* For TLS1_VERSION etc */
#include <openssl/params.h>
#include <openssl/ssl.h>

// internal, but useful OSSL define:
#define OSSL_NELEM(x) (sizeof(x) / sizeof((x)[0]))

#include "provider.h"

typedef struct km_group_constants_st {
    unsigned int group_id; /* Group ID */
    unsigned int secbits;  /* Bits of security */
    int mintls;            /* Minimum TLS version, -1 unsupported */
    int maxtls;            /* Maximum TLS version (or 0 for undefined) */
    int mindtls;           /* Minimum DTLS version, -1 unsupported */
    int maxdtls;           /* Maximum DTLS version (or 0 for undefined) */
    int is_kem;            /* Always set */
} KM_GROUP_CONSTANTS;

static KM_GROUP_CONSTANTS km_group_list[] = {
    // ad-hoc assignments - take from KM generate data structures
    ///// KM_TEMPLATE_FRAGMENT_GROUP_ASSIGNMENTS_START
    {0x0200, 128, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F00, 128, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x2F80, 128, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x0201, 128, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F01, 128, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x2F81, 128, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x0202, 192, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F02, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x2F82, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x0203, 192, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F03, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x2F83, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x0204, 256, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F04, 256, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x0205, 256, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F05, 256, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x023A, 128, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F3A, 128, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x2F39, 128, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x023C, 192, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F3C, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x2F90, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x6399, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x639A, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x023D, 256, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F3D, 256, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x024A, 128, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F4B, 128, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x2FB6, 128, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x0768, 192, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F4C, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x2FB7, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x11ec, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x11eb, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x1024, 256, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F4D, 256, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x2F4E, 256, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x0241, 128, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F41, 128, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x2FAE, 128, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x0242, 192, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F42, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x2FAF, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x0243, 256, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F43, 256, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x0244, 128, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F44, 128, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x2FB0, 128, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x0245, 192, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F45, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x2FB1, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x0246, 256, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F46, 256, TLS1_3_VERSION, 0, -1, -1, 1},
    ///// KM_TEMPLATE_FRAGMENT_GROUP_ASSIGNMENTS_END
};

// Adds entries for tlsname, `ecx`_tlsname and `ecp`_tlsname
#define KM_GROUP_ENTRY(tlsname, realname, algorithm, idx)                     \
    {                                                                          \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME, #tlsname,       \
                               sizeof(#tlsname)),                              \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL,    \
                                   #realname, sizeof(#realname)),              \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG, #algorithm,  \
                                   sizeof(#algorithm)),                        \
            OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID,                      \
                            (unsigned int *)&km_group_list[idx].group_id),    \
            OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS,           \
                            (unsigned int *)&km_group_list[idx].secbits),     \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS,                  \
                           (unsigned int *)&km_group_list[idx].mintls),       \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS,                  \
                           (unsigned int *)&km_group_list[idx].maxtls),       \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS,                 \
                           (unsigned int *)&km_group_list[idx].mindtls),      \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS,                 \
                           (unsigned int *)&km_group_list[idx].maxdtls),      \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_IS_KEM,                   \
                           (unsigned int *)&km_group_list[idx].is_kem),       \
            OSSL_PARAM_END                                                     \
    }

static const OSSL_PARAM km_param_group_list[][11] = {
///// KM_TEMPLATE_FRAGMENT_GROUP_NAMES_START
    KM_GROUP_ENTRY(kyber512, kyber512, kyber512, 16),
    KM_GROUP_ENTRY(kyber768, kyber768, kyber768, 19),
    KM_GROUP_ENTRY(kyber1024, kyber1024, kyber1024, 24),
    KM_GROUP_ENTRY(mlkem512, mlkem512, mlkem512, 26),
    KM_GROUP_ENTRY(mlkem768, mlkem768, mlkem768, 29),
    KM_GROUP_ENTRY(mlkem1024, mlkem1024, mlkem1024, 34),
    ///// KM_TEMPLATE_FRAGMENT_GROUP_NAMES_END
};

typedef struct km_sigalg_constants_st {
    unsigned int code_point; /* Code point */
    unsigned int secbits;    /* Bits of security */
    int mintls;              /* Minimum TLS version, -1 unsupported */
    int maxtls;              /* Maximum TLS version (or 0 for undefined) */
} KM_SIGALG_CONSTANTS;

static KM_SIGALG_CONSTANTS km_sigalg_list[] = {
    // ad-hoc assignments - take from KM generate data structures
    ///// KM_TEMPLATE_FRAGMENT_SIGALG_ASSIGNMENTS_START
    {0xfea0, 128, TLS1_3_VERSION, 0}, {0xfea1, 128, TLS1_3_VERSION, 0},
    {0xfea2, 128, TLS1_3_VERSION, 0}, {0xfea3, 192, TLS1_3_VERSION, 0},
    {0xfea4, 192, TLS1_3_VERSION, 0}, {0xfea5, 256, TLS1_3_VERSION, 0},
    {0xfea6, 256, TLS1_3_VERSION, 0}, {0xfed0, 128, TLS1_3_VERSION, 0},
    {0xfed3, 128, TLS1_3_VERSION, 0}, {0xfed4, 128, TLS1_3_VERSION, 0},
    {0xfee1, 128, TLS1_3_VERSION, 0}, {0xfee2, 128, TLS1_3_VERSION, 0},
    {0xfee3, 128, TLS1_3_VERSION, 0}, {0xfee4, 128, TLS1_3_VERSION, 0},
    {0xfee5, 128, TLS1_3_VERSION, 0}, {0xfed1, 192, TLS1_3_VERSION, 0},
    {0xfed5, 192, TLS1_3_VERSION, 0}, {0xfee6, 192, TLS1_3_VERSION, 0},
    {0xfee7, 192, TLS1_3_VERSION, 0}, {0xfee8, 192, TLS1_3_VERSION, 0},
    {0xfee9, 192, TLS1_3_VERSION, 0}, {0xfeea, 192, TLS1_3_VERSION, 0},
    {0xfed2, 256, TLS1_3_VERSION, 0}, {0xfed6, 256, TLS1_3_VERSION, 0},
    {0xfeeb, 256, TLS1_3_VERSION, 0}, {0xfeec, 256, TLS1_3_VERSION, 0},
    {0xfeed, 256, TLS1_3_VERSION, 0}, {0xfed7, 128, TLS1_3_VERSION, 0},
    {0xfed8, 128, TLS1_3_VERSION, 0}, {0xfed9, 128, TLS1_3_VERSION, 0},
    {0xfedc, 128, TLS1_3_VERSION, 0}, {0xfedd, 128, TLS1_3_VERSION, 0},
    {0xfede, 128, TLS1_3_VERSION, 0}, {0xfeda, 256, TLS1_3_VERSION, 0},
    {0xfedb, 256, TLS1_3_VERSION, 0}, {0xfedf, 256, TLS1_3_VERSION, 0},
    {0xfee0, 256, TLS1_3_VERSION, 0}, {0xfeb3, 128, TLS1_3_VERSION, 0},
    {0xfeb4, 128, TLS1_3_VERSION, 0}, {0xfeb5, 128, TLS1_3_VERSION, 0},
    {0xfeb6, 128, TLS1_3_VERSION, 0}, {0xfeb7, 128, TLS1_3_VERSION, 0},
    {0xfeb8, 128, TLS1_3_VERSION, 0}, {0xfeb9, 192, TLS1_3_VERSION, 0},
    {0xfeba, 192, TLS1_3_VERSION, 0}, {0xfec2, 128, TLS1_3_VERSION, 0},
    {0xfec3, 128, TLS1_3_VERSION, 0}, {0xfec4, 128, TLS1_3_VERSION, 0},
    {0xfeee, 128, TLS1_3_VERSION, 0}, {0xfef2, 128, TLS1_3_VERSION, 0},
    {0xfeef, 128, TLS1_3_VERSION, 0}, {0xfef3, 128, TLS1_3_VERSION, 0},
    {0xfef0, 192, TLS1_3_VERSION, 0}, {0xfef4, 192, TLS1_3_VERSION, 0},
    {0xfef1, 256, TLS1_3_VERSION, 0}, {0xfef5, 256, TLS1_3_VERSION, 0},
    {0xfef6, 128, TLS1_3_VERSION, 0},
    ///// KM_TEMPLATE_FRAGMENT_SIGALG_ASSIGNMENTS_END
};

int km_patch_codepoints() {
    ///// KM_TEMPLATE_FRAGMENT_CODEPOINT_PATCHING_START
    if (getenv("KM_CODEPOINT_DILITHIUM2"))
        km_sigalg_list[0].code_point =
            atoi(getenv("KM_CODEPOINT_DILITHIUM2"));
    
    if (getenv("KM_CODEPOINT_DILITHIUM3"))
        km_sigalg_list[1].code_point =
            atoi(getenv("KM_CODEPOINT_DILITHIUM3"));
    
    if (getenv("KM_CODEPOINT_DILITHIUM5"))
        km_sigalg_list[2].code_point =
            atoi(getenv("KM_CODEPOINT_DILITHIUM5"));

    if (getenv("KM_CODEPOINT_MLDSA44"))
        km_sigalg_list[3].code_point = atoi(getenv("KM_CODEPOINT_MLDSA44"));
    if (getenv("KM_CODEPOINT_MLDSA65"))
        km_sigalg_list[4].code_point = atoi(getenv("KM_CODEPOINT_MLDSA65"));
    if (getenv("KM_CODEPOINT_MLDSA87"))
        km_sigalg_list[5].code_point = atoi(getenv("KM_CODEPOINT_MLDSA87"));

    if (getenv("KM_CODEPOINT_SPHINCSSHA2128FSIMPLE"))
        km_sigalg_list[6].code_point =
            atoi(getenv("KM_CODEPOINT_SPHINCSSHA2128FSIMPLE"));
    if (getenv("KM_CODEPOINT_P256_SPHINCSSHA2128FSIMPLE"))
        km_sigalg_list[7].code_point =
            atoi(getenv("KM_CODEPOINT_P256_SPHINCSSHA2128FSIMPLE"));
    if (getenv("KM_CODEPOINT_RSA3072_SPHINCSSHA2128FSIMPLE"))
        km_sigalg_list[8].code_point =
            atoi(getenv("KM_CODEPOINT_RSA3072_SPHINCSSHA2128FSIMPLE"));

    if (getenv("KM_CODEPOINT_SPHINCSSHA2128SSIMPLE"))
        km_sigalg_list[9].code_point =
            atoi(getenv("KM_CODEPOINT_SPHINCSSHA2128SSIMPLE"));
    if (getenv("KM_CODEPOINT_P256_SPHINCSSHA2128SSIMPLE"))
        km_sigalg_list[10].code_point =
            atoi(getenv("KM_CODEPOINT_P256_SPHINCSSHA2128SSIMPLE"));
    if (getenv("KM_CODEPOINT_RSA3072_SPHINCSSHA2128SSIMPLE"))
        km_sigalg_list[11].code_point =
            atoi(getenv("KM_CODEPOINT_RSA3072_SPHINCSSHA2128SSIMPLE"));

    if (getenv("KM_CODEPOINT_SPHINCSSHA2192FSIMPLE"))
        km_sigalg_list[12].code_point =
            atoi(getenv("KM_CODEPOINT_SPHINCSSHA2192FSIMPLE"));

    if (getenv("KM_CODEPOINT_SPHINCSSHAKE128FSIMPLE"))
        km_sigalg_list[13].code_point =
            atoi(getenv("KM_CODEPOINT_SPHINCSSHAKE128FSIMPLE"));
    if (getenv("KM_CODEPOINT_P256_SPHINCSSHAKE128FSIMPLE"))
        km_sigalg_list[14].code_point =
            atoi(getenv("KM_CODEPOINT_P256_SPHINCSSHAKE128FSIMPLE"));
    if (getenv("KM_CODEPOINT_RSA3072_SPHINCSSHAKE128FSIMPLE"))
        km_sigalg_list[15].code_point =
            atoi(getenv("KM_CODEPOINT_RSA3072_SPHINCSSHAKE128FSIMPLE"));

    if (getenv("KM_CODEPOINT_KYBER512"))
        km_group_list[0].group_id = atoi(getenv("KM_CODEPOINT_KYBER512"));
    if (getenv("KM_CODEPOINT_KYBER768"))
        km_group_list[1].group_id = atoi(getenv("KM_CODEPOINT_KYBER768"));
    if (getenv("KM_CODEPOINT_KYBER1024"))
        km_group_list[2].group_id = atoi(getenv("KM_CODEPOINT_KYBER1024"));

    if (getenv("KM_CODEPOINT_MLKEM512"))
        km_group_list[3].group_id = atoi(getenv("KM_CODEPOINT_MLKEM512"));
    if (getenv("KM_CODEPOINT_MLKEM768"))
        km_group_list[4].group_id = atoi(getenv("KM_CODEPOINT_MLKEM768"));
    if (getenv("KM_CODEPOINT_MLKEM1024"))
        km_group_list[5].group_id = atoi(getenv("KM_CODEPOINT_MLKEM1024"));

    ///// KM_TEMPLATE_FRAGMENT_CODEPOINT_PATCHING_END
    return 1;
}

static int km_group_capability(OSSL_CALLBACK *cb, void *arg) {
    size_t i;

    for (i = 0; i < OSSL_NELEM(km_param_group_list); i++) {
        if (!cb(km_param_group_list[i], arg))
            return 0;
    }

    return 1;
}

#ifdef OSSL_CAPABILITY_TLS_SIGALG_NAME
#define KM_SIGALG_ENTRY(tlsname, realname, algorithm, oid, idx)               \
    {                                                                          \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME, #tlsname, \
                               sizeof(#tlsname)),                              \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_NAME, #tlsname,  \
                                   sizeof(#tlsname)),                          \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_OID, #oid,       \
                                   sizeof(#oid)),                              \
            OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT,             \
                            (unsigned int *)&km_sigalg_list[idx].code_point), \
            OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS,          \
                            (unsigned int *)&km_sigalg_list[idx].secbits),    \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS,                 \
                           (unsigned int *)&km_sigalg_list[idx].mintls),      \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS,                 \
                           (unsigned int *)&km_sigalg_list[idx].maxtls),      \
            OSSL_PARAM_END                                                     \
    }

static const OSSL_PARAM km_param_sigalg_list[][12] = {
///// KM_TEMPLATE_FRAGMENT_SIGALG_NAMES_START
    KM_SIGALG_ENTRY(dilithium2, dilithium2, dilithium2,
                     "1.3.6.1.4.1.2.267.7.4.4", 0),
    KM_SIGALG_ENTRY(dilithium3, dilithium3, dilithium3,
                     "1.3.6.1.4.1.2.267.7.6.5", 1),
    KM_SIGALG_ENTRY(dilithium5, dilithium5, dilithium5,
                     "1.3.6.1.4.1.2.267.7.8.7", 2),
    KM_SIGALG_ENTRY(mldsa44, mldsa44, mldsa44, "1.3.6.1.4.1.2.267.12.4.4", 3),
    KM_SIGALG_ENTRY(mldsa65, mldsa65, mldsa65, "1.3.6.1.4.1.2.267.12.6.5", 4),
    KM_SIGALG_ENTRY(mldsa87, mldsa87, mldsa87, "1.3.6.1.4.1.2.267.12.8.7", 5),
    KM_SIGALG_ENTRY(sphincssha2128fsimple, sphincssha2128fsimple,
                     sphincssha2128fsimple, "1.3.9999.6.4.13", 6),
    KM_SIGALG_ENTRY(sphincssha2128ssimple, sphincssha2128ssimple,
                     sphincssha2128ssimple, "1.3.9999.6.4.16", 7),
    KM_SIGALG_ENTRY(sphincssha2192fsimple, sphincssha2192fsimple,
                     sphincssha2192fsimple, "1.3.9999.6.5.10", 8),
    KM_SIGALG_ENTRY(sphincsshake128fsimple, sphincsshake128fsimple,
                     sphincsshake128fsimple, "1.3.9999.6.7.13", 9),

    ///// KM_TEMPLATE_FRAGMENT_SIGALG_NAMES_END
};

static int km_sigalg_capability(OSSL_CALLBACK *cb, void *arg) {
    size_t i;

    // relaxed assertion for the case that not all algorithms are enabled in
    // liboqs:
    assert(OSSL_NELEM(km_param_sigalg_list) <= OSSL_NELEM(km_sigalg_list));
    for (i = 0; i < OSSL_NELEM(km_param_sigalg_list); i++) {
        if (!cb(km_param_sigalg_list[i], arg))
            return 0;
    }

    return 1;
}
#endif /* OSSL_CAPABILITY_TLS_SIGALG_NAME */

int km_provider_get_capabilities(void *provctx, const char *capability,
                                  OSSL_CALLBACK *cb, void *arg) {
    if (strcasecmp(capability, "TLS-GROUP") == 0)
        return km_group_capability(cb, arg);

#ifdef OSSL_CAPABILITY_TLS_SIGALG_NAME
    if (strcasecmp(capability, "TLS-SIGALG") == 0)
        return km_sigalg_capability(cb, arg);
#else
#ifndef NDEBUG
    fprintf(stderr, "Warning: OSSL_CAPABILITY_TLS_SIGALG_NAME not defined: "
                    "OpenSSL version used that does not support pluggable "
                    "signature capabilities.\nUpgrading OpenSSL installation "
                    "recommended to enable QSC TLS signature support.\n\n");
#endif /* NDEBUG */
#endif /* OSSL_CAPABILITY_TLS_SIGALG_NAME */

    /* We don't support this capability */
    return 0;
}
