// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * Main kmprovider header file
 *
 * Code strongly inspired by OpenSSL crypto/ecx key handler.
 *
 */

/* Internal KM functions for other submodules: not for application use */
#ifndef KMX_H
#define KMX_H

#ifndef KM_PROVIDER_NOATOMIC
#include <stdatomic.h>
#endif

#include <openssl/bio.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/e_os2.h>
#include <openssl/opensslconf.h>

#define KM_PROVIDER_VERSION_STR KMPROVIDER_VERSION_TEXT

/* internal, but useful OSSL define */
#define OSSL_NELEM(x) (sizeof(x) / sizeof((x)[0]))

#ifdef _MSC_VER
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#endif

/* km error codes */
#define KMPROV_R_INVALID_DIGEST 1
#define KMPROV_R_INVALID_SIZE 2
#define KMPROV_R_INVALID_KEY 3
#define KMPROV_R_UNSUPPORTED 4
#define KMPROV_R_MISSING_OID 5
#define KMPROV_R_OBJ_CREATE_ERR 6
#define KMPROV_R_INVALID_ENCODING 7
#define KMPROV_R_SIGN_ERROR 8
#define KMPROV_R_LIB_CREATE_ERR 9
#define KMPROV_R_NO_PRIVATE_KEY 10
#define KMPROV_R_BUFFER_LENGTH_WRONG 11
#define KMPROV_R_SIGNING_FAILED 12
#define KMPROV_R_WRONG_PARAMETERS 13
#define KMPROV_R_VERIFY_ERROR 14
#define KMPROV_R_EVPINFO_MISSING 15
#define KMPROV_R_INTERNAL_ERROR 16

/* Extra OpenSSL parameters for hybrid EVP_PKEY. */
#define KM_HYBRID_PKEY_PARAM_CLASSICAL_PUB_KEY                                \
    "hybrid_classical_" OSSL_PKEY_PARAM_PUB_KEY
#define KM_HYBRID_PKEY_PARAM_CLASSICAL_PRIV_KEY                               \
    "hybrid_classical_" OSSL_PKEY_PARAM_PRIV_KEY
#define KM_HYBRID_PKEY_PARAM_PQ_PUB_KEY "hybrid_pq_" OSSL_PKEY_PARAM_PUB_KEY
#define KM_HYBRID_PKEY_PARAM_PQ_PRIV_KEY "hybrid_pq_" OSSL_PKEY_PARAM_PRIV_KEY

/* Extras for KM extension */

// clang-format off
// Helpers for (classic) key length storage
#define SIZE_OF_UINT32 4
#define ENCODE_UINT32(pbuf, i)                     \
    (pbuf)[0] = (unsigned char)((i >> 24) & 0xff); \
    (pbuf)[1] = (unsigned char)((i >> 16) & 0xff); \
    (pbuf)[2] = (unsigned char)((i >> 8) & 0xff);  \
    (pbuf)[3] = (unsigned char)((i) & 0xff)
#define DECODE_UINT32(i, pbuf)                         \
    i = ((uint32_t)((unsigned char *)pbuf)[0]) << 24;  \
    i |= ((uint32_t)((unsigned char *)pbuf)[1]) << 16; \
    i |= ((uint32_t)((unsigned char *)pbuf)[2]) << 8;  \
    i |= ((uint32_t)((unsigned char *)pbuf)[3])
// clang-format on

#define ON_ERR_SET_GOTO(condition, ret, code, gt)                              \
    if ((condition)) {                                                         \
        (ret) = (code);                                                        \
        goto gt;                                                               \
    }

#define ON_ERR_GOTO(condition, gt)                                             \
    if ((condition)) {                                                         \
        goto gt;                                                               \
    }

typedef struct prov_km_ctx_st {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx; /* For all provider modules */
    BIO_METHOD *corebiometh;
} PROV_KM_CTX;

PROV_KM_CTX *kmx_newprovctx(OSSL_LIB_CTX *libctx,
                              const OSSL_CORE_HANDLE *handle, BIO_METHOD *bm);
void kmx_freeprovctx(PROV_KM_CTX *ctx);
#define PROV_KM_LIBCTX_OF(provctx)                                            \
    provctx ? (((PROV_KM_CTX *)provctx)->libctx) : NULL

#include "oqs/oqs.h"

/* helper structure for classic key components in hybrid keys.
 * Actual tables in KMPROV_keys.c
 */
struct kmx_evp_info_st {
    int keytype;
    int nid;
    int raw_key_support;
    size_t length_public_key;
    size_t length_private_key;
    size_t kex_length_secret;
    size_t length_signature;
};

typedef struct kmx_evp_info_st KMX_EVP_INFO;

struct kmx_evp_ctx_st {
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *keyParam;
    const KMX_EVP_INFO *evp_info;
};

typedef struct kmx_evp_ctx_st KMX_EVP_CTX;

typedef union {
    OQS_SIG *sig;
    OQS_KEM *kem;
} KMX_QS_CTX;

struct kmx_provider_ctx_st {
    KMX_QS_CTX kmx_qs_ctx;
    KMX_EVP_CTX *kmx_evp_ctx;
};

typedef struct kmx_provider_ctx_st KMX_PROVIDER_CTX;

enum kmx_key_type_en {
    KEY_TYPE_SIG,
    KEY_TYPE_KEM,
    KEY_TYPE_ECP_HYB_KEM,
    KEY_TYPE_ECX_HYB_KEM,
    KEY_TYPE_HYB_SIG,
    KEY_TYPE_CMP_SIG
};

typedef enum kmx_key_type_en KMX_KEY_TYPE;

struct kmx_key_st {
    OSSL_LIB_CTX *libctx;
#ifdef KM_PROVIDER_NOATOMIC
    CRYPTO_RWLOCK *lock;
#endif
    char *propq;
    KMX_KEY_TYPE keytype;
    KMX_PROVIDER_CTX kmx_provider_ctx;
    EVP_PKEY *classical_pkey; // for hybrid & composite sigs
    const KMX_EVP_INFO *evp_info;
    size_t numkeys;

    /* Indicates if the share of a hybrid scheme should be reversed */
    int reverse_share;

    /* key lengths including size fields for classic key length information:
     * (numkeys-1)*SIZE_OF_UINT32
     */
    size_t privkeylen;
    size_t pubkeylen;
    size_t *privkeylen_cmp;
    size_t *pubkeylen_cmp;
    size_t bit_security;
    char *tls_name;
#ifndef KM_PROVIDER_NOATOMIC
    _Atomic
#endif
        int references;

    /* point to actual priv key material -- if is a hydrid, the classic key
     * will be present first, i.e., KM key always at comp_*key[numkeys-1] - if
     * is a composite, the classic key will be presented second, i.e., KM key
     * always at comp_*key[0]
     */
    void **comp_privkey;
    void **comp_pubkey;

    /* contain key material: First SIZE_OF_UINT32 bytes indicating actual
     * classic key length in case of hybrid keys (if numkeys>1)
     */
    void *privkey;
    void *pubkey;
};

typedef struct kmx_key_st KMX_KEY;

// composite signature
struct SignatureModel {
    ASN1_BIT_STRING *sig1;
    ASN1_BIT_STRING *sig2;
};

typedef struct SignatureModel CompositeSignature;

char *get_kmname_fromtls(char *tlsname);
char *get_kmname(int nid);
char *get_cmpname(int nid, int index);
int get_kmalg_idx(int nid);
int get_composite_idx(int idx);

/* Workaround for not functioning EC PARAM initialization
 * TBD, check https://github.com/openssl/openssl/issues/16989
 */
EVP_PKEY *setECParams(EVP_PKEY *eck, int nid);

/* Register given NID with tlsname in OSSL3 registry */
int km_set_nid(char *tlsname, int nid);

/* Create KMX_KEY data structure based on parameters; key material allocated
 * separately */
KMX_KEY *kmx_key_new(OSSL_LIB_CTX *libctx, char *km_name, char *tls_name,
                       int is_kem, const char *propq, int bit_security,
                       int alg_idx, int reverse_share);

/* allocate key material; component pointers need to be set separately */
int kmx_key_allocate_keymaterial(KMX_KEY *key, int include_private);

/* free all data structures, incl. key material */
void kmx_key_free(KMX_KEY *key);

/* increase reference count of given key */
int kmx_key_up_ref(KMX_KEY *key);

/* do (composite) key generation */
int kmx_key_gen(KMX_KEY *key);

/* create KMX_KEY from pkcs8 data structure */
KMX_KEY *kmx_key_from_pkcs8(const PKCS8_PRIV_KEY_INFO *p8inf,
                              OSSL_LIB_CTX *libctx, const char *propq);

/* create KMX_KEY (public key material only) from X509 data structure */
KMX_KEY *kmx_key_from_x509pubkey(const X509_PUBKEY *xpk, OSSL_LIB_CTX *libctx,
                                   const char *propq);

/* Backend support */
/* populate key material from parameters */
int kmx_key_fromdata(KMX_KEY *kmxk, const OSSL_PARAM params[],
                      int include_private);
/* retrieve security bit count for key */
int kmx_key_secbits(KMX_KEY *k);
/* retrieve pure KM key len */
int kmx_key_get_km_public_key_len(KMX_KEY *k);
/* retrieve maximum size of generated artifact (shared secret or signature,
 * respectively) */
int kmx_key_maxsize(KMX_KEY *k);
void kmx_key_set0_libctx(KMX_KEY *key, OSSL_LIB_CTX *libctx);
int km_patch_codepoints(void);

/* Function prototypes */

extern const OSSL_DISPATCH km_generic_kem_functions[];
extern const OSSL_DISPATCH km_hybrid_kem_functions[];
extern const OSSL_DISPATCH km_signature_functions[];

///// KM_TEMPLATE_FRAGMENT_ENDECODER_FUNCTIONS_START
// #ifdef KM_KEM_ENCODERS
extern const OSSL_DISPATCH
    km_kyber512_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_kyber512_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_kyber512_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_kyber512_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_kyber512_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_kyber512_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH km_kyber512_to_text_encoder_functions[];
extern const OSSL_DISPATCH
    km_PrivateKeyInfo_der_to_kyber512_decoder_functions[];
extern const OSSL_DISPATCH
    km_SubjectPublicKeyInfo_der_to_kyber512_decoder_functions[];

extern const OSSL_DISPATCH
    km_x25519_kyber512_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_x25519_kyber512_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_x25519_kyber512_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_x25519_kyber512_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_x25519_kyber512_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_x25519_kyber512_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH km_x25519_kyber512_to_text_encoder_functions[];
extern const OSSL_DISPATCH
    km_PrivateKeyInfo_der_to_x25519_kyber512_decoder_functions[];
extern const OSSL_DISPATCH
    km_SubjectPublicKeyInfo_der_to_x25519_kyber512_decoder_functions[];

extern const OSSL_DISPATCH
    km_kyber768_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_kyber768_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_kyber768_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_kyber768_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_kyber768_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_kyber768_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH km_kyber768_to_text_encoder_functions[];
extern const OSSL_DISPATCH
    km_PrivateKeyInfo_der_to_kyber768_decoder_functions[];
extern const OSSL_DISPATCH
    km_SubjectPublicKeyInfo_der_to_kyber768_decoder_functions[];

extern const OSSL_DISPATCH
    km_x25519_kyber768_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_x25519_kyber768_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_x25519_kyber768_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_x25519_kyber768_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_x25519_kyber768_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_x25519_kyber768_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH km_x25519_kyber768_to_text_encoder_functions[];
extern const OSSL_DISPATCH
    km_PrivateKeyInfo_der_to_x25519_kyber768_decoder_functions[];
extern const OSSL_DISPATCH
    km_SubjectPublicKeyInfo_der_to_x25519_kyber768_decoder_functions[];

extern const OSSL_DISPATCH
    km_kyber1024_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_kyber1024_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_kyber1024_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_kyber1024_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_kyber1024_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_kyber1024_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH km_kyber1024_to_text_encoder_functions[];
extern const OSSL_DISPATCH
    km_PrivateKeyInfo_der_to_kyber1024_decoder_functions[];
extern const OSSL_DISPATCH
    km_SubjectPublicKeyInfo_der_to_kyber1024_decoder_functions[];

extern const OSSL_DISPATCH
    km_mlkem512_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_mlkem512_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_mlkem512_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_mlkem512_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_mlkem512_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_mlkem512_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH km_mlkem512_to_text_encoder_functions[];
extern const OSSL_DISPATCH
    km_PrivateKeyInfo_der_to_mlkem512_decoder_functions[];
extern const OSSL_DISPATCH
    km_SubjectPublicKeyInfo_der_to_mlkem512_decoder_functions[];

extern const OSSL_DISPATCH
    km_x25519_mlkem512_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_x25519_mlkem512_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_x25519_mlkem512_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_x25519_mlkem512_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_x25519_mlkem512_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_x25519_mlkem512_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH km_x25519_mlkem512_to_text_encoder_functions[];
extern const OSSL_DISPATCH
    km_PrivateKeyInfo_der_to_x25519_mlkem512_decoder_functions[];
extern const OSSL_DISPATCH
    km_SubjectPublicKeyInfo_der_to_x25519_mlkem512_decoder_functions[];

extern const OSSL_DISPATCH
    km_mlkem768_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_mlkem768_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_mlkem768_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_mlkem768_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_mlkem768_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_mlkem768_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH km_mlkem768_to_text_encoder_functions[];
extern const OSSL_DISPATCH
    km_PrivateKeyInfo_der_to_mlkem768_decoder_functions[];
extern const OSSL_DISPATCH
    km_SubjectPublicKeyInfo_der_to_mlkem768_decoder_functions[];

extern const OSSL_DISPATCH
    km_X25519MLKEM768_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_X25519MLKEM768_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_X25519MLKEM768_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_X25519MLKEM768_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_X25519MLKEM768_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_X25519MLKEM768_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH km_X25519MLKEM768_to_text_encoder_functions[];
extern const OSSL_DISPATCH
    km_PrivateKeyInfo_der_to_X25519MLKEM768_decoder_functions[];
extern const OSSL_DISPATCH
    km_SubjectPublicKeyInfo_der_to_X25519MLKEM768_decoder_functions[];

extern const OSSL_DISPATCH
    km_mlkem1024_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_mlkem1024_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_mlkem1024_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_mlkem1024_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_mlkem1024_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_mlkem1024_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH km_mlkem1024_to_text_encoder_functions[];
extern const OSSL_DISPATCH
    km_PrivateKeyInfo_der_to_mlkem1024_decoder_functions[];
extern const OSSL_DISPATCH
    km_SubjectPublicKeyInfo_der_to_mlkem1024_decoder_functions[];
// #endif /* KM_KEM_ENCODERS */

extern const OSSL_DISPATCH
    km_dilithium2_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_dilithium2_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_dilithium2_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_dilithium2_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_dilithium2_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_dilithium2_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH km_dilithium2_to_text_encoder_functions[];
extern const OSSL_DISPATCH
    km_PrivateKeyInfo_der_to_dilithium2_decoder_functions[];
extern const OSSL_DISPATCH
    km_SubjectPublicKeyInfo_der_to_dilithium2_decoder_functions[];

extern const OSSL_DISPATCH
    km_dilithium3_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_dilithium3_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_dilithium3_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_dilithium3_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_dilithium3_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_dilithium3_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH km_dilithium3_to_text_encoder_functions[];
extern const OSSL_DISPATCH
    km_PrivateKeyInfo_der_to_dilithium3_decoder_functions[];
extern const OSSL_DISPATCH
    km_SubjectPublicKeyInfo_der_to_dilithium3_decoder_functions[];

extern const OSSL_DISPATCH
    km_dilithium5_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_dilithium5_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_dilithium5_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_dilithium5_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_dilithium5_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_dilithium5_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH km_dilithium5_to_text_encoder_functions[];
extern const OSSL_DISPATCH
    km_PrivateKeyInfo_der_to_dilithium5_decoder_functions[];
extern const OSSL_DISPATCH
    km_SubjectPublicKeyInfo_der_to_dilithium5_decoder_functions[];

extern const OSSL_DISPATCH
    km_mldsa44_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_mldsa44_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_mldsa44_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_mldsa44_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_mldsa44_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_mldsa44_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH km_mldsa44_to_text_encoder_functions[];
extern const OSSL_DISPATCH
    km_PrivateKeyInfo_der_to_mldsa44_decoder_functions[];
extern const OSSL_DISPATCH
    km_SubjectPublicKeyInfo_der_to_mldsa44_decoder_functions[];

extern const OSSL_DISPATCH
    km_mldsa65_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_mldsa65_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_mldsa65_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_mldsa65_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_mldsa65_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_mldsa65_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH km_mldsa65_to_text_encoder_functions[];
extern const OSSL_DISPATCH
    km_PrivateKeyInfo_der_to_mldsa65_decoder_functions[];
extern const OSSL_DISPATCH
    km_SubjectPublicKeyInfo_der_to_mldsa65_decoder_functions[];

extern const OSSL_DISPATCH
    km_mldsa87_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_mldsa87_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_mldsa87_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_mldsa87_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_mldsa87_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_mldsa87_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH km_mldsa87_to_text_encoder_functions[];
extern const OSSL_DISPATCH
    km_PrivateKeyInfo_der_to_mldsa87_decoder_functions[];
extern const OSSL_DISPATCH
    km_SubjectPublicKeyInfo_der_to_mldsa87_decoder_functions[];

extern const OSSL_DISPATCH
    km_sphincssha2128fsimple_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_sphincssha2128fsimple_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_sphincssha2128fsimple_to_EncryptedPrivateKeyInfo_der_encoder_functions
        [];
extern const OSSL_DISPATCH
    km_sphincssha2128fsimple_to_EncryptedPrivateKeyInfo_pem_encoder_functions
        [];
extern const OSSL_DISPATCH
    km_sphincssha2128fsimple_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_sphincssha2128fsimple_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_sphincssha2128fsimple_to_text_encoder_functions[];
extern const OSSL_DISPATCH
    km_PrivateKeyInfo_der_to_sphincssha2128fsimple_decoder_functions[];
extern const OSSL_DISPATCH
    km_SubjectPublicKeyInfo_der_to_sphincssha2128fsimple_decoder_functions[];

extern const OSSL_DISPATCH
    km_sphincssha2128ssimple_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_sphincssha2128ssimple_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_sphincssha2128ssimple_to_EncryptedPrivateKeyInfo_der_encoder_functions
        [];
extern const OSSL_DISPATCH
    km_sphincssha2128ssimple_to_EncryptedPrivateKeyInfo_pem_encoder_functions
        [];
extern const OSSL_DISPATCH
    km_sphincssha2128ssimple_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_sphincssha2128ssimple_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_sphincssha2128ssimple_to_text_encoder_functions[];
extern const OSSL_DISPATCH
    km_PrivateKeyInfo_der_to_sphincssha2128ssimple_decoder_functions[];
extern const OSSL_DISPATCH
    km_SubjectPublicKeyInfo_der_to_sphincssha2128ssimple_decoder_functions[];

extern const OSSL_DISPATCH
    km_sphincssha2192fsimple_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_sphincssha2192fsimple_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_sphincssha2192fsimple_to_EncryptedPrivateKeyInfo_der_encoder_functions
        [];
extern const OSSL_DISPATCH
    km_sphincssha2192fsimple_to_EncryptedPrivateKeyInfo_pem_encoder_functions
        [];
extern const OSSL_DISPATCH
    km_sphincssha2192fsimple_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_sphincssha2192fsimple_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_sphincssha2192fsimple_to_text_encoder_functions[];
extern const OSSL_DISPATCH
    km_PrivateKeyInfo_der_to_sphincssha2192fsimple_decoder_functions[];
extern const OSSL_DISPATCH
    km_SubjectPublicKeyInfo_der_to_sphincssha2192fsimple_decoder_functions[];

extern const OSSL_DISPATCH
    km_sphincsshake128fsimple_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_sphincsshake128fsimple_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_sphincsshake128fsimple_to_EncryptedPrivateKeyInfo_der_encoder_functions
        [];
extern const OSSL_DISPATCH
    km_sphincsshake128fsimple_to_EncryptedPrivateKeyInfo_pem_encoder_functions
        [];
extern const OSSL_DISPATCH
    km_sphincsshake128fsimple_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH
    km_sphincsshake128fsimple_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH
    km_sphincsshake128fsimple_to_text_encoder_functions[];
extern const OSSL_DISPATCH
    km_PrivateKeyInfo_der_to_sphincsshake128fsimple_decoder_functions[];
extern const OSSL_DISPATCH
    km_SubjectPublicKeyInfo_der_to_sphincsshake128fsimple_decoder_functions[];

///// KM_TEMPLATE_FRAGMENT_ENDECODER_FUNCTIONS_END

///// KM_TEMPLATE_FRAGMENT_ALG_FUNCTIONS_START
extern const OSSL_DISPATCH km_dilithium2_keymgmt_functions[];
extern const OSSL_DISPATCH km_dilithium3_keymgmt_functions[];
extern const OSSL_DISPATCH km_dilithium5_keymgmt_functions[];

extern const OSSL_DISPATCH km_mldsa44_keymgmt_functions[];
extern const OSSL_DISPATCH km_mldsa65_keymgmt_functions[];
extern const OSSL_DISPATCH km_mldsa87_keymgmt_functions[];

extern const OSSL_DISPATCH km_sphincssha2128fsimple_keymgmt_functions[];
extern const OSSL_DISPATCH km_sphincssha2128ssimple_keymgmt_functions[];
extern const OSSL_DISPATCH km_sphincssha2192fsimple_keymgmt_functions[];
extern const OSSL_DISPATCH km_sphincsshake128fsimple_keymgmt_functions[];


extern const OSSL_DISPATCH km_kyber512_keymgmt_functions[];
extern const OSSL_DISPATCH km_ecx_x25519_kyber512_keymgmt_functions[];
extern const OSSL_DISPATCH km_kyber768_keymgmt_functions[];
extern const OSSL_DISPATCH km_ecx_x25519_kyber768_keymgmt_functions[];
extern const OSSL_DISPATCH km_kyber1024_keymgmt_functions[];

extern const OSSL_DISPATCH km_mlkem512_keymgmt_functions[];
extern const OSSL_DISPATCH km_ecx_x25519_mlkem512_keymgmt_functions[];
extern const OSSL_DISPATCH km_mlkem768_keymgmt_functions[];
extern const OSSL_DISPATCH km_ecx_X25519MLKEM768_keymgmt_functions[];
extern const OSSL_DISPATCH km_mlkem1024_keymgmt_functions[];
///// KM_TEMPLATE_FRAGMENT_ALG_FUNCTIONS_END

/* BIO function declarations */
int km_prov_bio_from_dispatch(const OSSL_DISPATCH *fns);

OSSL_CORE_BIO *km_prov_bio_new_file(const char *filename, const char *mode);
OSSL_CORE_BIO *km_prov_bio_new_membuf(const char *filename, int len);
int km_prov_bio_read_ex(OSSL_CORE_BIO *bio, void *data, size_t data_len,
                         size_t *bytes_read);
int km_prov_bio_write_ex(OSSL_CORE_BIO *bio, const void *data, size_t data_len,
                          size_t *written);
int km_prov_bio_gets(OSSL_CORE_BIO *bio, char *buf, int size);
int km_prov_bio_puts(OSSL_CORE_BIO *bio, const char *str);
int km_prov_bio_ctrl(OSSL_CORE_BIO *bio, int cmd, long num, void *ptr);
int km_prov_bio_up_ref(OSSL_CORE_BIO *bio);
int km_prov_bio_free(OSSL_CORE_BIO *bio);
int km_prov_bio_vprintf(OSSL_CORE_BIO *bio, const char *format, va_list ap);
int km_prov_bio_printf(OSSL_CORE_BIO *bio, const char *format, ...);

BIO_METHOD *km_bio_prov_init_bio_method(void);
BIO *km_bio_new_from_core_bio(PROV_KM_CTX *provctx, OSSL_CORE_BIO *corebio);

#endif
