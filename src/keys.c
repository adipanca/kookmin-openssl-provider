// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * KM OpenSSL 3 key handler.
 *
 * Code strongly inspired by OpenSSL crypto/ec key handler but relocated here
 * to have code within provider.
 *
 */

#include <assert.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <string.h>

#include "provider.h"

#ifdef NDEBUG
#define KM_KEY_PRINTF(a)
#define KM_KEY_PRINTF2(a, b)
#define KM_KEY_PRINTF3(a, b, c)
#else
#define KM_KEY_PRINTF(a)                                                      \
    if (getenv("KMKEY"))                                                      \
    printf(a)
#define KM_KEY_PRINTF2(a, b)                                                  \
    if (getenv("KMKEY"))                                                      \
    printf(a, b)
#define KM_KEY_PRINTF3(a, b, c)                                               \
    if (getenv("KMKEY"))                                                      \
    printf(a, b, c)
#endif // NDEBUG

typedef enum { KEY_OP_PUBLIC, KEY_OP_PRIVATE, KEY_OP_KEYGEN } kmx_key_op_t;

/// NID/name table

typedef struct {
    int nid;
    char *tlsname;
    char *kmname;
    int keytype;
    int secbits;
    int reverseshare;
} km_nid_name_t;

static int kmx_key_recreate_classickey(KMX_KEY *key, kmx_key_op_t op);

///// KM_TEMPLATE_FRAGMENT_KMNAMES_START

#define NID_TABLE_LEN 110
static km_nid_name_t nid_names[NID_TABLE_LEN] = {
    /* KEM / Hybrid ECX KEM */
    {0, "kyber512",          OQS_KEM_alg_kyber_512,  KEY_TYPE_KEM,         128, 0},
    {0, "x25519_kyber512",   OQS_KEM_alg_kyber_512,  KEY_TYPE_ECX_HYB_KEM, 128, 0},
    {0, "kyber768",          OQS_KEM_alg_kyber_768,  KEY_TYPE_KEM,         192, 0},
    {0, "x25519_kyber768",   OQS_KEM_alg_kyber_768,  KEY_TYPE_ECX_HYB_KEM, 192, 0},
    {0, "kyber1024",         OQS_KEM_alg_kyber_1024, KEY_TYPE_KEM,         256, 0},
    {0, "mlkem512",          OQS_KEM_alg_ml_kem_512, KEY_TYPE_KEM,         128, 0},
    {0, "x25519_mlkem512",   OQS_KEM_alg_ml_kem_512, KEY_TYPE_ECX_HYB_KEM, 128, 1},
    {0, "mlkem768",          OQS_KEM_alg_ml_kem_768, KEY_TYPE_KEM,         192, 0},
    {0, "X25519MLKEM768",    OQS_KEM_alg_ml_kem_768, KEY_TYPE_ECX_HYB_KEM, 192, 1},
    {0, "mlkem1024",         OQS_KEM_alg_ml_kem_1024,KEY_TYPE_KEM,         256, 0},

    /* SIG PQ */
    {0, "dilithium2",        OQS_SIG_alg_dilithium_2, KEY_TYPE_SIG, 128, 0},
    {0, "dilithium3",        OQS_SIG_alg_dilithium_3, KEY_TYPE_SIG, 192, 0},
    {0, "dilithium5",        OQS_SIG_alg_dilithium_5, KEY_TYPE_SIG, 256, 0},
    {0, "mldsa44",           OQS_SIG_alg_ml_dsa_44,    KEY_TYPE_SIG, 128, 0},
    {0, "mldsa65",           OQS_SIG_alg_ml_dsa_65,    KEY_TYPE_SIG, 192, 0},
    {0, "mldsa87",           OQS_SIG_alg_ml_dsa_87,    KEY_TYPE_SIG, 256, 0},

    /* SPHINCS+ contoh (subset) */
    {0, "sphincssha2128fsimple",  OQS_SIG_alg_sphincs_sha2_128f_simple,   KEY_TYPE_SIG, 128, 0},
    {0, "sphincssha2128ssimple",  OQS_SIG_alg_sphincs_sha2_128s_simple,   KEY_TYPE_SIG, 128, 0},
    {0, "sphincssha2192fsimple",  OQS_SIG_alg_sphincs_sha2_192f_simple,   KEY_TYPE_SIG, 192, 0},
    {0, "sphincsshake128fsimple", OQS_SIG_alg_sphincs_shake_128f_simple,  KEY_TYPE_SIG, 128, 0},
    /* ... (entri lain tetap seperti file asli Anda) ... */
};


/* ======= mapping & composite helpers (same behavior) ======= */

static inline int km__find_idx_by_nid(int nid) {
    for (int i = 0; i < NID_TABLE_LEN; ++i) {
        if (nid_names[i].nid == nid) return i;
    }
    return -1;
}

int km_set_nid(char *tlsname, int nid) {
    if (tlsname == NULL) return 0;
    for (int i = 0; i < NID_TABLE_LEN; ++i) {
        /* bandingkan ke dua sisi lebih dulu agar cepat short-circuit */
        if (nid_names[i].tlsname && strcmp(nid_names[i].tlsname, tlsname) == 0) {
            nid_names[i].nid = nid;
            return 1;
        }
    }
    return 0;
}

static int get_secbits(int nid) {
    int idx = km__find_idx_by_nid(nid);
    return (idx >= 0) ? nid_names[idx].secbits : 0;
}

static int get_reverseshare(int nid) {
    int idx = km__find_idx_by_nid(nid);
    return (idx >= 0) ? nid_names[idx].reverseshare : 0;
}

static int get_keytype(int nid) {
    int idx = km__find_idx_by_nid(nid);
    return (idx >= 0) ? nid_names[idx].keytype : 0;
}

char *get_kmname_fromtls(char *tlsname) {
    if (tlsname == NULL) return NULL;
    for (int i = 0; i < NID_TABLE_LEN; ++i) {
        /* hanya cek entri SIG; “classical” dikembalikan NULL */
        if (nid_names[i].keytype != KEY_TYPE_SIG) continue;

        /* cocokkan baik nama KM maupun TLS agar robust */
        if ((nid_names[i].kmname && strcmp(nid_names[i].kmname, tlsname) == 0) ||
            (nid_names[i].tlsname && strcmp(nid_names[i].tlsname, tlsname) == 0)) {
            return nid_names[i].kmname;
        }
    }
    return NULL; /* classical */
}

char *get_kmname(int nid) {
    int idx = km__find_idx_by_nid(nid);
    return (idx >= 0) ? nid_names[idx].kmname : NULL;
}

int get_kmalg_idx(int nid) {
    return km__find_idx_by_nid(nid);
}

char *get_cmpname(int nid, int index) {
    int table_idx = km__find_idx_by_nid(nid);
    if (table_idx < 0) return NULL;

    const char *s = nid_names[table_idx].tlsname;
    if (s == NULL) return NULL;

    /* pisahkan “algo1_algo2” di underscore pertama */
    const char *sep = strchr(s, '_');
    if (sep == NULL) {
        /* tidak ada underscore: hanya satu komponen, hanya index 0 valid */
        if (index == 0) return OPENSSL_strdup(s);
        return NULL;
    }

    switch (index) {
        case 0: {
            size_t left_len = (size_t)(sep - s);
            return OPENSSL_strndup(s, (int)left_len);
        }
        case 1: {
            const char *right = sep + 1;
            return OPENSSL_strdup(right);
        }
        default:
            return NULL;
    }
}

/* Menentukan indeks komponen klasik & PQ pada array comp_{priv,pub}key */
static void kmx_comp_set_idx(const KMX_KEY *key, int *idx_classic, int *idx_pq) {
    /* reverse_share hanya relevan untuk HYB KEM; buat boolean tunggal */
    const int is_hyb_kem = (key->keytype == KEY_TYPE_ECP_HYB_KEM ||
                            key->keytype == KEY_TYPE_ECX_HYB_KEM);
    const int reversed = is_hyb_kem && key->reverse_share;

    if (idx_classic) *idx_classic = reversed ? (key->numkeys - 1) : 0;
    if (idx_pq)      *idx_pq      = reversed ? 0 : (key->numkeys - 1);
}

/*
 * Menghitung offset pointer untuk komponen klasik & PQ di buffer komposit.
 * - Jika classic_lengths_fixed = 1, panjang klasik diambil dari evp_info
 *   (fixed); jika 0, panjang klasik dibaca dari prefix UINT32 di buffer.
 */
static int kmx_comp_set_offsets(const KMX_KEY *key,
                                int set_privkey_offsets,
                                int set_pubkey_offsets,
                                int classic_lengths_fixed) {
    if (key == NULL) return 0;

    int ok = 1;
    uint32_t klass_pub_len = 0;
    uint32_t klass_prv_len = 0;

    unsigned char *privkey = (unsigned char *)key->privkey;
    unsigned char *pubkey  = (unsigned char *)key->pubkey;

    const int is_hyb_kem = (key->keytype == KEY_TYPE_ECP_HYB_KEM ||
                            key->keytype == KEY_TYPE_ECX_HYB_KEM);
    const int reversed = is_hyb_kem && key->reverse_share;

    if (set_privkey_offsets) {
        if (privkey == NULL) return 0;

        key->comp_privkey[0] = privkey + SIZE_OF_UINT32;

        if (!classic_lengths_fixed) {
            DECODE_UINT32(klass_prv_len, privkey);
            if (klass_prv_len > key->evp_info->length_private_key) {
                ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING);
                ok = 0;
                goto done;
            }
        } else {
            klass_prv_len = (uint32_t)key->evp_info->length_private_key;
        }

        if (reversed) {
            /* [UINT32 | PQ_PRIV | CLASSIC_PRIV] */
            key->comp_privkey[1] = privkey
                + SIZE_OF_UINT32
                + key->kmx_provider_ctx.kmx_qs_ctx.kem->length_secret_key;
        } else {
            /* [UINT32 | CLASSIC_PRIV | PQ_PRIV] */
            key->comp_privkey[1] = privkey + SIZE_OF_UINT32 + klass_prv_len;
        }
    }

    if (set_pubkey_offsets) {
        if (pubkey == NULL) return 0;

        key->comp_pubkey[0] = pubkey + SIZE_OF_UINT32;

        if (!classic_lengths_fixed) {
            DECODE_UINT32(klass_pub_len, pubkey);
            if (klass_pub_len > key->evp_info->length_public_key) {
                ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING);
                ok = 0;
                goto done;
            }
        } else {
            klass_pub_len = (uint32_t)key->evp_info->length_public_key;
        }

        if (reversed) {
            /* [UINT32 | PQ_PUB | CLASSIC_PUB] */
            key->comp_pubkey[1] = pubkey
                + SIZE_OF_UINT32
                + key->kmx_provider_ctx.kmx_qs_ctx.kem->length_public_key;
        } else {
            /* [UINT32 | CLASSIC_PUB | PQ_PUB] */
            key->comp_pubkey[1] = pubkey + SIZE_OF_UINT32 + klass_pub_len;
        }
    }

done:
    return ok;
}

/* =========================
 * composites & ctx helpers
 * ========================= */

/* Prepare composite data structures. RetVal 0 is error. */
static int kmx_key_set_composites(KMX_KEY *key, int classic_lengths_fixed) {
    if (!key) return 0;

    KM_KEY_PRINTF2("Setting composites with evp_info %p\n", key->evp_info);

    /* Skenario 1: hanya satu komponen */
    if (key->numkeys == 1) {
        key->comp_privkey[0] = key->privkey;
        key->comp_pubkey[0]  = key->pubkey;
        return 1;
    }

    /* Skenario 2: composite signature (beberapa segmen berdampingan) */
    if (key->keytype == KEY_TYPE_CMP_SIG) {
        size_t off_priv = 0, off_pub = 0;
        for (int i = 0; i < key->numkeys; ++i) {
            if (key->privkey) {
                key->comp_privkey[i] = (unsigned char *)key->privkey + off_priv;
                off_priv += key->privkeylen_cmp[i];
            } else {
                key->comp_privkey[i] = NULL;
            }

            if (key->pubkey) {
                key->comp_pubkey[i] = (unsigned char *)key->pubkey + off_pub;
                off_pub += key->pubkeylen_cmp[i];
            } else {
                key->comp_pubkey[i] = NULL;
            }
        }
        return 1;
    }

    /* Skenario 3: hybrid (kem/sig klasik + PQ) – gunakan kalkulasi offset */
    {
        const int need_priv = (key->privkey != NULL);
        const int need_pub  = (key->pubkey  != NULL);

        int ok = kmx_comp_set_offsets(key, need_priv, need_pub, classic_lengths_fixed);
        if (!ok) return 0;

        if (!need_priv) key->comp_privkey[0] = key->comp_privkey[1] = NULL;
        if (!need_pub)  key->comp_pubkey[0]  = key->comp_pubkey[1]  = NULL;
        return 1;
    }
}

/* =========================
 * Provider ctx helpers
 * ========================= */

PROV_KM_CTX *kmx_newprovctx(OSSL_LIB_CTX *libctx,
                            const OSSL_CORE_HANDLE *handle,
                            BIO_METHOD *bm) {
    PROV_KM_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx) return NULL;

    ctx->libctx      = libctx;
    ctx->handle      = handle;
    ctx->corebiometh = bm;
    return ctx;
}

void kmx_freeprovctx(PROV_KM_CTX *ctx) {
    if (!ctx) return;
    OSSL_LIB_CTX_free(ctx->libctx);
    BIO_meth_free(ctx->corebiometh);
    OPENSSL_free(ctx);
}

void kmx_key_set0_libctx(KMX_KEY *key, OSSL_LIB_CTX *libctx) {
    if (key) key->libctx = libctx;
}

/* =========================
 * Factory key dari NID (khusus SIG)
 * ========================= */

static KMX_KEY *kmx_key_new_from_nid(OSSL_LIB_CTX *libctx,
                                     const char *propq,
                                     int nid) {
    KM_KEY_PRINTF2("Generating KMX key for nid %d\n", nid);

    const char *tls_algname = OBJ_nid2sn(nid);
    KM_KEY_PRINTF2("                    for tls_name %s\n",
                   tls_algname ? tls_algname : "(null)");

    if (!tls_algname) {
        ERR_raise(ERR_LIB_USER, KMPROV_R_WRONG_PARAMETERS);
        return NULL;
    }

    return kmx_key_new(libctx,
                       get_kmname(nid),
                       (char *)tls_algname,          /* API lama: char* */
                       get_keytype(nid),
                       propq,
                       get_secbits(nid),
                       get_kmalg_idx(nid),
                       get_reverseshare(nid));
}

/* =========================
 * Work-around EC params (DER OID → EVP_PKEY params)
 * ========================= */

EVP_PKEY *setECParams(EVP_PKEY *eck, int nid) {
    struct map_entry { int nid; const unsigned char *der; size_t len; };

    static const unsigned char der_p256[]  = {0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07};
    static const unsigned char der_p384[]  = {0x06,0x05,0x2b,0x81,0x04,0x00,0x22};
    static const unsigned char der_p521[]  = {0x06,0x05,0x2b,0x81,0x04,0x00,0x23};
    static const unsigned char der_bp256[] = {0x06,0x09,0x2b,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x07};
    static const unsigned char der_bp384[] = {0x06,0x09,0x2b,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0b};

    static const struct map_entry table[] = {
        { NID_X9_62_prime256v1, der_p256,  sizeof(der_p256)  },
        { NID_secp384r1,        der_p384,  sizeof(der_p384)  },
        { NID_secp521r1,        der_p521,  sizeof(der_p521)  },
        { NID_brainpoolP256r1,  der_bp256, sizeof(der_bp256) },
        { NID_brainpoolP384r1,  der_bp384, sizeof(der_bp384) },
    };

    for (size_t i = 0; i < sizeof(table)/sizeof(table[0]); ++i) {
        if (table[i].nid == nid) {
            const unsigned char *p = table[i].der;
            return d2i_KeyParams(EVP_PKEY_EC, &eck, &p, (long)table[i].len);
        }
    }
    return NULL;
}

/* =========================
 * Tabel nids_* & nama – (tidak diubah isinya)
 * ========================= */

static const KMX_EVP_INFO nids_sig[] = {
    {EVP_PKEY_EC, NID_X9_62_prime256v1, 0, 65, 121, 32, 72}, // 128 bit
    {EVP_PKEY_EC, NID_secp384r1,        0, 97, 167, 48, 104},// 192 bit
    {EVP_PKEY_EC, NID_secp521r1,        0,133, 223, 66, 141},// 256 bit
    {EVP_PKEY_EC, NID_brainpoolP256r1,  0, 65, 122, 32, 72}, // 256 bit
    {EVP_PKEY_EC, NID_brainpoolP384r1,  0, 97, 171, 48, 104},// 384 bit
    {EVP_PKEY_RSA, NID_rsaEncryption,   0,398,1770,  0, 384},// 128 bit
    {EVP_PKEY_RSA, NID_rsaEncryption,   0,270,1193,  0, 256},// 112 bit
    {EVP_PKEY_ED25519, NID_ED25519,     1, 32,  32, 32, 72}, // 128 bit
    {EVP_PKEY_ED448,   NID_ED448,       1, 57,  57, 57,122}, // 192 bit
};

/* hanya leading 4 char yang dicek – array harus sinkron */
static const char *KMX_ECP_NAMES[] = {
    "p256","p384","p521","SecP256r1","SecP384r1","SecP521r1",0
};

static const KMX_EVP_INFO nids_ecp[] = {
    {EVP_PKEY_EC, NID_X9_62_prime256v1, 0, 65, 121, 32, 0}, // 128 bit
    {EVP_PKEY_EC, NID_secp384r1,        0, 97, 167, 48, 0}, // 192 bit
    {EVP_PKEY_EC, NID_secp521r1,        0,133, 223, 66, 0}, // 256 bit
    {EVP_PKEY_EC, NID_X9_62_prime256v1, 0, 65, 121, 32, 0}, // 128 bit
    {EVP_PKEY_EC, NID_secp384r1,        0, 97, 167, 48, 0}, // 192 bit
    {EVP_PKEY_EC, NID_secp521r1,        0,133, 223, 66, 0}, // 256 bit
    {0, 0, 0, 0, 0, 0, 0}
};

/* hanya leading 4 char yang dicek – array harus sinkron */
static const char *KMX_ECX_NAMES[] = {"x25519","x448","X25519","X448",0};

static const KMX_EVP_INFO nids_ecx[] = {
    {EVP_PKEY_X25519, 0, 1, 32, 32, 32, 0}, // 128 bit
    {EVP_PKEY_X448,   0, 1, 56, 56, 56, 0}, // 192 bit
    {EVP_PKEY_X25519, 0, 1, 32, 32, 32, 0}, // 128 bit
    {EVP_PKEY_X448,   0, 1, 56, 56, 56, 0}, // 192 bit
    {0, 0, 0, 0, 0, 0, 0}
};

/* ============================================================
 * Helpers (internal only untuk file ini)
 * ============================================================ */

/* Hitung indeks nids_sig berdasarkan bit_security & nama algoritma klasik.
 * Mengembalikan 1 jika sukses, 0 jika gagal. out_idx diisi indeks final,
 * dan out_is_ed = 1 jika targetnya ED25519/ED448. */
static int kmx__resolve_sig_index(int bit_security,
                                  const char *algname,
                                  int *out_idx,
                                  int *out_is_ed)
{
    if (!algname || !out_idx || !out_is_ed) return 0;

    /* map 128/192/256 → 0/1/2; 112 ditangani khusus di RSA */
    int idx = (bit_security - 128) / 64;
    if (idx < 0 || idx > 5) return 0; /* batas aman sesuai array */

    *out_is_ed = 0;

    /* RSA/PSS: berpindah ke blok RSA pada tabel nids_sig */
    if (!strncmp(algname, "rsa", 3) || !strncmp(algname, "pss", 3)) {
        idx += 5;                  /* lompat ke entri RSA */
        if (bit_security == 112)   /* 2048-bit case */
            idx += 1;
    } else if (algname[0] == 'e') {
        /* ED25519/ED448 akan gunakan offset +7 (lihat nids_sig) */
        *out_is_ed = 1;
    } else if (algname[0] == 'b') {
        /* brainpool: bp256 -> geser 1 tingkat (kompatibel dengan kode lama) */
        if (algname[2] == '2')     /* "bp256..." */
            idx += 1;
        /* bp384 mengikuti idx default */
    } else if (algname[0] != 'p') {
        /* hanya p-*, e*, rsa/pss, atau brainpool yang valid */
        KM_KEY_PRINTF2("KM KEY: Incorrect hybrid name: %s\n", algname);
        return 0;
    }

    /* validasi akhir (array guard) */
    if (idx < 0 || idx > 6) return 0;

    *out_idx = idx;
    return 1;
}

/* Cari indeks nama kurva ECP pada KMX_ECP_NAMES berdasarkan prefix.
 * Mengembalikan -1 jika tidak ada. */
static int kmx__find_ecp_name_index(const char *tls_name)
{
    if (!tls_name) return -1;
    for (size_t i = 0; KMX_ECP_NAMES[i]; ++i) {
        const size_t need = (i < 3) ? 4 : 7; /* "p256"/"SecP256r1" dkk */
        if (!strncmp(tls_name, KMX_ECP_NAMES[i], need))
            return (int)i;
    }
    return -1;
}

/* Cari indeks nama ECX (X25519/X448) berdasarkan prefix 4 huruf. */
static int kmx__find_ecx_name_index(const char *tls_name)
{
    if (!tls_name) return -1;
    for (size_t i = 0; KMX_ECX_NAMES[i]; ++i) {
        if (!strncmp(tls_name, KMX_ECX_NAMES[i], 4))
            return (int)i;
    }
    return -1;
}

/* ============================================================
 * fungsi init
 * ============================================================ */

static int kmx_hybsig_init(int bit_security, KMX_EVP_CTX *evp_ctx,
                           char *algname)
{
    int ok, idx, is_ed = 0;
    int ret = 1;

    ok = kmx__resolve_sig_index(bit_security, algname, &idx, &is_ed);
    ON_ERR_GOTO(!ok, err_init);

    if (is_ed) {
        /* ED25519 / ED448: gunakan blok ED pada nids_sig (offset +7) */
        evp_ctx->evp_info = &nids_sig[idx + 7];

        evp_ctx->keyParam = EVP_PKEY_new();
        ON_ERR_SET_GOTO(!evp_ctx->keyParam, ret, -1, err_init);

        ret = EVP_PKEY_set_type(evp_ctx->keyParam, evp_ctx->evp_info->keytype);
        ON_ERR_SET_GOTO(ret <= 0, ret, -1, err_init);

        evp_ctx->ctx = EVP_PKEY_CTX_new(evp_ctx->keyParam, NULL);
        ON_ERR_SET_GOTO(!evp_ctx->ctx, ret, -1, err_init);
    } else {
        /* EC atau RSA */
        evp_ctx->evp_info = &nids_sig[idx];

        evp_ctx->ctx = EVP_PKEY_CTX_new_id(evp_ctx->evp_info->keytype, NULL);
        ON_ERR_GOTO(!evp_ctx->ctx, err_init);

        /* Untuk EC, lakukan paramgen (RSA: ukuran kunci diset saat keygen) */
        if (idx < 5) {
            ret = EVP_PKEY_paramgen_init(evp_ctx->ctx);
            ON_ERR_GOTO(ret <= 0, err_init);

            ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
                      evp_ctx->ctx, evp_ctx->evp_info->nid);
            ON_ERR_GOTO(ret <= 0, free_evp_ctx);

            ret = EVP_PKEY_paramgen(evp_ctx->ctx, &evp_ctx->keyParam);
            ON_ERR_GOTO(ret <= 0 || !evp_ctx->keyParam, free_evp_ctx);
        }
    }

    /* RSA bit length tetap diset saat keygen seperti semula */
    goto err_init;

free_evp_ctx:
    EVP_PKEY_CTX_free(evp_ctx->ctx);
    evp_ctx->ctx = NULL;

err_init:
    return ret;
}

static const int kmhybkem_init_ecp(char *tls_name, KMX_EVP_CTX *evp_ctx)
{
    int idx = kmx__find_ecp_name_index(tls_name);
    int ret = 1;

    ON_ERR_GOTO(idx < 0 || idx > 6, err_init_ecp);

    evp_ctx->evp_info = &nids_ecp[idx];

    evp_ctx->ctx = EVP_PKEY_CTX_new_id(evp_ctx->evp_info->keytype, NULL);
    ON_ERR_GOTO(!evp_ctx->ctx, err_init_ecp);

    ret = EVP_PKEY_paramgen_init(evp_ctx->ctx);
    ON_ERR_GOTO(ret <= 0, err_init_ecp);

    ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
              evp_ctx->ctx, evp_ctx->evp_info->nid);
    ON_ERR_GOTO(ret <= 0, err_init_ecp);

    ret = EVP_PKEY_paramgen(evp_ctx->ctx, &evp_ctx->keyParam);
    ON_ERR_GOTO(ret <= 0 || !evp_ctx->keyParam, err_init_ecp);

err_init_ecp:
    return ret;
}

static const int kmhybkem_init_ecx(char *tls_name, KMX_EVP_CTX *evp_ctx)
{
    int idx = kmx__find_ecx_name_index(tls_name);
    int ret = 1;

    ON_ERR_GOTO(idx < 0 || idx > 4, err_init_ecx);

    evp_ctx->evp_info = &nids_ecx[idx];

    evp_ctx->keyParam = EVP_PKEY_new();
    ON_ERR_SET_GOTO(!evp_ctx->keyParam, ret, -1, err_init_ecx);

    ret = EVP_PKEY_set_type(evp_ctx->keyParam, evp_ctx->evp_info->keytype);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err_init_ecx);

    evp_ctx->ctx = EVP_PKEY_CTX_new(evp_ctx->keyParam, NULL);
    ON_ERR_SET_GOTO(!evp_ctx->ctx, ret, -1, err_init_ecx);

err_init_ecx:
    return ret;
}

/* ---------- helpers khusus fungsi ini ---------- */

static int kmx__need_classic_fixed_lens(const KMX_KEY *key) {
    return key->keytype == KEY_TYPE_ECP_HYB_KEM ||
           key->keytype == KEY_TYPE_ECX_HYB_KEM;
}

static int kmx__ensure_material(KMX_KEY *key, int want_pub, int want_priv) {
    if (want_pub && kmx_key_allocate_keymaterial(key, 0))  return 0;
    if (want_priv && kmx_key_allocate_keymaterial(key, 1)) return 0;
    return 1;
}

/* Build ulang buffer privat/publik untuk COMPOSITE-SIG dari encoding berurutan. */
static int kmx__rebuild_composite_privpub(KMX_KEY *key,
                                          const unsigned char *p, int plen) {
    size_t acc_priv = 0, acc_pub = 0;
    size_t need_priv = 0, need_pub = 0;
    int i, pqc_pub_enc = 0;

    /* hitung total ukuran yang diharapkan */
    for (i = 0; i < key->numkeys; i++) {
        char *nm = get_cmpname(OBJ_sn2nid(key->tls_name), i);
        if (!nm) { ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING); return 0; }

        size_t priv_i = key->privkeylen_cmp[i];
        size_t pub_i  = (get_kmname_fromtls(nm) == 0) ? 0 : key->pubkeylen_cmp[i]; /* PQC mungkin include pubkey */

        need_priv += priv_i;
        need_pub  += pub_i;
        OPENSSL_free(nm);
    }

    /* jika public PQC inlined di priv, maka plen == need_priv + need_pub; jika tidak, plen == need_priv */
    if (need_priv != (size_t)plen) {
        pqc_pub_enc = 1;
        if (need_priv + need_pub != (size_t)plen) {
            ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING);
            return 0;
        }
        if (!kmx__ensure_material(key, /*pub*/1, /*priv*/0)) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }
    if (!kmx__ensure_material(key, /*pub*/0, /*priv*/1)) {
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    /* buffer sementara untuk merakit */
    unsigned char *tmp_priv = OPENSSL_secure_zalloc(need_priv ? need_priv : 1);
    unsigned char *tmp_pub  = OPENSSL_secure_zalloc(need_pub  ? need_pub  : 1);
    if (!tmp_priv || !tmp_pub) {
        OPENSSL_secure_clear_free(tmp_priv, need_priv);
        OPENSSL_secure_clear_free(tmp_pub,  need_pub);
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    /* salin potongan-potongan */
    for (i = 0; i < key->numkeys; i++) {
        char *nm = get_cmpname(OBJ_sn2nid(key->tls_name), i);
        if (!nm) { ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING); goto bad; }

        size_t priv_i, pub_i;
        if (get_kmname_fromtls(nm) == 0) {
            /* klasik: pub tidak inlined dalam priv → 0; raw RSA butuh panjang aktual (4 byte prefix) */
            if (key->kmx_provider_ctx.kmx_evp_ctx &&
                key->kmx_provider_ctx.kmx_evp_ctx->evp_info->keytype == EVP_PKEY_RSA) {
                if (acc_priv + acc_pub + 4 > (size_t)plen) { OPENSSL_free(nm); goto size_err; }
                unsigned char hdr[4];
                memcpy(hdr, p + acc_priv + acc_pub, 4);
                DECODE_UINT32(priv_i, hdr);
                priv_i += 4;
                if (priv_i > key->privkeylen_cmp[i]) { OPENSSL_free(nm); goto size_err; }
                key->privkeylen_cmp[i] = priv_i;
            } else {
                priv_i = key->privkeylen_cmp[i];
            }
            pub_i = 0;
        } else {
            /* PQC: pub bisa disertakan/dipisah */
            priv_i = key->privkeylen_cmp[i];
            pub_i  = pqc_pub_enc ? key->pubkeylen_cmp[i] : 0;
        }

        if (acc_priv + acc_pub + priv_i > (size_t)plen) { OPENSSL_free(nm); goto size_err; }

        memcpy(tmp_priv + acc_priv, p + acc_priv + acc_pub, priv_i);
        memcpy(tmp_pub  + acc_pub,  p + acc_priv + acc_pub + priv_i, pub_i);

        acc_priv += priv_i;
        acc_pub  += pub_i;
        OPENSSL_free(nm);
    }

    memcpy(key->privkey, tmp_priv, acc_priv);
    memcpy(key->pubkey,  tmp_pub,  acc_pub);

    OPENSSL_secure_clear_free(tmp_priv, need_priv);
    OPENSSL_secure_clear_free(tmp_pub,  need_pub);
    return 1;

size_err:
    ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING);
bad:
    OPENSSL_secure_clear_free(tmp_priv, need_priv);
    OPENSSL_secure_clear_free(tmp_pub,  need_pub);
    return 0;
}

/* ---------- fungsi utama ---------- */

static KMX_KEY *kmx_key_op(const X509_ALGOR *palg, const unsigned char *p,
                           int plen, kmx_key_op_t op, OSSL_LIB_CTX *libctx,
                           const char *propq)
{
    KMX_KEY *key = NULL;
    int nid = NID_undef;

    KM_KEY_PRINTF2("KMX KEY: key_op called with data of len %d\n", plen);

    /* Validasi parameter algoritma: harus tanpa parameter (UNDEF) */
    if (palg) {
        int ptype;
        X509_ALGOR_get0(NULL, &ptype, NULL, palg);
        if (ptype != V_ASN1_UNDEF || !palg->algorithm) {
            ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING);
            return NULL;
        }
        nid = OBJ_obj2nid(palg->algorithm);
    }
    if (!p || nid == EVP_PKEY_NONE || nid == NID_undef) {
        ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING);
        return NULL;
    }

    key = kmx_key_new_from_nid(libctx, propq, nid);
    if (!key) {
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    KM_KEY_PRINTF2("KMX KEY: Recreated KMX key %s\n", key->tls_name);

    /* === Jalur PUBLIC === */
    if (op == KEY_OP_PUBLIC) {
        if ((size_t)plen != key->pubkeylen) {
            ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING);
            goto fail;
        }
        if (!kmx__ensure_material(key, /*pub*/1, /*priv*/0)) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            goto fail;
        }
        memcpy(key->pubkey, p, plen);
    }
    /* === Jalur PRIVATE === */
    else {
        /* plain KM: priv||pub (atau hibrid/komposit: lihat cabang di bawah) */
        size_t actual_priv_len = key->privkeylen;

        if (key->keytype == KEY_TYPE_CMP_SIG) {
            if (!kmx__rebuild_composite_privpub(key, p, plen))
                goto fail;
        } else {
            /* Hybrid KEM/hybrid SIG dengan 2 komponen klasik+PQC */
            if (key->numkeys == 2) {
                size_t expected_pq_priv =
                    key->kmx_provider_ctx.kmx_qs_ctx.kem
                        ? key->kmx_provider_ctx.kmx_qs_ctx.kem->length_secret_key
                        : 0;
#ifndef NOPUBKEY_IN_PRIVKEY
                if (key->kmx_provider_ctx.kmx_qs_ctx.kem)
                    expected_pq_priv += key->kmx_provider_ctx.kmx_qs_ctx.kem->length_public_key;
#endif
                if (plen <= (int)(SIZE_OF_UINT32 + expected_pq_priv)) {
                    ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING);
                    goto fail;
                }

                size_t max_classic_priv = key->evp_info->length_private_key;
                size_t space_for_classic =
                    (size_t)plen - expected_pq_priv - SIZE_OF_UINT32;

                if (space_for_classic > max_classic_priv) {
                    ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING);
                    goto fail;
                }

                uint32_t classical_privatekey_len = 0;
                DECODE_UINT32(classical_privatekey_len, p);
                if (classical_privatekey_len != space_for_classic) {
                    ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING);
                    goto fail;
                }

                /* koreksi panjang actual priv (karena klasik mungkin < max) */
                actual_priv_len -= (key->evp_info->length_private_key - classical_privatekey_len);
            }

#ifdef NOPUBKEY_IN_PRIVKEY
            if ((size_t)plen != actual_priv_len) {
                KM_KEY_PRINTF3("KMX KEY: private key with unexpected length %d vs %d\n",
                               plen, (int)actual_priv_len);
                ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING);
                goto fail;
            }
            if (!kmx__ensure_material(key, /*pub*/0, /*priv*/1)) {
                ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
                goto fail;
            }
            memcpy(key->privkey, p, actual_priv_len);
#else
            if ((size_t)plen != actual_priv_len + (size_t)kmx_key_get_km_public_key_len(key)) {
                KM_KEY_PRINTF3("KMX KEY: private key with unexpected length %d vs %d\n",
                               plen, (int)(actual_priv_len + kmx_key_get_km_public_key_len(key)));
                ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING);
                goto fail;
            }
            if (!kmx__ensure_material(key, /*pub*/1, /*priv*/1)) {
                ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
                goto fail;
            }
            /* isi priv lebih dulu */
            memcpy(key->privkey, p, actual_priv_len);

            /* sisanya adalah KM public portion */
            if (key->numkeys == 2) {
                unsigned char *dst = (unsigned char *)key->pubkey;
                ENCODE_UINT32(dst, key->evp_info->length_public_key);
                if (key->reverse_share) {
                    memcpy(dst + SIZE_OF_UINT32,
                           p + actual_priv_len,
                           plen - (int)actual_priv_len);
                } else {
                    memcpy(dst + SIZE_OF_UINT32 + key->evp_info->length_public_key,
                           p + actual_priv_len,
                           plen - (int)actual_priv_len);
                }
            } else {
                memcpy(key->pubkey, p + key->privkeylen, plen - key->privkeylen);
            }
#endif
        }
    }

    /* Set offsets komposit & re-create classical EVP_PKEY */
    if (!kmx_key_set_composites(key, kmx__need_classic_fixed_lens(key)) ||
        !kmx_key_recreate_classickey(key, op)) {
        goto fail;
    }

    return key;

fail:
    kmx_key_free(key);
    return NULL;
}

/* ======== helpers privat untuk rekonstruksi klasik ======== */

static inline int kmx__is_cmp_sig(const KMX_KEY *k) {
    return k->keytype == KEY_TYPE_CMP_SIG;
}

static inline int kmx__has_raw_support(const KMX_KEY *k) {
    return k->kmx_provider_ctx.kmx_evp_ctx &&
           k->kmx_provider_ctx.kmx_evp_ctx->evp_info &&
           k->kmx_provider_ctx.kmx_evp_ctx->evp_info->raw_key_support;
}

static inline const KMX_EVP_INFO *kmx__evp_info(const KMX_KEY *k) {
    return k->kmx_provider_ctx.kmx_evp_ctx
               ? k->kmx_provider_ctx.kmx_evp_ctx->evp_info
               : k->evp_info;
}

/* Rekonstruksi EVP_PKEY publik klasik dari encoding DER/RAW */
static EVP_PKEY *kmx__load_classic_pub(const KMX_KEY *key,
                                       const unsigned char **enc,
                                       size_t enc_len) {
    const KMX_EVP_INFO *info = kmx__evp_info(key);
    if (!info) return NULL;

    if (info->raw_key_support) {
        return EVP_PKEY_new_raw_public_key(info->keytype, NULL, *enc, enc_len);
    } else {
        EVP_PKEY *npk = EVP_PKEY_new();
        if (info->keytype != EVP_PKEY_RSA) {
            npk = setECParams(npk, info->nid);
        }
        return d2i_PublicKey(info->keytype, &npk, enc, (long)enc_len);
    }
}

/* Rekonstruksi EVP_PKEY privat klasik dari encoding DER/RAW */
static EVP_PKEY *kmx__load_classic_priv(const KMX_KEY *key,
                                        const unsigned char **enc,
                                        size_t enc_len) {
    const KMX_EVP_INFO *info = kmx__evp_info(key);
    if (!info) return NULL;

    if (info->raw_key_support) {
        return EVP_PKEY_new_raw_private_key(info->keytype, NULL, *enc, enc_len);
    } else {
        return d2i_PrivateKey(info->keytype, NULL, enc, (long)enc_len);
    }
}

/* Tuliskan public DER/RAW hasil derive dari EVP_PKEY klasik ke buffer tujuan */
static int kmx__derive_pub_from_priv(const KMX_KEY *key,
                                     unsigned char **outbuf, size_t *outlen) {
    const KMX_EVP_INFO *info = kmx__evp_info(key);
    if (!info) return 0;

#ifndef NOPUBKEY_IN_PRIVKEY
    if (info->raw_key_support) {
        size_t n = info->length_public_key;
        if (EVP_PKEY_get_raw_public_key(key->classical_pkey, *outbuf, &n) != 1)
            return 0;
        *outlen = n;
        return 1;
    } else {
        int n = i2d_PublicKey(key->classical_pkey, outbuf);
        if (n != (int)info->length_public_key) return 0;
        *outlen = (size_t)n;
        return 1;
    }
#else
    (void)key; (void)outbuf; (void)outlen;
    return 1;
#endif
}

/* ======== implementasi utama ======== */

static int kmx_key_recreate_classickey(KMX_KEY *key, kmx_key_op_t op) {
    if (kmx__is_cmp_sig(key)) {
        /* COMPOSITE-SIG: iterasi setiap komponen */
        for (int i = 0; i < key->numkeys; i++) {
            char *nm = get_cmpname(OBJ_sn2nid(key->tls_name), i);
            if (!nm) { ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING); goto rec_err; }

            const int is_classic = (get_kmname_fromtls(nm) == 0);
            OPENSSL_free(nm);

            if (!is_classic) continue; /* PQC tak perlu EVP klasik */

            if (op == KEY_OP_PUBLIC) {
                const unsigned char *enc = key->comp_pubkey[i];
                key->classical_pkey = kmx__load_classic_pub(key, &enc, key->pubkeylen_cmp[i]);
                if (!key->classical_pkey) { ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING); goto rec_err; }
            } else if (op == KEY_OP_PRIVATE) {
                const unsigned char *enc = key->comp_privkey[i];
                key->classical_pkey = kmx__load_classic_priv(key, &enc, key->privkeylen_cmp[i]);
                if (!key->classical_pkey) { ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING); goto rec_err; }

#ifndef NOPUBKEY_IN_PRIVKEY
                /* derive & simpan pub klasik ke slot komponen publiknya */
                unsigned char *dst = key->comp_pubkey[i];
                size_t writ = 0;
                if (!kmx__derive_pub_from_priv(key, &dst, &writ)) {
                    ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING); goto rec_err;
                }
#endif
            }
        }
        return 1;
    }

    /* HYBRID (2 komponen): klasik + PQC */
    if (key->numkeys == 2) {
        int idx_classic;
        kmx_comp_set_idx(key, &idx_classic, NULL);

        const KMX_EVP_INFO *info = kmx__evp_info(key);
        if (!info) { ERR_raise(ERR_LIB_USER, KMPROV_R_EVPINFO_MISSING); goto rec_err; }

        if (op == KEY_OP_PUBLIC) {
            uint32_t classic_pub_len = 0;
            DECODE_UINT32(classic_pub_len, key->pubkey);
            if (classic_pub_len > info->length_public_key) {
                ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING); goto rec_err;
            }
            const unsigned char *enc = key->comp_pubkey[idx_classic];
            key->classical_pkey = kmx__load_classic_pub(key, &enc, classic_pub_len);
            if (!key->classical_pkey) { ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING); goto rec_err; }
        } else if (op == KEY_OP_PRIVATE) {
            uint32_t classic_priv_len = 0;
            DECODE_UINT32(classic_priv_len, key->privkey);
            if (classic_priv_len > info->length_private_key) {
                ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING); goto rec_err;
            }
            const unsigned char *enc_priv = key->comp_privkey[idx_classic];
            unsigned char       *enc_pub  = key->comp_pubkey[idx_classic];

            key->classical_pkey = kmx__load_classic_priv(key, &enc_priv, classic_priv_len);
            if (!key->classical_pkey) { ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING); goto rec_err; }

#ifndef NOPUBKEY_IN_PRIVKEY
            size_t publen = 0;
            if (!kmx__derive_pub_from_priv(key, &enc_pub, &publen) ||
                publen != info->length_public_key) {
                ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING); goto rec_err;
            }
#endif
        }
        return 1;
    }

    /* Kasus lain: tidak ada yang perlu direkonstruksi */
    return 1;

rec_err:
    return 0;
}

KMX_KEY *kmx_key_from_x509pubkey(const X509_PUBKEY *xpk,
                                 OSSL_LIB_CTX *libctx,
                                 const char *propq) {
    if (!xpk) return NULL;

    const unsigned char *der = NULL;
    int der_len = 0;
    X509_ALGOR *alg = NULL;
    KMX_KEY *out = NULL;

    if (!X509_PUBKEY_get0_param(NULL, &der, &der_len, &alg, xpk))
        return NULL;

    /* Untuk COMPOSITE-SIG, gabungkan ulang sequence jadi buffer datar */
    if (get_keytype(OBJ_obj2nid(alg->algorithm)) == KEY_TYPE_CMP_SIG) {
        STACK_OF(ASN1_TYPE) *seq = d2i_ASN1_SEQUENCE_ANY(NULL, &der, der_len);
        if (!seq) {
            sk_ASN1_TYPE_pop_free(seq, &ASN1_TYPE_free);
            ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING);
            return NULL;
        }

        const int n = sk_ASN1_TYPE_num(seq);
        unsigned char *joined = OPENSSL_zalloc(der_len);
        if (!joined) { sk_ASN1_TYPE_pop_free(seq, &ASN1_TYPE_free); return NULL; }

        int used = 0;
        for (int i = 0; i < n; i++) {
            ASN1_TYPE *t = sk_ASN1_TYPE_pop(seq); /* FILO → kita simpan mundur */
            const unsigned char *src = t->value.sequence->data;
            const int slen = t->value.sequence->length;
            used += slen;
            memcpy(joined + der_len - used, src, slen);
            ASN1_TYPE_free(t);
        }
        sk_ASN1_TYPE_free(seq);

        der = OPENSSL_memdup(joined + der_len - used, used);
        OPENSSL_clear_free(joined, der_len);
        der_len = used;
    }

    out = kmx_key_op(alg, der, der_len, KEY_OP_PUBLIC, libctx, propq);

    if (get_keytype(OBJ_obj2nid(alg->algorithm)) == KEY_TYPE_CMP_SIG) {
        OPENSSL_clear_free((unsigned char *)der, der_len);
    }
    return out;
}

KMX_KEY *kmx_key_from_pkcs8(const PKCS8_PRIV_KEY_INFO *p8inf,
                             OSSL_LIB_CTX *libctx,
                             const char *propq) {
    if (!p8inf) return NULL;

    const unsigned char *der = NULL;
    int der_len = 0;
    const X509_ALGOR *alg = NULL;
    ASN1_OCTET_STRING *oct = NULL;
    KMX_KEY *out = NULL;

    int key_diff = 0; /* koreksi untuk RSA encoded size */

    if (!PKCS8_pkey_get0(NULL, &der, &der_len, &alg, p8inf))
        return NULL;

    const int is_cmp = (get_keytype(OBJ_obj2nid(alg->algorithm)) == KEY_TYPE_CMP_SIG);

    if (!is_cmp) {
        /* kunci non-COMPOSITE tersimpan sebagai OCTET STRING */
        oct = d2i_ASN1_OCTET_STRING(NULL, &der, der_len);
        if (oct) {
            der     = ASN1_STRING_get0_data(oct);
            der_len = ASN1_STRING_length(oct);
        } else {
            der = NULL; der_len = 0;
        }
    } else {
        /* COMPOSITE-SIG: susun ulang semua inner PKCS8 jadi satu buffer */
        STACK_OF(ASN1_TYPE) *seq = d2i_ASN1_SEQUENCE_ANY(NULL, &der, der_len);
        if (!seq) {
            sk_ASN1_TYPE_pop_free(seq, &ASN1_TYPE_free);
            ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING);
            return NULL;
        }

        const int n = sk_ASN1_TYPE_num(seq);
        /* ambil ruang lebih (2x) untuk kemungkinan re-encode EC dengan param */
        int cap = der_len * 2;
        unsigned char *joined = OPENSSL_zalloc(cap);
        if (!joined) { sk_ASN1_TYPE_pop_free(seq, &ASN1_TYPE_free); return NULL; }

        int used = 0;
        for (int i = 0; i < n; i++) {
            ASN1_TYPE *t = sk_ASN1_TYPE_pop(seq);
            const unsigned char *inner_p = t->value.sequence->data;
            int inner_len = t->value.sequence->length;

            /* decode inner PKCS8 untuk cek tipe & perbaikan ukuran */
            PKCS8_PRIV_KEY_INFO *inner = NULL;
            inner = d2i_PKCS8_PRIV_KEY_INFO(&inner, &inner_p, inner_len);

            const X509_ALGOR *i_alg = NULL;
            const unsigned char *i_der = NULL;
            int i_len = 0;
            if (!PKCS8_pkey_get0(NULL, &i_der, &i_len, &i_alg, inner)) {
                ASN1_TYPE_free(t); PKCS8_PRIV_KEY_INFO_free(inner);
                OPENSSL_clear_free(joined, cap); sk_ASN1_TYPE_free(seq);
                return NULL;
            }

            int keytype = OBJ_obj2nid(i_alg->algorithm);

            /* EC: bila perlu, re-encode dengan public+group agar ukurannya fixed */
            int nid = 0;
            if (keytype == EVP_PKEY_EC) {
                nid = OBJ_obj2nid(i_alg->parameter->value.object);
                for (int j = 0; j < (int)OSSL_NELEM(nids_sig); j++) {
                    if (nids_sig[j].nid == nid &&
                        nids_sig[j].length_private_key > (size_t)i_len) {
                        /* re-encode: include EC params & public */
                        const unsigned char *raw = t->value.sequence->data;
                        EVP_PKEY *ecp = EVP_PKEY_new();
                        d2i_PrivateKey(EVP_PKEY_EC, &ecp, &raw, t->value.sequence->length);

                        int include_pub = 1;
                        OSSL_PARAM ps[3];
                        ps[0] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, &include_pub);
                        ps[1] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING,
                                                                 OSSL_PKEY_EC_ENCODING_GROUP, 0);
                        ps[2] = OSSL_PARAM_construct_end();
                        EVP_PKEY_set_params(ecp, ps);

                        unsigned char *buf = OPENSSL_malloc(nids_sig[j].length_private_key);
                        unsigned char *w   = buf;
                        int newlen = i2d_PrivateKey(ecp, &w);

                        used += newlen;
                        memcpy(joined + cap - used, buf, newlen);

                        OPENSSL_clear_free(buf, (size_t)newlen);
                        EVP_PKEY_free(ecp);
                        nid = -1; /* tandai sudah diproses */
                        break;
                    }
                }
            }

            /* RSA: ukuran encoding aktual mungkin < maksimal → simpan selisihnya */
            if (keytype == EVP_PKEY_RSA) {
                /* nama komponen (mis. p256_dilithium2 vs rsa3072_...) tak tersedia di sini
                   → pakai heuristik panjang: 3072 > 270 byte pub (lihat nids_sig) */
                /* mengacu kode lama: indeks 5 (rsa-3072) dan 6 (rsa-2048) */
                if (i_len > 300) key_diff = nids_sig[5].length_private_key - i_len; /* 3072 */
                else             key_diff = nids_sig[6].length_private_key - i_len; /* 2048 */
            }

            /* bila bukan kasus EC re-encode, salin apa adanya */
            if (nid != -1) {
                used += i_len;
                memcpy(joined + cap - used, i_der, i_len);
            }

            PKCS8_PRIV_KEY_INFO_free(inner);
            ASN1_TYPE_free(t);
        }

        sk_ASN1_TYPE_free(seq);

        der = OPENSSL_memdup(joined + cap - used, used);
        OPENSSL_clear_free(joined, cap);
        der_len = used;
    }

    out = kmx_key_op(alg, der, der_len + key_diff, KEY_OP_PRIVATE, libctx, propq);

    if (!is_cmp) {
        ASN1_OCTET_STRING_free(oct);
    } else {
        OPENSSL_clear_free((unsigned char *)der, der_len);
    }
    return out;
}


static const int (*init_kex_fun[])(char *, KMX_EVP_CTX *) = {
    kmhybkem_init_ecp, kmhybkem_init_ecx};
extern const char *km_oid_alg_list[];

KMX_KEY *kmx_key_new(OSSL_LIB_CTX *libctx, char *km_name, char *tls_name,
                       int primitive, const char *propq, int bit_security,
                       int alg_idx, int reverse_share) {
    KMX_KEY *ret =
        OPENSSL_zalloc(sizeof(*ret)); // ensure all component pointers are NULL
    KMX_EVP_CTX *evp_ctx = NULL;
    int ret2 = 0, i;

    if (ret == NULL)
        goto err;

#ifdef KM_PROVIDER_NOATOMIC
    ret->lock = CRYPTO_THREAD_lock_new();
    ON_ERR_GOTO(!ret->lock, err);
#endif

    if (km_name == NULL) {
        KM_KEY_PRINTF("KMX_KEY: Fatal error: No KM key name provided:\n");
        goto err;
    }

    if (tls_name == NULL) {
        KM_KEY_PRINTF("KMX_KEY: Fatal error: No TLS key name provided:\n");
        goto err;
    }

    switch (primitive) {
    case KEY_TYPE_SIG:
        ret->numkeys = 1;
        ret->comp_privkey = OPENSSL_malloc(sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(sizeof(void *));
        ON_ERR_GOTO(!ret->comp_privkey || !ret->comp_pubkey, err);
        ret->kmx_provider_ctx.kmx_evp_ctx = NULL;
        ret->kmx_provider_ctx.kmx_qs_ctx.sig = OQS_SIG_new(km_name);
        if (!ret->kmx_provider_ctx.kmx_qs_ctx.sig) {
            fprintf(stderr,
                    "Could not create KM signature algorithm %s. "
                    "Enabled in "
                    "liboqs?\n",
                    km_name);
            goto err;
        }

        ret->privkeylen =
            ret->kmx_provider_ctx.kmx_qs_ctx.sig->length_secret_key;
        ret->pubkeylen =
            ret->kmx_provider_ctx.kmx_qs_ctx.sig->length_public_key;
        ret->keytype = KEY_TYPE_SIG;
        break;
    case KEY_TYPE_KEM:
        ret->numkeys = 1;
        ret->comp_privkey = OPENSSL_malloc(sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(sizeof(void *));
        ON_ERR_GOTO(!ret->comp_privkey || !ret->comp_pubkey, err);
        ret->kmx_provider_ctx.kmx_evp_ctx = NULL;
        ret->kmx_provider_ctx.kmx_qs_ctx.kem = OQS_KEM_new(km_name);
        if (!ret->kmx_provider_ctx.kmx_qs_ctx.kem) {
            fprintf(stderr,
                    "Could not create KM KEM algorithm %s. Enabled "
                    "in liboqs?\n",
                    km_name);
            goto err;
        }
        ret->privkeylen =
            ret->kmx_provider_ctx.kmx_qs_ctx.kem->length_secret_key;
        ret->pubkeylen =
            ret->kmx_provider_ctx.kmx_qs_ctx.kem->length_public_key;
        ret->keytype = KEY_TYPE_KEM;
        break;
    case KEY_TYPE_ECX_HYB_KEM:
    case KEY_TYPE_ECP_HYB_KEM:
        ret->reverse_share = reverse_share;
        ret->kmx_provider_ctx.kmx_qs_ctx.kem = OQS_KEM_new(km_name);
        if (!ret->kmx_provider_ctx.kmx_qs_ctx.kem) {
            fprintf(stderr,
                    "Could not create KM KEM algorithm %s. Enabled "
                    "in liboqs?\n",
                    km_name);
            goto err;
        }
        evp_ctx = OPENSSL_zalloc(sizeof(KMX_EVP_CTX));
        ON_ERR_GOTO(!evp_ctx, err);

        ret2 =
            (init_kex_fun[primitive - KEY_TYPE_ECP_HYB_KEM])(tls_name, evp_ctx);
        ON_ERR_GOTO(ret2 <= 0 || !evp_ctx->keyParam || !evp_ctx->ctx, err);

        ret->numkeys = 2;
        ret->comp_privkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
        ON_ERR_GOTO(!ret->comp_privkey || !ret->comp_pubkey, err);
        ret->privkeylen =
            (ret->numkeys - 1) * SIZE_OF_UINT32 +
            ret->kmx_provider_ctx.kmx_qs_ctx.kem->length_secret_key +
            evp_ctx->evp_info->length_private_key;
        ret->pubkeylen =
            (ret->numkeys - 1) * SIZE_OF_UINT32 +
            ret->kmx_provider_ctx.kmx_qs_ctx.kem->length_public_key +
            evp_ctx->evp_info->length_public_key;
        ret->kmx_provider_ctx.kmx_evp_ctx = evp_ctx;
        ret->keytype = primitive;
        ret->evp_info = evp_ctx->evp_info;
        break;
    case KEY_TYPE_HYB_SIG:
        ret->kmx_provider_ctx.kmx_qs_ctx.sig = OQS_SIG_new(km_name);
        if (!ret->kmx_provider_ctx.kmx_qs_ctx.sig) {
            fprintf(stderr,
                    "Could not create KM signature algorithm %s. "
                    "Enabled in "
                    "liboqs?\n",
                    km_name);
            goto err;
        }
        evp_ctx = OPENSSL_zalloc(sizeof(KMX_EVP_CTX));
        ON_ERR_GOTO(!evp_ctx, err);

        ret2 = kmx_hybsig_init(bit_security, evp_ctx, tls_name);
        ON_ERR_GOTO(ret2 <= 0 || !evp_ctx->ctx, err);

        ret->numkeys = 2;
        ret->comp_privkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
        ON_ERR_GOTO(!ret->comp_privkey || !ret->comp_pubkey, err);
        ret->privkeylen =
            (ret->numkeys - 1) * SIZE_OF_UINT32 +
            ret->kmx_provider_ctx.kmx_qs_ctx.sig->length_secret_key +
            evp_ctx->evp_info->length_private_key;
        ret->pubkeylen =
            (ret->numkeys - 1) * SIZE_OF_UINT32 +
            ret->kmx_provider_ctx.kmx_qs_ctx.sig->length_public_key +
            evp_ctx->evp_info->length_public_key;
        ret->kmx_provider_ctx.kmx_evp_ctx = evp_ctx;
        ret->keytype = primitive;
        ret->evp_info = evp_ctx->evp_info;
        break;
    case KEY_TYPE_CMP_SIG:
        ret->numkeys = 2;
        ret->privkeylen = 0;
        ret->pubkeylen = 0;
        ret->privkeylen_cmp = OPENSSL_malloc(ret->numkeys * sizeof(size_t));
        ret->pubkeylen_cmp = OPENSSL_malloc(ret->numkeys * sizeof(size_t));
        ret->comp_privkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));

        for (i = 0; i < ret->numkeys; i++) {
            char *name;
            if ((name = get_cmpname(OBJ_sn2nid(tls_name), i)) == NULL) {
                ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING);
                goto err;
            }
            if (get_kmname_fromtls(name) != 0) {
                ret->kmx_provider_ctx.kmx_qs_ctx.sig =
                    OQS_SIG_new(get_kmname_fromtls(name));
                if (!ret->kmx_provider_ctx.kmx_qs_ctx.sig) {
                    fprintf(stderr,
                            "Could not create KM signature "
                            "algorithm %s. "
                            "Enabled in "
                            "liboqs?A\n",
                            name);
                    goto err;
                }
                ret->privkeylen_cmp[i] =
                    ret->kmx_provider_ctx.kmx_qs_ctx.sig->length_secret_key;
                ret->pubkeylen_cmp[i] =
                    ret->kmx_provider_ctx.kmx_qs_ctx.sig->length_public_key;
            } else {
                evp_ctx = OPENSSL_zalloc(sizeof(KMX_EVP_CTX));
                ON_ERR_GOTO(!evp_ctx, err);

                ret2 = kmx_hybsig_init(bit_security, evp_ctx, name);
                ON_ERR_GOTO(ret2 <= 0 || !evp_ctx->ctx, err);
                ret->kmx_provider_ctx.kmx_evp_ctx = evp_ctx;
                ret->privkeylen_cmp[i] = ret->kmx_provider_ctx.kmx_evp_ctx
                                             ->evp_info->length_private_key;
                ret->pubkeylen_cmp[i] = ret->kmx_provider_ctx.kmx_evp_ctx
                                            ->evp_info->length_public_key;
            }
            ret->privkeylen += ret->privkeylen_cmp[i];
            ret->pubkeylen += ret->pubkeylen_cmp[i];
            OPENSSL_free(name);
        }
        ret->keytype = primitive;

        break;
    default:
        KM_KEY_PRINTF2("KMX_KEY: Unknown key type encountered: %d\n",
                        primitive);
        goto err;
    }

    ret->libctx = libctx;
    ret->references = 1;
    ret->tls_name = OPENSSL_strdup(tls_name);
    ON_ERR_GOTO(!ret->tls_name, err);
    ret->bit_security = bit_security;

    if (propq != NULL) {
        ret->propq = OPENSSL_strdup(propq);
        ON_ERR_GOTO(!ret->propq, err);
    }

    KM_KEY_PRINTF2("KMX_KEY: new key created: %s\n", ret->tls_name);
    KM_KEY_PRINTF3("KMX_KEY: new key created: %p (type: %d)\n", ret,
                    ret->keytype);
    return ret;
err:
    ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
#ifdef KM_PROVIDER_NOATOMIC
    if (ret->lock)
        CRYPTO_THREAD_lock_free(ret->lock);
#endif
    if (ret) {
        OPENSSL_free(ret->tls_name);
        OPENSSL_free(ret->propq);
        OPENSSL_free(ret->comp_privkey);
        OPENSSL_free(ret->comp_pubkey);
    }
    OPENSSL_free(ret);
    return NULL;
}

void kmx_key_free(KMX_KEY *key) {
    int refcnt;
    if (key == NULL)
        return;

#ifndef KM_PROVIDER_NOATOMIC
    refcnt =
        atomic_fetch_sub_explicit(&key->references, 1, memory_order_relaxed) -
        1;
    if (refcnt == 0)
        atomic_thread_fence(memory_order_acquire);
#else
    CRYPTO_atomic_add(&key->references, -1, &refcnt, key->lock);
#endif

    KM_KEY_PRINTF3("%p:%4d:KMX_KEY\n", (void *)key, refcnt);
    if (refcnt > 0)
        return;
#ifndef NDEBUG
    assert(refcnt == 0);
#endif

    OPENSSL_free(key->propq);
    OPENSSL_free(key->tls_name);
    OPENSSL_secure_clear_free(key->privkey, key->privkeylen);
    OPENSSL_secure_clear_free(key->pubkey, key->pubkeylen);
    OPENSSL_free(key->comp_pubkey);
    OPENSSL_free(key->comp_privkey);
    if (key->keytype == KEY_TYPE_CMP_SIG) {
        OPENSSL_free(key->privkeylen_cmp);
        OPENSSL_free(key->pubkeylen_cmp);
    }
    if (key->keytype == KEY_TYPE_KEM)
        OQS_KEM_free(key->kmx_provider_ctx.kmx_qs_ctx.kem);
    else if (key->keytype == KEY_TYPE_ECP_HYB_KEM ||
             key->keytype == KEY_TYPE_ECX_HYB_KEM) {
        OQS_KEM_free(key->kmx_provider_ctx.kmx_qs_ctx.kem);
    } else
        OQS_SIG_free(key->kmx_provider_ctx.kmx_qs_ctx.sig);
    EVP_PKEY_free(key->classical_pkey);
    if (key->kmx_provider_ctx.kmx_evp_ctx) {
        EVP_PKEY_CTX_free(key->kmx_provider_ctx.kmx_evp_ctx->ctx);
        EVP_PKEY_free(key->kmx_provider_ctx.kmx_evp_ctx->keyParam);
        OPENSSL_free(key->kmx_provider_ctx.kmx_evp_ctx);
    }

#ifdef KM_PROVIDER_NOATOMIC
    CRYPTO_THREAD_lock_free(key->lock);
#endif
    OPENSSL_free(key);
}

int kmx_key_up_ref(KMX_KEY *key) {
    int refcnt;

#ifndef KM_PROVIDER_NOATOMIC
    refcnt =
        atomic_fetch_add_explicit(&key->references, 1, memory_order_relaxed) +
        1;
#else
    CRYPTO_atomic_add(&key->references, 1, &refcnt, key->lock);
#endif

    KM_KEY_PRINTF3("%p:%4d:KMX_KEY\n", (void *)key, refcnt);
#ifndef NDEBUG
    assert(refcnt > 1);
#endif
    return (refcnt > 1);
}

int kmx_key_allocate_keymaterial(KMX_KEY *key, int include_private) {
    int ret = 0, aux = 0;

    if (key->keytype != KEY_TYPE_CMP_SIG)
        aux = SIZE_OF_UINT32;

    if (!key->privkey && include_private) {
        key->privkey = OPENSSL_secure_zalloc(key->privkeylen + aux);
        ON_ERR_SET_GOTO(!key->privkey, ret, 1, err_alloc);
    }
    if (!key->pubkey && !include_private) {
        key->pubkey = OPENSSL_secure_zalloc(key->pubkeylen);
        ON_ERR_SET_GOTO(!key->pubkey, ret, 1, err_alloc);
    }
err_alloc:
    return ret;
}

int kmx_key_fromdata(KMX_KEY *key, const OSSL_PARAM params[],
                      int include_private) {
    const OSSL_PARAM *pp1, *pp2;

    int classic_lengths_fixed = key->keytype == KEY_TYPE_ECP_HYB_KEM ||
                                key->keytype == KEY_TYPE_ECX_HYB_KEM;

    KM_KEY_PRINTF("KMX Key from data called\n");
    pp1 = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    pp2 = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    // at least one parameter must be given
    if (pp1 == NULL && pp2 == NULL) {
        ERR_raise(ERR_LIB_USER, KMPROV_R_WRONG_PARAMETERS);
        return 0;
    }
    if (pp1 != NULL) {
        if (pp1->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_ENCODING);
            return 0;
        }
        if (key->privkeylen != pp1->data_size) {
            ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_SIZE);
            return 0;
        }
        OPENSSL_secure_clear_free(key->privkey, pp1->data_size);
        key->privkey = OPENSSL_secure_malloc(pp1->data_size);
        if (key->privkey == NULL) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        memcpy(key->privkey, pp1->data, pp1->data_size);
    }
    if (pp2 != NULL) {
        if (pp2->data_type != OSSL_PARAM_OCTET_STRING) {
            KM_KEY_PRINTF("invalid data type\n");
            return 0;
        }
        if (key->pubkeylen != pp2->data_size) {
            ERR_raise(ERR_LIB_USER, KMPROV_R_INVALID_SIZE);
            return 0;
        }
        OPENSSL_secure_clear_free(key->pubkey, pp2->data_size);
        key->pubkey = OPENSSL_secure_malloc(pp2->data_size);
        if (key->pubkey == NULL) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        memcpy(key->pubkey, pp2->data, pp2->data_size);
    }
    if (!kmx_key_set_composites(key, classic_lengths_fixed) ||
        !kmx_key_recreate_classickey(
            key, key->privkey != NULL ? KEY_OP_PRIVATE : KEY_OP_PUBLIC))
        return 0;
    return 1;
}

// KM key always the last of the numkeys comp keys
static int kmx_key_gen_km(KMX_KEY *key, int gen_kem) {
    int idx_pq;
    kmx_comp_set_idx(key, NULL, &idx_pq);

    if (gen_kem)
        return OQS_KEM_keypair(key->kmx_provider_ctx.kmx_qs_ctx.kem,
                               key->comp_pubkey[idx_pq],
                               key->comp_privkey[idx_pq]);
    else {
        return OQS_SIG_keypair(key->kmx_provider_ctx.kmx_qs_ctx.sig,
                               key->comp_pubkey[idx_pq],
                               key->comp_privkey[idx_pq]);
    }
}

/* Generate classic keys, store length in leading SIZE_OF_UINT32 bytes of
 * pubkey/privkey buffers; returned EVP_PKEY must be freed if not used
 */
static EVP_PKEY *kmx_key_gen_evp_key_sig(KMX_EVP_CTX *ctx,
                                          unsigned char *pubkey,
                                          unsigned char *privkey, int encode) {
    int ret = 0, ret2 = 0, aux = 0;

    // Free at errhyb:
    EVP_PKEY_CTX *kgctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *pubkey_encoded = NULL;

    size_t pubkeylen = 0, privkeylen = 0;

    if (encode) { // hybrid
        aux = SIZE_OF_UINT32;
    }

    if (ctx->keyParam)
        kgctx = EVP_PKEY_CTX_new(ctx->keyParam, NULL);
    else
        kgctx = EVP_PKEY_CTX_new_id(ctx->evp_info->nid, NULL);
    ON_ERR_SET_GOTO(!kgctx, ret, -1, errhyb);

    ret2 = EVP_PKEY_keygen_init(kgctx);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -1, errhyb);
    if (ctx->evp_info->keytype == EVP_PKEY_RSA) {
        if (ctx->evp_info->length_public_key > 270) {
            ret2 = EVP_PKEY_CTX_set_rsa_keygen_bits(kgctx, 3072);
        } else {
            ret2 = EVP_PKEY_CTX_set_rsa_keygen_bits(kgctx, 2048);
        }
        ON_ERR_SET_GOTO(ret2 <= 0, ret, -1, errhyb);
    }

    ret2 = EVP_PKEY_keygen(kgctx, &pkey);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -2, errhyb);

    if (ctx->evp_info->raw_key_support) {
        // TODO: If available, use preallocated memory
        if (ctx->evp_info->nid != NID_ED25519 &&
            ctx->evp_info->nid != NID_ED448) {
            pubkeylen = EVP_PKEY_get1_encoded_public_key(pkey, &pubkey_encoded);
            ON_ERR_SET_GOTO(pubkeylen != ctx->evp_info->length_public_key ||
                                !pubkey_encoded,
                            ret, -3, errhyb);
            memcpy(pubkey + aux, pubkey_encoded, pubkeylen);
        } else {
            pubkeylen = ctx->evp_info->length_public_key;
            ret2 = EVP_PKEY_get_raw_public_key(pkey, pubkey + aux, &pubkeylen);
            ON_ERR_SET_GOTO(ret2 <= 0 ||
                                pubkeylen != ctx->evp_info->length_public_key,
                            ret, -3, errhyb);
        }
        privkeylen = ctx->evp_info->length_private_key;
        ret2 = EVP_PKEY_get_raw_private_key(pkey, privkey + aux, &privkeylen);
        ON_ERR_SET_GOTO(ret2 <= 0 ||
                            privkeylen != ctx->evp_info->length_private_key,
                        ret, -4, errhyb);
    } else {
        unsigned char *pubkey_enc = pubkey + aux;
        const unsigned char *pubkey_enc2 = pubkey + aux;
        pubkeylen = i2d_PublicKey(pkey, &pubkey_enc);
        ON_ERR_SET_GOTO(!pubkey_enc ||
                            pubkeylen > (int)ctx->evp_info->length_public_key,
                        ret, -11, errhyb);
        unsigned char *privkey_enc = privkey + aux;
        const unsigned char *privkey_enc2 = privkey + aux;
        privkeylen = i2d_PrivateKey(pkey, &privkey_enc);
        ON_ERR_SET_GOTO(!privkey_enc ||
                            privkeylen > (int)ctx->evp_info->length_private_key,
                        ret, -12, errhyb);
        // selftest:
        EVP_PKEY *ck2 = d2i_PrivateKey(ctx->evp_info->keytype, NULL,
                                       &privkey_enc2, privkeylen);
        ON_ERR_SET_GOTO(!ck2, ret, -14, errhyb);
        EVP_PKEY_free(ck2);
    }
    if (encode) {
        ENCODE_UINT32(pubkey, pubkeylen);
        ENCODE_UINT32(privkey, privkeylen);
    }
    KM_KEY_PRINTF3(
        "KMKM: Storing classical privkeylen: %ld & pubkeylen: %ld\n",
        privkeylen, pubkeylen);

    EVP_PKEY_CTX_free(kgctx);
    OPENSSL_free(pubkey_encoded);
    return pkey;

errhyb:
    EVP_PKEY_CTX_free(kgctx);
    EVP_PKEY_free(pkey);
    OPENSSL_free(pubkey_encoded);
    return NULL;
}

/* Generate classic keys, store length in leading SIZE_OF_UINT32 bytes of
 * pubkey/privkey buffers; returned EVP_PKEY must be freed if not used
 */
static EVP_PKEY *kmx_key_gen_evp_key_kem(KMX_KEY *key, unsigned char *pubkey,
                                          unsigned char *privkey, int encode) {
    int ret = 0, ret2 = 0, aux = 0;

    // Free at errhyb:
    EVP_PKEY_CTX *kgctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *pubkey_encoded = NULL;
    int idx_classic;
    KMX_EVP_CTX *ctx = key->kmx_provider_ctx.kmx_evp_ctx;

    size_t pubkeylen = 0, privkeylen = 0;

    unsigned char *pubkey_sizeenc = key->pubkey;
    unsigned char *privkey_sizeenc = key->privkey;

    if (ctx->keyParam)
        kgctx = EVP_PKEY_CTX_new(ctx->keyParam, NULL);
    else
        kgctx = EVP_PKEY_CTX_new_id(ctx->evp_info->nid, NULL);
    ON_ERR_SET_GOTO(!kgctx, ret, -1, errhyb);

    ret2 = EVP_PKEY_keygen_init(kgctx);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -1, errhyb);

    ret2 = EVP_PKEY_keygen(kgctx, &pkey);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -2, errhyb);

    if (ctx->evp_info->raw_key_support) {
        // TODO: If available, use preallocated memory
        if (ctx->evp_info->nid != NID_ED25519 &&
            ctx->evp_info->nid != NID_ED448) {
            pubkeylen = EVP_PKEY_get1_encoded_public_key(pkey, &pubkey_encoded);
            ON_ERR_SET_GOTO(pubkeylen != ctx->evp_info->length_public_key ||
                                !pubkey_encoded,
                            ret, -3, errhyb);
            memcpy(pubkey + aux, pubkey_encoded, pubkeylen);
        } else {
            pubkeylen = ctx->evp_info->length_public_key;
            ret2 = EVP_PKEY_get_raw_public_key(pkey, pubkey + aux, &pubkeylen);
            ON_ERR_SET_GOTO(ret2 <= 0 ||
                                pubkeylen != ctx->evp_info->length_public_key,
                            ret, -3, errhyb);
        }
        privkeylen = ctx->evp_info->length_private_key;
        ret2 = EVP_PKEY_get_raw_private_key(pkey, privkey + aux, &privkeylen);
        ON_ERR_SET_GOTO(ret2 <= 0 ||
                            privkeylen != ctx->evp_info->length_private_key,
                        ret, -4, errhyb);
    } else {
        unsigned char *pubkey_enc = pubkey + aux;
        const unsigned char *pubkey_enc2 = pubkey + aux;
        pubkeylen = i2d_PublicKey(pkey, &pubkey_enc);
        ON_ERR_SET_GOTO(!pubkey_enc ||
                            pubkeylen > (int)ctx->evp_info->length_public_key,
                        ret, -11, errhyb);
        unsigned char *privkey_enc = privkey + aux;
        const unsigned char *privkey_enc2 = privkey + aux;
        privkeylen = i2d_PrivateKey(pkey, &privkey_enc);
        ON_ERR_SET_GOTO(!privkey_enc ||
                            privkeylen > (int)ctx->evp_info->length_private_key,
                        ret, -12, errhyb);
        // selftest:
        EVP_PKEY *ck2 = d2i_PrivateKey(ctx->evp_info->keytype, NULL,
                                       &privkey_enc2, privkeylen);
        ON_ERR_SET_GOTO(!ck2, ret, -14, errhyb);
        EVP_PKEY_free(ck2);
    }
    if (encode) {
        ENCODE_UINT32(pubkey_sizeenc, pubkeylen);
        ENCODE_UINT32(privkey_sizeenc, privkeylen);
    }
    KM_KEY_PRINTF3(
        "KMKM: Storing classical privkeylen: %ld & pubkeylen: %ld\n",
        privkeylen, pubkeylen);

    EVP_PKEY_CTX_free(kgctx);
    OPENSSL_free(pubkey_encoded);
    return pkey;

errhyb:
    EVP_PKEY_CTX_free(kgctx);
    EVP_PKEY_free(pkey);
    OPENSSL_free(pubkey_encoded);
    return NULL;
}

/* allocates KM and classical keys */
int kmx_key_gen(KMX_KEY *key) {
    int ret = 0;
    EVP_PKEY *pkey = NULL;

    if (key->privkey == NULL || key->pubkey == NULL) {
        ret = kmx_key_allocate_keymaterial(key, 0) ||
              kmx_key_allocate_keymaterial(key, 1);
        ON_ERR_GOTO(ret, err_gen);
    }

    if (key->keytype == KEY_TYPE_KEM) {
        ret = !kmx_key_set_composites(key, 0);
        ON_ERR_GOTO(ret, err_gen);
        ret = kmx_key_gen_km(key, 1);
    } else if (key->keytype == KEY_TYPE_HYB_SIG) {
        pkey = kmx_key_gen_evp_key_sig(key->kmx_provider_ctx.kmx_evp_ctx,
                                        key->pubkey, key->privkey, 1);
        ON_ERR_GOTO(pkey == NULL, err_gen);
        ret = !kmx_key_set_composites(key, 0);
        ON_ERR_GOTO(ret, err_gen);
        KM_KEY_PRINTF3("KMKM: KMX_KEY privkeylen %ld & pubkeylen: %ld\n",
                        key->privkeylen, key->pubkeylen);

        key->classical_pkey = pkey;
        ret = kmx_key_gen_km(key, key->keytype != KEY_TYPE_HYB_SIG);
    } else if (key->keytype == KEY_TYPE_ECP_HYB_KEM ||
               key->keytype == KEY_TYPE_ECX_HYB_KEM) {
        int idx_classic;
        kmx_comp_set_idx(key, &idx_classic, NULL);

        ret = !kmx_key_set_composites(key, 1);
        ON_ERR_GOTO(ret != 0, err_gen);

        pkey = kmx_key_gen_evp_key_kem(key, key->comp_pubkey[idx_classic],
                                        key->comp_privkey[idx_classic], 1);
        ON_ERR_GOTO(pkey == NULL, err_gen);

        KM_KEY_PRINTF3("KMKM: KMX_KEY privkeylen %ld & pubkeylen: %ld\n",
                        key->privkeylen, key->pubkeylen);

        key->classical_pkey = pkey;
        ret = kmx_key_gen_km(key, key->keytype != KEY_TYPE_HYB_SIG);
    } else if (key->keytype == KEY_TYPE_CMP_SIG) {
        int i;
        ret = kmx_key_set_composites(key, 0);
        for (i = 0; i < key->numkeys; i++) {
            char *name;
            if ((name = get_cmpname(OBJ_sn2nid(key->tls_name), i)) == NULL) {
                ON_ERR_GOTO(ret, err_gen);
            }
            if (get_kmname_fromtls(name) == 0) {
                pkey = kmx_key_gen_evp_key_sig(
                    key->kmx_provider_ctx.kmx_evp_ctx, key->comp_pubkey[i],
                    key->comp_privkey[i], 0);
                OPENSSL_free(name);
                ON_ERR_GOTO(pkey == NULL, err_gen);
                key->classical_pkey = pkey;
            } else {
                ret =
                    OQS_SIG_keypair(key->kmx_provider_ctx.kmx_qs_ctx.sig,
                                    key->comp_pubkey[i], key->comp_privkey[i]);
                OPENSSL_free(name);
                ON_ERR_GOTO(ret, err_gen);
            }
        }
    } else if (key->keytype == KEY_TYPE_SIG) {
        ret = !kmx_key_set_composites(key, 0);
        ON_ERR_GOTO(ret, err_gen);
        ret = kmx_key_gen_km(key, 0);
    } else {
        ret = 1;
    }
err_gen:
    if (ret) {
        EVP_PKEY_free(pkey);
        key->classical_pkey = NULL;
    }
    return ret;
}

int kmx_key_secbits(KMX_KEY *key) { return key->bit_security; }

int kmx_key_maxsize(KMX_KEY *key) {
    switch (key->keytype) {
    case KEY_TYPE_KEM:
        return key->kmx_provider_ctx.kmx_qs_ctx.kem->length_shared_secret;
    case KEY_TYPE_ECP_HYB_KEM:
    case KEY_TYPE_ECX_HYB_KEM:
        return key->kmx_provider_ctx.kmx_evp_ctx->evp_info
                   ->kex_length_secret +
               key->kmx_provider_ctx.kmx_qs_ctx.kem->length_shared_secret;
    case KEY_TYPE_SIG:
        return key->kmx_provider_ctx.kmx_qs_ctx.sig->length_signature;
    case KEY_TYPE_HYB_SIG:
        return key->kmx_provider_ctx.kmx_qs_ctx.sig->length_signature +
               key->kmx_provider_ctx.kmx_evp_ctx->evp_info->length_signature +
               SIZE_OF_UINT32;
    case KEY_TYPE_CMP_SIG:
        return sizeof(CompositeSignature) +
               key->kmx_provider_ctx.kmx_evp_ctx->evp_info->length_signature +
               key->kmx_provider_ctx.kmx_qs_ctx.sig->length_signature;

    default:
        KM_KEY_PRINTF("KMX KEY: Wrong key type\n");
        return 0;
    }
}

int kmx_key_get_km_public_key_len(KMX_KEY *k) {
    switch (k->keytype) {
    case KEY_TYPE_SIG:
    case KEY_TYPE_KEM:
        return k->pubkeylen;
    case KEY_TYPE_HYB_SIG:
        return k->kmx_provider_ctx.kmx_qs_ctx.sig->length_public_key;
    case KEY_TYPE_ECX_HYB_KEM:
    case KEY_TYPE_ECP_HYB_KEM:
        return k->kmx_provider_ctx.kmx_qs_ctx.kem->length_public_key;
    default:
        KM_KEY_PRINTF2("KMX_KEY: Unknown key type encountered: %d\n",
                        k->keytype);
        return -1;
    }
}
