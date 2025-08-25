// src/dec_raw.c
#include "km_provider.h"
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/evp.h>
#include <openssl/decoder.h>
#include <openssl/core_object.h>
#include <openssl/pem.h> // Pastikan ini ada
#include <ctype.h>
#include <string.h>
#include <stdio.h>

/* Beberapa versi header pakai nama param yang sama, jaga-jaga */
#ifndef OSSL_DECODER_PARAM_INPUT_TYPE
#  define OSSL_DECODER_PARAM_INPUT_TYPE "input-type"
#endif

/* ---------- Context ---------- */
typedef struct {
    KM_PROVCTX *provctx;
} KM_DEC_CTX;

static void *km_dec_newctx(void *vprovctx) {
    KM_DEC_CTX *c = OPENSSL_zalloc(sizeof(*c));
    if (!c) return NULL;
    c->provctx = (KM_PROVCTX*)vprovctx;
    return c;
}
static void km_dec_freectx(void *v) { OPENSSL_free(v); }

/* Jangan terlalu ketat di sini: always-on supaya tidak terfilter */
// static int km_dec_does_selection(void *v, int selection) {
//     (void)v; (void)selection;
//     return 1;
// }
static int km_dec_does_selection(void *vctx, int selection) {
    (void)vctx;
    int ok = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
    fprintf(stderr, "[decoder] does_selection sel=0x%x -> %d\n", selection, ok);
    return ok;
}



/* ---------- Util: parse PEM ---------- */
static int parse_pem(const char *txt, size_t len,
                     char *label_out, size_t lsz,
                     unsigned char **data_out, size_t *dlen_out,
                     int *is_priv)
{
    const char *p = strstr(txt, "-----BEGIN ");
    if (!p) return 0;
    p += strlen("-----BEGIN ");
    const char *hdr_end = strstr(p, "-----");
    if (!hdr_end) return 0;

    size_t labellen = (size_t)(hdr_end - p);
    if (labellen == 0 || labellen >= lsz) return 0;
    memcpy(label_out, p, labellen);
    label_out[labellen] = '\0';

    /* Loncat ke akhir baris header */
    const char *body = strchr(hdr_end, '\n');
    if (!body) return 0;
    body++;

    /* Cari footer yang cocok persis */
    size_t need = strlen("-----END ") + labellen + strlen("-----") + 1;
    char *endline = OPENSSL_malloc(need);
    if (!endline) return 0;
    int n = snprintf(endline, need, "-----END %s-----", label_out);
    if (n < 0 || (size_t)n >= need) { OPENSSL_free(endline); return 0; }

    const char *footer = strstr(body, endline);
    OPENSSL_free(endline);
    if (!footer) return 0;

    /* Kumpulkan base64 (hapus \r\n spasi tab) */
    size_t b64cap = (size_t)(footer - body);
    unsigned char *b64 = OPENSSL_malloc(b64cap + 1);
    if (!b64) return 0;

    size_t b64len = 0;
    for (const char *q = body; q < footer; q++) {
        unsigned char c = (unsigned char)*q;
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        b64[b64len++] = c;
    }
    b64[b64len] = 0;

    /* Base64 decode */
    size_t outcap = 3 * (b64len / 4) + 4;
    unsigned char *out = OPENSSL_malloc(outcap);
    if (!out) { OPENSSL_free(b64); return 0; }

    int dec = EVP_DecodeBlock(out, b64, (int)b64len);
    if (dec < 0) { OPENSSL_free(out); OPENSSL_free(b64); return 0; }

    /* padding '=' */
    int pad = 0;
    if (b64len >= 1 && b64[b64len - 1] == '=') pad++;
    if (b64len >= 2 && b64[b64len - 2] == '=') pad++;
    OPENSSL_free(b64);

    size_t dlen = (size_t)dec - (size_t)pad;

    *data_out = out;
    *dlen_out = dlen;

    *is_priv = (strstr(label_out, "PRIVATE KEY") != NULL);
    return 1;
}

/* ke lowercase in-place */
static void to_lower(char *s) { for (; *s; ++s) *s = (char)tolower((unsigned char)*s); }

/* LABEL → keymgmt name + selector
   Contoh label: "MLDSA44 PRIVATE KEY" atau "MLKEM512 PUBLIC KEY" */
static int label_to_alg(const char *label, char *alg, size_t asz, int *selector)
{
    char tmp[128];
    OPENSSL_strlcpy(tmp, label, sizeof(tmp));
    to_lower(tmp);

    const int is_priv = (strstr(tmp, "private key") != NULL);
    *selector = is_priv ? OSSL_KEYMGMT_SELECT_PRIVATE_KEY : OSSL_KEYMGMT_SELECT_PUBLIC_KEY;

    const char *sp = strchr(tmp, ' ');
    size_t n = sp ? (size_t)(sp - tmp) : strlen(tmp);
    if (n == 0 || n >= asz) return 0;

    memcpy(alg, tmp, n);
    alg[n] = '\0';  /* "mldsa44" atau "mlkem512" */

    /* Normalisasi "mlkemNNN" → "MLKEMNNN" sesuai nama keymgmt */
    if (!strncmp(alg, "mlkem", 5)) {
        alg[0]='M'; alg[1]='L'; alg[2]='K'; alg[3]='E'; alg[4]='M';
        for (size_t i = 5; i < n; i++) alg[i] = (char)toupper((unsigned char)alg[i]);
    }
    /* mldsa** sengaja tetap lowercase (sesuai register keymgmt) */

    return 1;
}

/* === GETTABLE/GET_PARAMS untuk advertise input type "pem" === */
static const OSSL_PARAM *km_dec_gettable_params(void *provctx)
{
    (void)provctx;
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_utf8_string(OSSL_DECODER_PARAM_INPUT_TYPE, NULL, 0),
        OSSL_PARAM_END
    };
    return gettable;
}
static int km_dec_get_params(void *provctx, OSSL_PARAM params[])
{
    (void)provctx;
    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_DECODER_PARAM_INPUT_TYPE);
    if (p && !OSSL_PARAM_set_utf8_string(p, "pem"))
        return 0;
    return 1;
}

// --- helpers ---
/* ---------- read_all_core: dengan log yang jelas ---------- */
static int read_all_core(KM_PROVCTX *p, OSSL_CORE_BIO *in,
                         unsigned char **out, size_t *outlen)
{
    size_t cap = 4096, len = 0;
    unsigned char *buf = OPENSSL_malloc(cap + 1);
    if (!buf) return 0;

    for (;;) {
        if (cap - len < 1024) {            // jaga-jaga, grow lebih awal
            size_t newcap = cap * 2;
            unsigned char *tmp = OPENSSL_realloc(buf, newcap + 1);
            if (!tmp) { OPENSSL_free(buf); return 0; }
            buf = tmp;
            cap = newcap;
            fprintf(stderr, "[read_all_core] grow -> %zu\n", cap);
        }

        size_t n = 0;
        int r = p->core_bio_read_ex(in, buf + len, cap - len, &n);
        fprintf(stderr, "[read_all_core] r=%d n=%zu len=%zu\n", r, n, len);

        if (r <= 0) {              // EOF atau tidak bisa lanjut dibaca
            break;                 // <- **JANGAN return 0 di sini**
        }
        if (n == 0) {              // EOF normal
            break;
        }
        len += n;
    }

    buf[len] = 0;                  // biar aman diparse pakai strstr/memmem
    *out = buf;
    *outlen = len;
    fprintf(stderr, "[read_all_core] done len=%zu\n", len);
    return 1;
}


/* ---------- cari blok PEM MLDSA{44,65,87} ---------- */
static int find_pem_block(const unsigned char *txt, size_t tlen,
                          const char **alg_out,
                          const unsigned char **b64, size_t *b64len)
{
    const char *labels[]   = { "MLDSA44 PRIVATE KEY", "MLDSA65 PRIVATE KEY", "MLDSA87 PRIVATE KEY" };
    const char *algnames[] = { "mldsa44",             "mldsa65",             "mldsa87"             };

    for (size_t i = 0; i < 3; i++) {
        char begin[96], end[96];
        BIO_snprintf(begin, sizeof(begin), "-----BEGIN %s-----", labels[i]);
        BIO_snprintf(end,   sizeof(end),   "-----END %s-----",   labels[i]);

        const unsigned char *b = (const unsigned char*)strstr((const char*)txt, begin);
        const unsigned char *e = (const unsigned char*)strstr((const char*)txt, end);
        if (b && e && e > b) {
            b += strlen(begin);
            while (b < txt + tlen && (*b == '\r' || *b == '\n')) b++;
            *alg_out = algnames[i];
            *b64     = b;
            *b64len  = (size_t)(e - b);
            return 1;
        }
    }
    return 0;
}

/* ---------- util ---------- */
static void strip_ws_inplace(unsigned char *s, size_t *len) {
    size_t w = 0, n = *len;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = s[i];
        if (c != '\r' && c != '\n' && c != ' ' && c != '\t') s[w++] = c;
    }
    *len = w;
}
static int b64_decode(const unsigned char *in, size_t inlen,
                      unsigned char **out, size_t *outlen)
{
    size_t pad = (4 - (inlen % 4)) % 4;
    unsigned char *tmp = OPENSSL_malloc(inlen + pad);
    if (!tmp) return 0;
    memcpy(tmp, in, inlen);
    for (size_t i = 0; i < pad; i++) tmp[inlen + i] = '=';

    size_t max = (inlen + pad) / 4 * 3;
    unsigned char *buf = OPENSSL_malloc(max);
    if (!buf) { OPENSSL_free(tmp); return 0; }

    int n = EVP_DecodeBlock(buf, tmp, (int)(inlen + pad));
    OPENSSL_free(tmp);
    if (n < 0) { OPENSSL_free(buf); return 0; }
    *out = buf; *outlen = (size_t)n;
    return 1;
}

/* ---------- decoder_decode (yang dipanggil OpenSSL) ---------- */
static int km_dec_decode(void *vctx,
                         OSSL_CORE_BIO *cin,
                         int selection,
                         OSSL_CALLBACK *cb, void *cbarg,
                         OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    (void)selection; (void)pw_cb; (void)pw_cbarg;
    KM_DEC_CTX *ctx = (KM_DEC_CTX*)vctx;
    KM_PROVCTX *prov = ctx ? ctx->provctx : NULL;
    if (!prov) return 0;

    fprintf(stderr, "[decoder] called\n");
    
    /* 1) baca semua input */
    unsigned char *txt = NULL; size_t tlen = 0;
    if (!read_all_core(prov, cin, &txt, &tlen)) return 0;
    fprintf(stderr, "[read_all_core] end\n");
    
    /* 2) temukan blok PEM kita */
    const char *alg = NULL;
    const unsigned char *b64p = NULL; size_t b64len = 0;
    fprintf(stderr, "[find_pem_block] called\n");
    if (!find_pem_block(txt, tlen, &alg, &b64p, &b64len)) {
        fprintf(stderr, "[decoder] no MLDSA PEM header found\n");
        OPENSSL_free(txt);
        return 0;
    }

    /* 3) bersihkan whitespace base64 di buffer temp lalu decode */
    unsigned char *b64tmp = OPENSSL_malloc(b64len);
    if (!b64tmp) { OPENSSL_free(txt); return 0; }
    memcpy(b64tmp, b64p, b64len);
    strip_ws_inplace(b64tmp, &b64len);

    unsigned char *sk = NULL; size_t sklen = 0;
    int okb64 = b64_decode(b64tmp, b64len, &sk, &sklen);
    fprintf(stderr, "[decoder] found alg=%s b64len=%zu\n", alg, b64len);
    OPENSSL_free(b64tmp);
    OPENSSL_free(txt);
    if (!okb64) {
        fprintf(stderr, "[decoder] base64 decode failed\n");
        return 0;
    }
    fprintf(stderr, "[decoder] decoded sklen=%zu\n", sklen);

    /* 4) kirim ke core -> KEYMGMT.import() */
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    if (!bld) { OPENSSL_free(sk); return 0; }

    if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_OBJECT_PARAM_DATA_TYPE, alg, 0)) goto err;
    if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PRIV_KEY, sk, sklen)) goto err;

    OSSL_PARAM *out = OSSL_PARAM_BLD_to_param(bld);
    OPENSSL_free(sk);
    OSSL_PARAM_BLD_free(bld);
    if (!out) return 0;

    for (const OSSL_PARAM *pp = out; pp && pp->key; ++pp)
    fprintf(stderr, "[decoder] out param: %s (data_type=%d size=%zu)\n",
            pp->key, pp->data_type, pp->data_size);


    int ok = cb(out, cbarg); /* ← ini harus 1 kalau KEYMGMT.import sukses */
    fprintf(stderr, "[decoder] construct/import -> %d\n", ok);
    OSSL_PARAM_free(out);
    return ok;

err:
    OPENSSL_free(sk);
    OSSL_PARAM_BLD_free(bld);
    return 0;
}


/* ---------- Dispatch table ---------- */
static const OSSL_DISPATCH km_decoder_pem_fns[] = {
    { OSSL_FUNC_DECODER_NEWCTX,          (void (*)(void))km_dec_newctx },
    { OSSL_FUNC_DECODER_FREECTX,         (void (*)(void))km_dec_freectx },
    { OSSL_FUNC_DECODER_GETTABLE_PARAMS, (void (*)(void))km_dec_gettable_params },
    { OSSL_FUNC_DECODER_GET_PARAMS,      (void (*)(void))km_dec_get_params },
    { OSSL_FUNC_DECODER_DOES_SELECTION,  (void (*)(void))km_dec_does_selection },
    { OSSL_FUNC_DECODER_DECODE,          (void (*)(void))km_dec_decode },
    { 0, NULL }
};

/* Register decoder: input=pem (lowercase) */
const OSSL_ALGORITHM km_algs_decoder[] = {
    { "mldsa44",   "input=PEM,structure=raw", km_decoder_pem_fns },
    { "mldsa65",   "input=PEM,structure=raw", km_decoder_pem_fns },
    { "mldsa87",   "input=PEM,structure=raw", km_decoder_pem_fns },
    { "MLKEM512",  "input=PEM,structure=raw", km_decoder_pem_fns },
    { "MLKEM768",  "input=PEM,structure=raw", km_decoder_pem_fns },
    { "MLKEM1024", "input=PEM,structure=raw", km_decoder_pem_fns },
    { NULL, NULL, NULL }
};
