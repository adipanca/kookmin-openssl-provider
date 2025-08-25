// tests/test_enc_sig_roundtrip.c
#include <openssl/evp.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <stdio.h>
#include <string.h>

static void print_errors(const char *where) {
    fprintf(stderr, "== OpenSSL errors at %s ==\n", where);
    ERR_print_errors_fp(stderr);
}

static int roundtrip_one(OSSL_LIB_CTX *libctx, const char *alg) {
    int ok = 0;
    EVP_PKEY *pkey = NULL, *pkey2 = NULL, *p_import = NULL;
    EVP_PKEY_CTX *kctx = NULL, *pctx2 = NULL, *sctx = NULL, *vctx = NULL;
    OSSL_ENCODER_CTX *ectx = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    BIO *mem = NULL, *mem2 = NULL;

    printf("\n---- [%s] ROUNDTRIP BEGIN ----\n", alg);

    /* 1) Keygen (di libctx yang sama) */
    kctx = EVP_PKEY_CTX_new_from_name(libctx, alg, /*propq*/NULL);
    if (!kctx) { fprintf(stderr, "[%s] new_from_name fail\n", alg); print_errors("new_from_name"); goto end; }
    if (EVP_PKEY_keygen_init(kctx) <= 0) { fprintf(stderr, "[%s] keygen_init fail\n", alg); print_errors("keygen_init"); goto end; }
    if (EVP_PKEY_generate(kctx, &pkey) <= 0) { fprintf(stderr, "[%s] keygen fail\n", alg); print_errors("keygen"); goto end; }
    EVP_PKEY_CTX_free(kctx); kctx = NULL;
    printf("[%s] keygen OK\n", alg);

    /* 1b) Export -> PARAMS, ambil PRIV_KEY bytes */
    OSSL_PARAM *to = NULL;
    if (EVP_PKEY_todata(pkey, EVP_PKEY_KEYPAIR, &to) <= 0) {
        fprintf(stderr, "[%s] todata fail\n", alg);
        print_errors("EVP_PKEY_todata");
        goto end;
    }
    const OSSL_PARAM *pr = OSSL_PARAM_locate_const(to, OSSL_PKEY_PARAM_PRIV_KEY);
    if (!pr || pr->data_type != OSSL_PARAM_OCTET_STRING || pr->data == NULL || pr->data_size == 0) {
        fprintf(stderr, "[%s] todata: no PRIV_KEY param\n", alg);
        OSSL_PARAM_free(to);
        goto end;
    }
    size_t sklen = pr->data_size;
    unsigned char *skcopy = OPENSSL_malloc(sklen);
    if (!skcopy) { OSSL_PARAM_free(to); goto end; }
    memcpy(skcopy, pr->data, sklen);
    OSSL_PARAM_free(to);

    /* 1c) fromdata(import) -> harus memicu KEYMGMT.import() provider kamu */
    pctx2 = EVP_PKEY_CTX_new_from_name(libctx, alg, /*propq*/NULL);
    if (!pctx2) { fprintf(stderr, "[%s] new_from_name(import) fail\n", alg); OPENSSL_free(skcopy); print_errors("EVP_PKEY_CTX_new_from_name"); goto end; }
    if (EVP_PKEY_fromdata_init(pctx2) <= 0) { fprintf(stderr, "[%s] fromdata_init fail\n", alg); OPENSSL_free(skcopy); print_errors("EVP_PKEY_fromdata_init"); goto end; }

    OSSL_PARAM inparams[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, skcopy, sklen),
        OSSL_PARAM_END
    };
    int ok_fromdata = EVP_PKEY_fromdata(pctx2, &p_import, EVP_PKEY_PRIVATE_KEY, inparams);
    printf("[%s] fromdata(import) ok=%d p_import=%p (expect ok=1)\n", alg, ok_fromdata, (void*)p_import);
    EVP_PKEY_CTX_free(pctx2); pctx2 = NULL;
    OPENSSL_free(skcopy);
    EVP_PKEY_free(p_import); p_import = NULL;

    if (ok_fromdata != 1) {
        fprintf(stderr, "[%s] fromdata/import FAILED — KEYMGMT.import bermasalah\n", alg);
        print_errors("EVP_PKEY_fromdata");
        goto end;
    }

    /* 2) ENCODE ke PEM via encoder provider kamu */
    ectx = OSSL_ENCODER_CTX_new_for_pkey(
        pkey,
        OSSL_KEYMGMT_SELECT_KEYPAIR,
        "PEM",     /* output format */
        NULL,      /* structure (NULL untuk custom) */
        /* propq */ NULL           /* <- JANGAN filter provider di sini */
    );
    if (!ectx) { fprintf(stderr, "[%s] encoder ctx NULL\n", alg); print_errors("ENCODER_CTX_new_for_pkey"); goto end; }

    mem = BIO_new(BIO_s_mem());
    if (!mem) { fprintf(stderr, "[%s] BIO mem fail\n", alg); goto end; }

    if (!OSSL_ENCODER_to_bio(ectx, mem)) {
        fprintf(stderr, "[%s] ENCODE to PEM fail\n", alg);
        print_errors("ENCODER_to_bio");
        goto end;
    }
    printf("[%s] encode -> PEM OK\n", alg);

    /* ambil pointer & length dari BIO mem */
    const char *pem_ptr = NULL;
    long pem_len = BIO_get_mem_data(mem, &pem_ptr);
    if (pem_len <= 0 || pem_ptr == NULL) {
        fprintf(stderr, "[%s] BIO_get_mem_data fail\n", alg);
        goto end;
    }
    printf("[%s] PEM length = %ld bytes\n", alg, pem_len);
    fwrite(pem_ptr, 1, (size_t)pem_len, stdout);
    if (pem_len && pem_ptr[pem_len - 1] != '\n') putchar('\n');

    /* 3) DECODE dari PEM -> EVP_PKEY (pakai libctx yg sama, tanpa prop filter) */
    dctx = OSSL_DECODER_CTX_new_for_pkey(
        &pkey2,
        "PEM",
        NULL,      /* structure */
        NULL,      /* keytype auto */
        // OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
        OSSL_KEYMGMT_SELECT_KEYPAIR,   /* <<— was PRIVATE_KEY */
        libctx,    /* <- libctx yang sama */
        // "provider=kookminlib"
        NULL       /* <- propq NULL, jangan filter provider */
    );
    if (!dctx) { fprintf(stderr, "[%s] decoder ctx NULL\n", alg); print_errors("DECODER_CTX_new_for_pkey"); goto end; }

    mem2 = BIO_new_mem_buf(pem_ptr, (int)pem_len);
    if (!mem2) { fprintf(stderr, "[%s] BIO mem2 fail\n", alg); goto end; }

    if (!OSSL_DECODER_from_bio(dctx, mem2)) {
        fprintf(stderr, "[%s] DECODE from PEM fail\n", alg);
        print_errors("DECODER_from_bio");
        goto end;
    }
    printf("[%s] decode <- PEM OK\n", alg);

    /* 4) Pure sign/verify pakai pkey2 */
    {
        const unsigned char msg[] = "hello oqs provider";
        size_t siglen = 0;

        sctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey2, /*propq*/NULL);
        if (!sctx) { fprintf(stderr, "[%s] sign ctx fail\n", alg); print_errors("EVP_PKEY_CTX_new"); goto end; }
        if (EVP_PKEY_sign_init(sctx) <= 0) { fprintf(stderr, "[%s] sign_init fail\n", alg); print_errors("EVP_PKEY_sign_init"); goto end; }
        if (EVP_PKEY_sign(sctx, NULL, &siglen, msg, sizeof(msg)-1) <= 0) { fprintf(stderr, "[%s] sign(size) fail\n", alg); print_errors("EVP_PKEY_sign(size)"); goto end; }

        unsigned char *sig = OPENSSL_malloc(siglen);
        if (!sig) { fprintf(stderr, "[%s] malloc sig fail\n", alg); goto end; }
        if (EVP_PKEY_sign(sctx, sig, &siglen, msg, sizeof(msg)-1) <= 0) { fprintf(stderr, "[%s] sign fail\n", alg); print_errors("EVP_PKEY_sign"); OPENSSL_free(sig); goto end; }

        vctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey2, /*propq*/NULL);
        if (!vctx) { fprintf(stderr, "[%s] verify ctx fail\n", alg); OPENSSL_free(sig); goto end; }
        if (EVP_PKEY_verify_init(vctx) <= 0) { fprintf(stderr, "[%s] verify_init fail\n", alg); print_errors("EVP_PKEY_verify_init"); OPENSSL_free(sig); goto end; }
        int vr = EVP_PKEY_verify(vctx, sig, siglen, msg, sizeof(msg)-1);
        OPENSSL_free(sig);

        printf("[%s] pure verify -> %d (1=ok)\n", alg, vr);
        ok = (vr == 1);
    }

end:
    if (!ok) print_errors("roundtrip_one");
    EVP_PKEY_CTX_free(vctx);
    EVP_PKEY_CTX_free(sctx);
    OSSL_DECODER_CTX_free(dctx);
    OSSL_ENCODER_CTX_free(ectx);
    EVP_PKEY_free(pkey2);
    BIO_free(mem2);
    BIO_free(mem);
    EVP_PKEY_free(pkey);
    return ok;
}

int main(void) {
    /* Pakai libctx eksplisit agar semua fetch/encode/decode konsisten */
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (!libctx) { fprintf(stderr, "libctx new fail\n"); return 1; }

    OSSL_PROVIDER *defp = OSSL_PROVIDER_load(libctx, "default");
    OSSL_PROVIDER *kmp  = OSSL_PROVIDER_load(libctx, "kookminlib");
    if (!defp || !kmp) {
        fprintf(stderr, "provider load fail\n");
        print_errors("OSSL_PROVIDER_load");
        OSSL_PROVIDER_unload(kmp);
        OSSL_PROVIDER_unload(defp);
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }

    int all = 1;
    all &= roundtrip_one(libctx, "mldsa44");
    all &= roundtrip_one(libctx, "mldsa65");
    all &= roundtrip_one(libctx, "mldsa87");

    OSSL_PROVIDER_unload(kmp);
    OSSL_PROVIDER_unload(defp);
    OSSL_LIB_CTX_free(libctx);

    if (!all) { fprintf(stderr, "\nSome roundtrips FAILED\n"); return 1; }
    printf("\nAll roundtrips OK\n");
    return 0;
}
