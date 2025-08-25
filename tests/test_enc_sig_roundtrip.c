// tests/test_enc_sig_roundtrip.c
#include <openssl/evp.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <stdio.h>
#include <string.h>

static void print_errors(const char *where) {
    fprintf(stderr, "== OpenSSL errors at %s ==\n", where);
    ERR_print_errors_fp(stderr);
}

static int roundtrip_one(const char *alg) {
    int ok = 0;
    EVP_PKEY *pkey = NULL, *pkey2 = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    OSSL_ENCODER_CTX *ectx = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    BIO *mem = NULL, *mem2 = NULL;

    printf("\n---- [%s] ROUNDTRIP BEGIN ----\n", alg);

    /* 1) Keygen */
    kctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (!kctx) { fprintf(stderr, "[%s] new_from_name fail\n", alg); print_errors("new_from_name"); goto end; }
    if (EVP_PKEY_keygen_init(kctx) <= 0) { fprintf(stderr, "[%s] keygen_init fail\n", alg); print_errors("keygen_init"); goto end; }
    if (EVP_PKEY_generate(kctx, &pkey) <= 0) { fprintf(stderr, "[%s] keygen fail\n", alg); print_errors("keygen"); goto end; }
    EVP_PKEY_CTX_free(kctx); kctx = NULL;
    printf("[%s] keygen OK\n", alg);

    /* 2) ENCODE ke PEM via encoder provider kita */
    ectx = OSSL_ENCODER_CTX_new_for_pkey(
        pkey,
        OSSL_KEYMGMT_SELECT_KEYPAIR,
        "PEM",     /* output format */
        NULL,      /* structure (biarkan NULL utk custom) */
        "provider=kookminlib"
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

    /* 3) DECODE dari PEM kembali ke EVP_PKEY */
    dctx = OSSL_DECODER_CTX_new_for_pkey(
        &pkey2,
        "PEM",     /* input format */
        NULL,      /* structure */
        NULL,      /* keytype auto */
        // OSSL_KEYMGMT_SELECT_KEYPAIR,
        OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
        NULL,      /* libctx */
        "provider=kookminlib"
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
    const unsigned char msg[] = "hello oqs provider";
    size_t siglen = 0;
    EVP_PKEY_CTX *sctx = EVP_PKEY_CTX_new(pkey2, NULL);
    if (!sctx) { fprintf(stderr, "[%s] sign ctx fail\n", alg); print_errors("EVP_PKEY_CTX_new"); goto end; }
    if (EVP_PKEY_sign_init(sctx) <= 0) { fprintf(stderr, "[%s] sign_init fail\n", alg); print_errors("EVP_PKEY_sign_init"); EVP_PKEY_CTX_free(sctx); goto end; }
    if (EVP_PKEY_sign(sctx, NULL, &siglen, msg, sizeof(msg)-1) <= 0) { fprintf(stderr, "[%s] sign(size) fail\n", alg); print_errors("EVP_PKEY_sign(size)"); EVP_PKEY_CTX_free(sctx); goto end; }
    unsigned char *sig = OPENSSL_malloc(siglen);
    if (!sig) { fprintf(stderr, "[%s] malloc sig fail\n", alg); EVP_PKEY_CTX_free(sctx); goto end; }
    if (EVP_PKEY_sign(sctx, sig, &siglen, msg, sizeof(msg)-1) <= 0) { fprintf(stderr, "[%s] sign fail\n", alg); print_errors("EVP_PKEY_sign"); OPENSSL_free(sig); EVP_PKEY_CTX_free(sctx); goto end; }
    EVP_PKEY_CTX_free(sctx);

    EVP_PKEY_CTX *vctx = EVP_PKEY_CTX_new(pkey2, NULL);
    if (!vctx) { fprintf(stderr, "[%s] verify ctx fail\n", alg); OPENSSL_free(sig); goto end; }
    if (EVP_PKEY_verify_init(vctx) <= 0) { fprintf(stderr, "[%s] verify_init fail\n", alg); print_errors("EVP_PKEY_verify_init"); EVP_PKEY_CTX_free(vctx); OPENSSL_free(sig); goto end; }
    int vr = EVP_PKEY_verify(vctx, sig, siglen, msg, sizeof(msg)-1);
    EVP_PKEY_CTX_free(vctx);
    OPENSSL_free(sig);

    printf("[%s] pure verify -> %d (1=ok)\n", alg, vr);
    ok = (vr == 1);

end:
    if (!ok) print_errors("roundtrip_one");
    OSSL_DECODER_CTX_free(dctx);
    OSSL_ENCODER_CTX_free(ectx);
    EVP_PKEY_free(pkey2);
    BIO_free(mem2);
    BIO_free(mem);
    EVP_PKEY_free(pkey);
    return ok;
}

int main(void) {
    OSSL_PROVIDER *defp = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER *kmp  = OSSL_PROVIDER_load(NULL, "kookminlib");
    if (!defp || !kmp) { fprintf(stderr, "provider load fail\n"); print_errors("OSSL_PROVIDER_load"); return 1; }

    int all = 1;
    all &= roundtrip_one("mldsa44");
    all &= roundtrip_one("mldsa65");
    all &= roundtrip_one("mldsa87");

    OSSL_PROVIDER_unload(kmp);
    OSSL_PROVIDER_unload(defp);

    if (!all) { fprintf(stderr, "\nSome roundtrips FAILED\n"); return 1; }
    printf("\nAll roundtrips OK\n");
    return 0;
}
