// tests/test_mlkem.c
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

static void print_errors(const char *where) {
    fprintf(stderr, "%s:\n", where);
    ERR_print_errors_fp(stderr);
}

static int test_one(const char *alg) {
    int ok = 0;

    OSSL_PROVIDER *defp = NULL, *kmp = NULL;
    EVP_PKEY_CTX *kctx = NULL, *ectx = NULL, *dctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *ct = NULL, *sec = NULL, *sec2 = NULL;
    size_t ctlen = 0, seclen = 0, seclen2 = 0;

    /* load providers */
    defp = OSSL_PROVIDER_load(NULL, "default");
    kmp  = OSSL_PROVIDER_load(NULL, "kookminlib");
    if (!defp || !kmp) { fprintf(stderr, "provider load fail\n"); goto cleanup; }

    /* keygen */
    kctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (!kctx) { fprintf(stderr,"[%s] new_from_name fail\n", alg); print_errors("new_from_name"); goto cleanup; }
    if (EVP_PKEY_keygen_init(kctx) <= 0) { fprintf(stderr,"[%s] keygen_init fail\n", alg); print_errors("keygen_init"); goto cleanup; }
    if (EVP_PKEY_generate(kctx, &pkey) <= 0) { fprintf(stderr,"[%s] keygen fail\n", alg); print_errors("keygen"); goto cleanup; }
    EVP_PKEY_CTX_free(kctx); kctx = NULL;

    /* encapsulate (pakai public key) */
    ectx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (!ectx) { fprintf(stderr,"[%s] ectx new fail\n", alg); print_errors("ectx_new"); goto cleanup; }
    if (EVP_PKEY_encapsulate_init(ectx, NULL) <= 0) { fprintf(stderr,"[%s] encapsulate_init fail\n", alg); print_errors("encapsulate_init"); goto cleanup; }

    if (EVP_PKEY_encapsulate(ectx, NULL, &ctlen, NULL, &seclen) <= 0) {
        fprintf(stderr,"[%s] encapsulate(size) fail\n", alg); print_errors("encapsulate(size)"); goto cleanup;
    }
    ct  = OPENSSL_malloc(ctlen);
    sec = OPENSSL_malloc(seclen);
    if (!ct || !sec) { fprintf(stderr,"[%s] malloc ct/sec fail\n", alg); goto cleanup; }

    if (EVP_PKEY_encapsulate(ectx, ct, &ctlen, sec, &seclen) <= 0) {
        fprintf(stderr,"[%s] encapsulate fail\n", alg); print_errors("encapsulate"); goto cleanup;
    }
    EVP_PKEY_CTX_free(ectx); ectx = NULL;

    /* decapsulate (pakai private key) */
    dctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (!dctx) { fprintf(stderr,"[%s] dctx new fail\n", alg); print_errors("dctx_new"); goto cleanup; }
    if (EVP_PKEY_decapsulate_init(dctx, NULL) <= 0) {
        fprintf(stderr,"[%s] decapsulate_init fail\n", alg); print_errors("decapsulate_init"); goto cleanup;
    }
    sec2 = OPENSSL_malloc(seclen);
    if (!sec2) { fprintf(stderr,"[%s] malloc sec2 fail\n", alg); goto cleanup; }
    seclen2 = seclen; /* beri kapasitas awal */

    if (EVP_PKEY_decapsulate(dctx, sec2, &seclen2, ct, ctlen) <= 0) {
        fprintf(stderr,"[%s] decapsulate fail\n", alg); print_errors("decapsulate"); goto cleanup;
    }

    if (seclen2 == seclen && memcmp(sec, sec2, seclen) == 0) {
        printf("[%s] KEM OK: shared secret match (ctlen=%zu, seclen=%zu)\n", alg, ctlen, seclen);
        ok = 1;
    } else {
        printf("[%s] KEM MISMATCH: %zu vs %zu\n", alg, seclen, seclen2);
    }

cleanup:
    if (dctx) EVP_PKEY_CTX_free(dctx);
    if (ectx) EVP_PKEY_CTX_free(ectx);
    if (kctx) EVP_PKEY_CTX_free(kctx);
    if (pkey) EVP_PKEY_free(pkey);
    OPENSSL_free(ct);
    OPENSSL_free(sec);
    OPENSSL_free(sec2);
    if (kmp)  OSSL_PROVIDER_unload(kmp);
    if (defp) OSSL_PROVIDER_unload(defp);
    return ok;
}

int main(void) {
    /* Prasyarat:
       - export OPENSSL_MODULES=/opt/openssl-master/lib/ossl-modules
       - `openssl list -kem-algorithms -provider default -provider kookminlib`
         menampilkan MLKEM512/768/1024
       - Provider kamu mendaftarkan *keymgmt* dan *kem* untuk MLKEM
    */
    ERR_load_crypto_strings();

    int ok = 1;
    ok &= test_one("MLKEM512");
    ok &= test_one("MLKEM768");
    ok &= test_one("MLKEM1024");
    return ok ? 0 : 1;
}
