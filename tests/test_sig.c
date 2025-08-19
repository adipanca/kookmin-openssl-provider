// tests/test_pure.c
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

static int test_one(const char *alg) {
    OSSL_PROVIDER *defp = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER *kmp  = OSSL_PROVIDER_load(NULL, "kookminlib");

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (!kctx) { fprintf(stderr,"[%s] new_from_name fail\n",alg); return 0; }
    if (EVP_PKEY_keygen_init(kctx)<=0){ fprintf(stderr,"[%s] keygen_init fail\n",alg); return 0; }
    EVP_PKEY *pkey=NULL;
    if (EVP_PKEY_generate(kctx,&pkey)<=0){ fprintf(stderr,"[%s] keygen fail\n",alg); return 0; }
    EVP_PKEY_CTX_free(kctx);

    const unsigned char msg[] = "hello oqs provider";
    size_t siglen=0;
    EVP_PKEY_CTX *sctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_sign_init(sctx); /* PURE sign */
    EVP_PKEY_sign(sctx, NULL, &siglen, msg, sizeof(msg)-1);
    unsigned char *sig = OPENSSL_malloc(siglen);
    if (EVP_PKEY_sign(sctx, sig, &siglen, msg, sizeof(msg)-1)<=0){
        fprintf(stderr,"[%s] PKEY_sign fail\n",alg); return 0;
    }
    EVP_PKEY_CTX_free(sctx);

    EVP_PKEY_CTX *vctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_verify_init(vctx);
    int vr = EVP_PKEY_verify(vctx, sig, siglen, msg, sizeof(msg)-1);
    printf("[%s] pure verify -> %d (1=ok)\n", alg, vr);
    EVP_PKEY_CTX_free(vctx);

    OPENSSL_free(sig);
    EVP_PKEY_free(pkey);
    OSSL_PROVIDER_unload(kmp);
    OSSL_PROVIDER_unload(defp);
    return vr == 1;
}

int main(void){
    int ok = 1;
    ok &= test_one("mldsa44");
    ok &= test_one("mldsa65");
    ok &= test_one("mldsa87");
    return ok?0:1;
}
