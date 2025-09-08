// kem_tool.c - Minimal KEM encapsulation/decapsulation tool using OpenSSL EVP API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>
#include <openssl/pem.h>

static void die(const char *msg) { fprintf(stderr, "%s\n", msg); exit(1); }

static EVP_PKEY *load_key(OSSL_LIB_CTX *ctx, const char *path, int pub)
{
    FILE *f = fopen(path, "rb");
    if (!f) die("fopen failed");
    EVP_PKEY *pkey = NULL;
    if (pub) {
        pkey = PEM_read_PUBKEY_ex(f, NULL, NULL, NULL, ctx, NULL);
    } else {
        pkey = PEM_read_PrivateKey_ex(f, NULL, NULL, NULL, ctx, NULL);
    }
    fclose(f);
    if (!pkey) die("read key failed");
    return pkey;
}

static void write_bin(const char *path, const unsigned char *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) die("open out failed");
    if (fwrite(buf, 1, len, f) != len) die("write failed");
    fclose(f);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "Usage:\n"
            "  %s encap <pubkey.pem> <ct.bin> <ss.bin>\n"
            "  %s decap <privkey.pem> <ct.bin> <ss.bin>\n", argv[0], argv[0]);
        return 2;
    }

    const char *mode = argv[1];
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (!libctx) die("OSSL_LIB_CTX_new failed");

    OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(libctx, "default");
    OSSL_PROVIDER *kmprov  = OSSL_PROVIDER_load(libctx, "kookminlib");
    if (!defprov || !kmprov) die("OSSL_PROVIDER_load failed (default/kookminlib)");

    int ret = 1;

    if (strcmp(mode, "encap") == 0) {
        if (argc != 5) die("encap args: <pubkey.pem> <ct.bin> <ss.bin>");
        EVP_PKEY *pub = load_key(libctx, argv[2], 1);

        EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new_from_pkey(libctx, pub, NULL);
        if (!ectx) die("EVP_PKEY_CTX_new_from_pkey failed");
        if (EVP_PKEY_encapsulate_init(ectx, NULL) <= 0) die("encapsulate_init failed");

        size_t ctlen = 0, sslen = 0;
        if (EVP_PKEY_encapsulate(ectx, NULL, &ctlen, NULL, &sslen) <= 0) die("encapsulate(size) failed");

        unsigned char *ct = OPENSSL_malloc(ctlen);
        unsigned char *ss = OPENSSL_malloc(sslen);
        if (!ct || !ss) die("malloc failed");

        if (EVP_PKEY_encapsulate(ectx, ct, &ctlen, ss, &sslen) <= 0) die("encapsulate failed");

        write_bin(argv[3], ct, ctlen);
        write_bin(argv[4], ss, sslen);
        printf("Encap OK. ct=%zu bytes, ss=%zu bytes\n", ctlen, sslen);

        OPENSSL_free(ct);
        OPENSSL_free(ss);
        EVP_PKEY_CTX_free(ectx);
        EVP_PKEY_free(pub);
        ret = 0;
    } else if (strcmp(mode, "decap") == 0) {
        if (argc != 5) die("decap args: <privkey.pem> <ct.bin> <ss.bin>");

        // read ct
        FILE *f = fopen(argv[3], "rb");
        if (!f) die("open ct failed");
        fseek(f, 0, SEEK_END);
        long L = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (L <= 0) die("ct empty");
        unsigned char *ct = OPENSSL_malloc((size_t)L);
        if (!ct) die("malloc ct failed");
        if (fread(ct, 1, (size_t)L, f) != (size_t)L) die("read ct failed");
        fclose(f);

        EVP_PKEY *priv = load_key(libctx, argv[2], 0);
        EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new_from_pkey(libctx, priv, NULL);
        if (!dctx) die("EVP_PKEY_CTX_new_from_pkey failed");
        if (EVP_PKEY_decapsulate_init(dctx, NULL) <= 0) die("decapsulate_init failed");

        size_t sslen = 0;
        if (EVP_PKEY_decapsulate(dctx, NULL, &sslen, ct, (size_t)L) <= 0) die("decapsulate(size) failed");
        unsigned char *ss = OPENSSL_malloc(sslen);
        if (!ss) die("malloc ss failed");
        if (EVP_PKEY_decapsulate(dctx, ss, &sslen, ct, (size_t)L) <= 0) die("decapsulate failed");

        write_bin(argv[4], ss, sslen);
        printf("Decap OK. ss=%zu bytes\n", sslen);

        OPENSSL_free(ss);
        OPENSSL_free(ct);
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(priv);
        ret = 0;
    } else {
        die("mode must be encap or decap");
    }

    OSSL_PROVIDER_unload(kmprov);
    OSSL_PROVIDER_unload(defprov);
    OSSL_LIB_CTX_free(libctx);
    return ret;
}
