#pragma once
#include "km_provider.h"
#include <oqs/oqs.h>

typedef struct {
    KM_PROVCTX *provctx;
    char  alg_name[32];          /* "MLKEM512" / "MLKEM768" / "MLKEM1024" */
    OQS_KEM *kem;                /* handle liboqs */
    unsigned char *pub;  size_t publen;
    unsigned char *priv; size_t privlen;
} KM_KEM_KEY;

/* helper memastikan k->kem terisi sesuai alg_name */
int km_kem_ensure(KM_KEM_KEY *k);
