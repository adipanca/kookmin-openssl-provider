#pragma once
#include <string.h>

static inline const char *km_label_for_alg(const char *alg) {
    if (!alg) return "UNKNOWN";
    if (strncmp(alg, "mldsa", 5) == 0) {
        if (strcmp(alg,"mldsa44")==0) return "MLDSA44";
        if (strcmp(alg,"mldsa65")==0) return "MLDSA65";
        if (strcmp(alg,"mldsa87")==0) return "MLDSA87";
        return "MLDSA";
    }
    /* MLKEM512/768/1024 sudah uppercase */
    return alg;
}
