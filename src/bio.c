// SPDX-License-Identifier: Apache-2.0 AND MIT
// KM OpenSSL 3 provider

#include <assert.h>
#include <stdarg.h>
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/bio.h>

#include "provider.h"

/* ------------------------------------------------------------------------- */
/*                    Core BIO callback vtable (singleton)                   */
/* ------------------------------------------------------------------------- */

typedef struct km_bio_core_vtbl_st {
    OSSL_FUNC_BIO_new_file_fn   *p_new_file;
    OSSL_FUNC_BIO_new_membuf_fn *p_new_membuf;
    OSSL_FUNC_BIO_read_ex_fn    *p_read_ex;
    OSSL_FUNC_BIO_write_ex_fn   *p_write_ex;
    OSSL_FUNC_BIO_gets_fn       *p_gets;
    OSSL_FUNC_BIO_puts_fn       *p_puts;
    OSSL_FUNC_BIO_ctrl_fn       *p_ctrl;
    OSSL_FUNC_BIO_up_ref_fn     *p_up_ref;
    OSSL_FUNC_BIO_free_fn       *p_free;
    OSSL_FUNC_BIO_vprintf_fn    *p_vprintf;
} km_bio_core_vtbl;

/* Zero-initialized at start; we only ever fill it once per provider. */
static km_bio_core_vtbl g_bio_vtbl;

/* Small helper to check if the vtable was (at least partially) populated. */
static int km_bio_vtbl_is_bound(void) {
    return g_bio_vtbl.p_read_ex != NULL || g_bio_vtbl.p_write_ex != NULL
        || g_bio_vtbl.p_ctrl   != NULL;
}

/* ------------------------------------------------------------------------- */
/*                         Dispatch binding from Core                        */
/* ------------------------------------------------------------------------- */

#define BIND_IF(fnid, member, caster)           \
    case fnid:                                   \
        if (g_bio_vtbl.member == NULL)          \
            g_bio_vtbl.member = caster(fns);    \
        break

int km_prov_bio_from_dispatch(const OSSL_DISPATCH *fns)
{
    if (fns == NULL)
        return 0;

    /* Iterate the array until sentinel (function_id == 0). */
    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        BIND_IF(OSSL_FUNC_BIO_NEW_FILE,   p_new_file,   OSSL_FUNC_BIO_new_file);
        BIND_IF(OSSL_FUNC_BIO_NEW_MEMBUF, p_new_membuf, OSSL_FUNC_BIO_new_membuf);
        BIND_IF(OSSL_FUNC_BIO_READ_EX,    p_read_ex,    OSSL_FUNC_BIO_read_ex);
        BIND_IF(OSSL_FUNC_BIO_WRITE_EX,   p_write_ex,   OSSL_FUNC_BIO_write_ex);
        BIND_IF(OSSL_FUNC_BIO_GETS,       p_gets,       OSSL_FUNC_BIO_gets);
        BIND_IF(OSSL_FUNC_BIO_PUTS,       p_puts,       OSSL_FUNC_BIO_puts);
        BIND_IF(OSSL_FUNC_BIO_CTRL,       p_ctrl,       OSSL_FUNC_BIO_ctrl);
        BIND_IF(OSSL_FUNC_BIO_UP_REF,     p_up_ref,     OSSL_FUNC_BIO_up_ref);
        BIND_IF(OSSL_FUNC_BIO_FREE,       p_free,       OSSL_FUNC_BIO_free);
        BIND_IF(OSSL_FUNC_BIO_VPRINTF,    p_vprintf,    OSSL_FUNC_BIO_vprintf);
        default:
            /* Ignore unknown ids; future-proof against newer cores. */
            break;
        }
    }

    /* Minimal sanity: ensure at least core I/O is available if needed. */
    return km_bio_vtbl_is_bound() ? 1 : 1; /* allow partial; wrappers check */
}

/* ------------------------------------------------------------------------- */
/*                          Thin wrappers (public API)                       */
/* ------------------------------------------------------------------------- */

OSSL_CORE_BIO *km_prov_bio_new_file(const char *filename, const char *mode)
{
    if (g_bio_vtbl.p_new_file == NULL)
        return NULL;
    return g_bio_vtbl.p_new_file(filename, mode);
}

OSSL_CORE_BIO *km_prov_bio_new_membuf(const char *buf, int len)
{
    if (g_bio_vtbl.p_new_membuf == NULL)
        return NULL;
    return g_bio_vtbl.p_new_membuf(buf, len);
}

int km_prov_bio_read_ex(OSSL_CORE_BIO *bio, void *data, size_t data_len,
                        size_t *bytes_read)
{
    if (g_bio_vtbl.p_read_ex == NULL || bio == NULL || data == NULL)
        return 0;
    return g_bio_vtbl.p_read_ex(bio, data, data_len, bytes_read);
}

int km_prov_bio_write_ex(OSSL_CORE_BIO *bio, const void *data, size_t data_len,
                         size_t *written)
{
    if (g_bio_vtbl.p_write_ex == NULL || bio == NULL || data == NULL)
        return 0;
    return g_bio_vtbl.p_write_ex(bio, data, data_len, written);
}

int km_prov_bio_gets(OSSL_CORE_BIO *bio, char *buf, int size)
{
    if (g_bio_vtbl.p_gets == NULL || bio == NULL || buf == NULL || size <= 0)
        return -1;
    return g_bio_vtbl.p_gets(bio, buf, size);
}

int km_prov_bio_puts(OSSL_CORE_BIO *bio, const char *str)
{
    if (g_bio_vtbl.p_puts == NULL || bio == NULL || str == NULL)
        return -1;
    return g_bio_vtbl.p_puts(bio, str);
}

int km_prov_bio_ctrl(OSSL_CORE_BIO *bio, int cmd, long num, void *ptr)
{
    if (g_bio_vtbl.p_ctrl == NULL || bio == NULL)
        return -1;
    return g_bio_vtbl.p_ctrl(bio, cmd, num, ptr);
}

int km_prov_bio_up_ref(OSSL_CORE_BIO *bio)
{
    if (g_bio_vtbl.p_up_ref == NULL || bio == NULL)
        return 0;
    return g_bio_vtbl.p_up_ref(bio);
}

int km_prov_bio_free(OSSL_CORE_BIO *bio)
{
    if (g_bio_vtbl.p_free == NULL || bio == NULL)
        return 0;
    return g_bio_vtbl.p_free(bio);
}

int km_prov_bio_vprintf(OSSL_CORE_BIO *bio, const char *format, va_list ap)
{
    if (g_bio_vtbl.p_vprintf == NULL || bio == NULL || format == NULL)
        return -1;
    return g_bio_vtbl.p_vprintf(bio, format, ap);
}

int km_prov_bio_printf(OSSL_CORE_BIO *bio, const char *format, ...)
{
    if (format == NULL)
        return -1;

    va_list ap;
    va_start(ap, format);
    const int r = km_prov_bio_vprintf(bio, format, ap);
    va_end(ap);
    return r;
}

/* ------------------------------------------------------------------------- */
/*                           BIO_METHOD bridge (non-FIPS)                    */
/* ------------------------------------------------------------------------- */

#ifndef FIPS_MODULE
/* No direct BIO support in the FIPS module */

static int km_bio_bridge_read_ex(BIO *bio, char *data, size_t data_len,
                                 size_t *bytes_read)
{
    return km_prov_bio_read_ex((OSSL_CORE_BIO *)BIO_get_data(bio),
                               data, data_len, bytes_read);
}

static int km_bio_bridge_write_ex(BIO *bio, const char *data, size_t data_len,
                                  size_t *written)
{
    return km_prov_bio_write_ex((OSSL_CORE_BIO *)BIO_get_data(bio),
                                data, data_len, written);
}

static long km_bio_bridge_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    return km_prov_bio_ctrl((OSSL_CORE_BIO *)BIO_get_data(bio),
                            cmd, num, ptr);
}

static int km_bio_bridge_gets(BIO *bio, char *buf, int size)
{
    return km_prov_bio_gets((OSSL_CORE_BIO *)BIO_get_data(bio),
                            buf, size);
}

static int km_bio_bridge_puts(BIO *bio, const char *str)
{
    return km_prov_bio_puts((OSSL_CORE_BIO *)BIO_get_data(bio),
                            str);
}

static int km_bio_bridge_new(BIO *bio)
{
    BIO_set_init(bio, 1);
    BIO_set_data(bio, NULL);
    return 1;
}

static int km_bio_bridge_free(BIO *bio)
{
    OSSL_CORE_BIO *core = (OSSL_CORE_BIO *)BIO_get_data(bio);
    BIO_set_init(bio, 0);
    BIO_set_data(bio, NULL);
    if (core != NULL)
        (void)km_prov_bio_free(core);
    return 1;
}

BIO_METHOD *km_bio_prov_init_bio_method(void)
{
    BIO_METHOD *m = BIO_meth_new(BIO_TYPE_CORE_TO_PROV, "core<->prov bridge");
    if (m == NULL)
        return NULL;

    if (!BIO_meth_set_write_ex(m, km_bio_bridge_write_ex) ||
        !BIO_meth_set_read_ex (m, km_bio_bridge_read_ex)  ||
        !BIO_meth_set_puts    (m, km_bio_bridge_puts)     ||
        !BIO_meth_set_gets    (m, km_bio_bridge_gets)     ||
        !BIO_meth_set_ctrl    (m, km_bio_bridge_ctrl)     ||
        !BIO_meth_set_create  (m, km_bio_bridge_new)      ||
        !BIO_meth_set_destroy (m, km_bio_bridge_free)) {
        BIO_meth_free(m);
        return NULL;
    }
    return m;
}

BIO *km_bio_new_from_core_bio(PROV_KM_CTX *provctx, OSSL_CORE_BIO *corebio)
{
    if (provctx == NULL || provctx->corebiometh == NULL || corebio == NULL)
        return NULL;

    BIO *b = BIO_new(provctx->corebiometh);
    if (b == NULL)
        return NULL;

    if (!km_prov_bio_up_ref(corebio)) {
        BIO_free(b);
        return NULL;
    }

    BIO_set_data(b, corebio);
    BIO_set_init(b, 1);
    return b;
}
#endif /* !FIPS_MODULE */
