
/*
 * Copyright (C) Gabriel Clima
 *
 * The fingerprint computation logic in this file (GREASE filter, ja3
 * formatting) is derived from nginx-ssl-ja3
 *   https://github.com/fooinha/nginx-ssl-ja3
 * Copyright (C) 2017-2019 Paulo Pacheco, BSD-2-Clause licensed.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#if (NGX_HTTP_SSL)


#include <ngx_md5.h>

#include "ngx_http_lua_common.h"
#include "ngx_http_lua_ssl.h"
#include "ngx_http_lua_ssl_ja3.h"


int  ngx_http_lua_ssl_ja3_index = -1;


static const unsigned short  ngx_http_lua_ssl_ja3_grease[] = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
    0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
};


static int
ngx_http_lua_ssl_ja3_is_grease(unsigned int v)
{
    size_t  i;

    for (i = 0;
         i < sizeof(ngx_http_lua_ssl_ja3_grease)
                / sizeof(ngx_http_lua_ssl_ja3_grease[0]);
         i++)
    {
        if (v == ngx_http_lua_ssl_ja3_grease[i]) {
            return 1;
        }
    }

    return 0;
}


static int
ngx_http_lua_ssl_ja3_cmp_int(const void *a, const void *b)
{
    int  ia = *(const int *) a;
    int  ib = *(const int *) b;

    return (ia > ib) - (ia < ib);
}


static size_t
ngx_http_lua_ssl_ja3_num_digits(unsigned int n)
{
    size_t  c = 1;

    while (n >= 10) {
        n /= 10;
        c++;
    }

    return c;
}


/* Collect ClientHello fields needed by JA3.  Buffers are allocated on pool;
 * pool MUST outlive the cached struct, so callers pass the connection pool.
 *
 * The underlying OpenSSL accessors only succeed during the ClientHello
 * callback (i.e. ssl_client_hello_by_lua* phase), so this routine returns
 * NGX_DECLINED when called later. */
static ngx_int_t
ngx_http_lua_ssl_ja3_collect(ngx_ssl_conn_t *ssl_conn, ngx_pool_t *pool,
    ngx_http_lua_ssl_ja3_t *ja3)
{
#ifdef SSL_ERROR_WANT_CLIENT_HELLO_CB
    int                     *ext_out;
    size_t                   i, ext_len, plen;
    const unsigned char     *p;
    unsigned short           v;

    ngx_memzero(ja3, sizeof(*ja3));

    /* TLS legacy_version field of the ClientHello (always 0x0303 for any
     * TLS 1.2+ client; for TLS 1.3 the negotiated version is in the
     * supported_versions extension, but JA3 uses legacy_version). */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    {
        unsigned int  legacy;

        legacy = SSL_client_hello_get0_legacy_version(ssl_conn);
        ja3->version = (int) legacy;
    }
#else
    ja3->version = SSL_client_version(ssl_conn);
#endif

    /* Extensions, in ClientHello order; OpenSSL allocates ext_out for us. */
    ext_out = NULL;
    ext_len = 0;

    if (!SSL_client_hello_get1_extensions_present(ssl_conn, &ext_out, &ext_len)
        || ext_out == NULL)
    {
        /* Either we are not inside the ClientHello callback, or there are no
         * extensions at all (extremely unlikely for any modern client). */
        return NGX_DECLINED;
    }

    if (ext_len > 0) {
        ja3->extensions = ngx_palloc(pool, sizeof(int) * ext_len);
        if (ja3->extensions == NULL) {
            OPENSSL_free(ext_out);
            return NGX_ERROR;
        }

        for (i = 0; i < ext_len; i++) {
            if (!ngx_http_lua_ssl_ja3_is_grease((unsigned int) ext_out[i])) {
                ja3->extensions[ja3->extensions_n++] = ext_out[i];
            }
        }

        /* Chrome 110+ permutes ClientHello extension order to defeat stable
         * fingerprinting; sort to recover stability (the "JA3N" variant). */
        if (ja3->extensions_n > 1) {
            ngx_qsort(ja3->extensions, ja3->extensions_n, sizeof(int),
                      ngx_http_lua_ssl_ja3_cmp_int);
        }
    }

    OPENSSL_free(ext_out);

    /* Cipher suites (raw network byte order, two bytes per cipher) */
    plen = SSL_client_hello_get0_ciphers(ssl_conn, &p);
    if (plen > 0 && (plen & 1) == 0) {
        ja3->ciphers = ngx_palloc(pool, sizeof(unsigned short) * (plen / 2));
        if (ja3->ciphers == NULL) {
            return NGX_ERROR;
        }

        for (i = 0; i < plen; i += 2) {
            v = ((unsigned short) p[i] << 8) | p[i + 1];
            if (!ngx_http_lua_ssl_ja3_is_grease(v)) {
                ja3->ciphers[ja3->ciphers_n++] = v;
            }
        }
    }

    /* supported_groups (formerly elliptic_curves), extension type 10 */
    if (SSL_client_hello_get0_ext(ssl_conn, 10, &p, &plen)
        && plen >= 2 && ((plen - 2) & 1) == 0)
    {
        size_t                list_bytes;
        const unsigned char  *q;

        list_bytes = plen - 2;       /* first 2 bytes are the list length */
        q = p + 2;

        ja3->curves = ngx_palloc(pool,
                                 sizeof(unsigned short) * (list_bytes / 2));
        if (ja3->curves == NULL) {
            return NGX_ERROR;
        }

        for (i = 0; i < list_bytes; i += 2) {
            v = ((unsigned short) q[i] << 8) | q[i + 1];
            if (!ngx_http_lua_ssl_ja3_is_grease(v)) {
                ja3->curves[ja3->curves_n++] = v;
            }
        }
    }

    /* ec_point_formats, extension type 11 */
    if (SSL_client_hello_get0_ext(ssl_conn, 11, &p, &plen) && plen >= 1) {
        size_t  list_bytes = plen - 1;  /* first byte is the list length */

        ja3->point_formats = ngx_palloc(pool, list_bytes);
        if (ja3->point_formats == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(ja3->point_formats, p + 1, list_bytes);
        ja3->point_formats_n = list_bytes;
    }

    return NGX_OK;

#else
    return NGX_DECLINED;
#endif
}


/* JA3 fingerprint string formatting.  Adapted from nginx-ssl-ja3
 * (Paulo Pacheco, BSD-2-Clause). */
static ngx_int_t
ngx_http_lua_ssl_ja3_format(ngx_pool_t *pool,
    const ngx_http_lua_ssl_ja3_t *ja3, ngx_str_t *out)
{
    size_t   i, len;
    u_char  *p;

    len = ngx_http_lua_ssl_ja3_num_digits((unsigned int) ja3->version) + 1;

    for (i = 0; i < ja3->ciphers_n; i++) {
        len += ngx_http_lua_ssl_ja3_num_digits(ja3->ciphers[i])
               + (i ? 1 : 0);
    }
    len++;

    for (i = 0; i < ja3->extensions_n; i++) {
        len += ngx_http_lua_ssl_ja3_num_digits(
                   (unsigned int) ja3->extensions[i])
               + (i ? 1 : 0);
    }
    len++;

    for (i = 0; i < ja3->curves_n; i++) {
        len += ngx_http_lua_ssl_ja3_num_digits(ja3->curves[i])
               + (i ? 1 : 0);
    }
    len++;

    for (i = 0; i < ja3->point_formats_n; i++) {
        len += ngx_http_lua_ssl_ja3_num_digits(ja3->point_formats[i])
               + (i ? 1 : 0);
    }

    out->data = ngx_pnalloc(pool, len);
    if (out->data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_sprintf(out->data, "%d,", ja3->version);

    for (i = 0; i < ja3->ciphers_n; i++) {
        if (i) {
            *p++ = '-';
        }
        p = ngx_sprintf(p, "%ud", (unsigned int) ja3->ciphers[i]);
    }
    *p++ = ',';

    for (i = 0; i < ja3->extensions_n; i++) {
        if (i) {
            *p++ = '-';
        }
        p = ngx_sprintf(p, "%ud", (unsigned int) ja3->extensions[i]);
    }
    *p++ = ',';

    for (i = 0; i < ja3->curves_n; i++) {
        if (i) {
            *p++ = '-';
        }
        p = ngx_sprintf(p, "%ud", (unsigned int) ja3->curves[i]);
    }
    *p++ = ',';

    for (i = 0; i < ja3->point_formats_n; i++) {
        if (i) {
            *p++ = '-';
        }
        p = ngx_sprintf(p, "%ud", (unsigned int) ja3->point_formats[i]);
    }

    out->len = p - out->data;
    return NGX_OK;
}


static ngx_int_t
ngx_http_lua_ssl_ja3_md5_hex(ngx_pool_t *pool, ngx_str_t *fp,
    ngx_str_t *hash_hex)
{
    ngx_md5_t  md5;
    u_char     md[16];

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, fp->data, fp->len);
    ngx_md5_final(md, &md5);

    hash_hex->data = ngx_pnalloc(pool, 32);
    if (hash_hex->data == NULL) {
        return NGX_ERROR;
    }

    ngx_hex_dump(hash_hex->data, md, sizeof(md));
    hash_hex->len = 32;
    return NGX_OK;
}


/* Returns the JA3 fingerprint string for the current SSL connection.
 * Computes and caches the value the first time it is called, which must
 * be during the ssl_client_hello_by_lua* phase (the underlying OpenSSL
 * ClientHello accessors are only valid then).  Subsequent calls in any
 * later phase that still has access to r->connection->ssl return the
 * cached string in O(1).
 *
 * Out and outlen are caller-provided pointers; on success they are filled
 * in with a pointer/length to a buffer owned by the connection pool.  The
 * buffer is valid until the connection is released. */
int
ngx_http_lua_ffi_ssl_get_ja3(ngx_http_request_t *r, const char **out,
    size_t *outlen, char **err)
{
    ngx_connection_t              *c;
    ngx_ssl_conn_t                *ssl_conn;
    ngx_http_lua_ssl_ja3_cache_t  *cache;
    ngx_http_lua_ssl_ja3_t         ja3;
    ngx_int_t                      rc;

    if (r->connection == NULL || r->connection->ssl == NULL) {
        *err = "bad request";
        return NGX_ERROR;
    }

    ssl_conn = r->connection->ssl->connection;
    if (ssl_conn == NULL) {
        *err = "bad ssl conn";
        return NGX_ERROR;
    }

    /* In ssl_client_hello_by_lua* the request is a fake request bound to a
     * fake connection whose pool dies when the handshake finishes.  We
     * always need to allocate the cache and its buffers on the REAL
     * connection's pool so they outlive that scope and are reachable from
     * later phases. */
    c = ngx_ssl_get_connection(ssl_conn);
    if (c == NULL) {
        *err = "no real connection bound to ssl";
        return NGX_ERROR;
    }

    cache = SSL_get_ex_data(ssl_conn, ngx_http_lua_ssl_ja3_index);
    if (cache != NULL && cache->ja3.len) {
        *out = (const char *) cache->ja3.data;
        *outlen = cache->ja3.len;
        return NGX_OK;
    }

    rc = ngx_http_lua_ssl_ja3_collect(ssl_conn, c->pool, &ja3);
    if (rc == NGX_DECLINED) {
        *err = "ja3 not available: must be initialized in "
               "ssl_client_hello_by_lua*";
        return NGX_DECLINED;
    }

    if (rc != NGX_OK) {
        *err = "ja3 collection failed";
        return NGX_ERROR;
    }

    if (cache == NULL) {
        cache = ngx_pcalloc(c->pool, sizeof(*cache));
        if (cache == NULL) {
            *err = "no memory";
            return NGX_ERROR;
        }

        if (SSL_set_ex_data(ssl_conn, ngx_http_lua_ssl_ja3_index, cache) != 1)
        {
            *err = "SSL_set_ex_data() failed";
            return NGX_ERROR;
        }
    }

    if (ngx_http_lua_ssl_ja3_format(c->pool, &ja3, &cache->ja3) != NGX_OK) {
        *err = "ja3 format failed";
        return NGX_ERROR;
    }

    *out = (const char *) cache->ja3.data;
    *outlen = cache->ja3.len;
    return NGX_OK;
}


int
ngx_http_lua_ffi_ssl_get_ja3_hash(ngx_http_request_t *r, const char **out,
    size_t *outlen, char **err)
{
    ngx_connection_t              *c;
    ngx_ssl_conn_t                *ssl_conn;
    ngx_http_lua_ssl_ja3_cache_t  *cache;
    const char                    *fp;
    size_t                         fplen;
    ngx_str_t                      fp_str;
    int                            rc;

    if (r->connection == NULL || r->connection->ssl == NULL) {
        *err = "bad request";
        return NGX_ERROR;
    }

    ssl_conn = r->connection->ssl->connection;
    if (ssl_conn == NULL) {
        *err = "bad ssl conn";
        return NGX_ERROR;
    }

    c = ngx_ssl_get_connection(ssl_conn);
    if (c == NULL) {
        *err = "no real connection bound to ssl";
        return NGX_ERROR;
    }

    cache = SSL_get_ex_data(ssl_conn, ngx_http_lua_ssl_ja3_index);
    if (cache != NULL && cache->ja3_hash.len) {
        *out = (const char *) cache->ja3_hash.data;
        *outlen = cache->ja3_hash.len;
        return NGX_OK;
    }

    /* This both populates the fingerprint string and ensures the cache
     * struct is attached to the SSL ex_data. */
    rc = ngx_http_lua_ffi_ssl_get_ja3(r, &fp, &fplen, err);
    if (rc != NGX_OK) {
        return rc;
    }

    cache = SSL_get_ex_data(ssl_conn, ngx_http_lua_ssl_ja3_index);
    if (cache == NULL) {
        *err = "ja3 cache missing after compute";
        return NGX_ERROR;
    }

    fp_str.data = (u_char *) fp;
    fp_str.len = fplen;

    if (ngx_http_lua_ssl_ja3_md5_hex(c->pool, &fp_str, &cache->ja3_hash)
        != NGX_OK)
    {
        *err = "ja3 hash format failed";
        return NGX_ERROR;
    }

    *out = (const char *) cache->ja3_hash.data;
    *outlen = cache->ja3_hash.len;
    return NGX_OK;
}


#endif /* NGX_HTTP_SSL */
