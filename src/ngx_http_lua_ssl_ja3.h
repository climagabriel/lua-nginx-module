
/*
 * Copyright (C) Gabriel Clima
 */


#ifndef _NGX_HTTP_LUA_SSL_JA3_H_INCLUDED_
#define _NGX_HTTP_LUA_SSL_JA3_H_INCLUDED_


#include "ngx_http_lua_common.h"


#if (NGX_HTTP_SSL)


typedef struct {
    int               version;

    size_t            ciphers_n;
    unsigned short   *ciphers;

    size_t            extensions_n;
    int              *extensions;

    size_t            curves_n;
    unsigned short   *curves;

    size_t            point_formats_n;
    unsigned char    *point_formats;
} ngx_http_lua_ssl_ja3_t;


typedef struct {
    ngx_str_t         ja3;          /* JA3 string, ClientHello extension order */
    ngx_str_t         ja3_hash;     /* hex md5 of ja3 */
} ngx_http_lua_ssl_ja3_cache_t;


extern int ngx_http_lua_ssl_ja3_index;


#endif /* NGX_HTTP_SSL */


#endif /* _NGX_HTTP_LUA_SSL_JA3_H_INCLUDED_ */
