#ifndef __SESSION_H__
#define __SESSION_H__

/*--------------------------------------------------------------------------
 *
 * Copyright (C) 2013 Daurnimator
 *
 *--------------------------------------------------------------------------*/

#include <openssl/ssl.h>
#include <lua.h>

#include "context.h"

void pushSSL_SESSION (lua_State *L, SSL_SESSION *p);
SSL_SESSION * checkSSL_SESSION (lua_State *L, int narg);

LUASEC_API int luaopen_ssl_session(lua_State *L);

#endif
