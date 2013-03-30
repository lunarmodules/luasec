#ifndef LSEC_X509_H
#define LSEC_X509_H

/*--------------------------------------------------------------------------
 * LuaSec 0.4.1
 * Copyright (C) 2012
 *
 *--------------------------------------------------------------------------*/

#include <openssl/x509v3.h>
#include <lua.h>

#include "config.h"

typedef struct t_x509_ {
  X509 *cert;
} t_x509;
typedef t_x509* p_x509;

void  lsec_pushx509(lua_State* L, X509* cert);
X509* lsec_checkx509(lua_State* L, int idx);

LSEC_API int luaopen_ssl_x509(lua_State *L);

#endif
