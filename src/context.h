#ifndef __CONTEXT_H__
#define __CONTEXT_H__

/*--------------------------------------------------------------------------
 * LuaSec 0.4
 * Copyright (C) 2006-2009 Bruno Silvestre
 *
 *--------------------------------------------------------------------------*/

#include <lua.h>
#include <openssl/ssl.h>

#if defined(_WIN32)
#define LUASEC_API __declspec(dllexport) 
#else
#define LUASEC_API extern
#endif

#define MD_CTX_INVALID 0
#define MD_CTX_SERVER 1
#define MD_CTX_CLIENT 2

typedef struct t_context_ {
  SSL_CTX *context;
  char mode;
} t_context;
typedef t_context* p_context;

/* Retrieve the SSL context from the Lua stack */
SSL_CTX *ctx_getcontext(lua_State *L, int idx);
/* Retrieve the mode from the context in the Lua stack */
char ctx_getmode(lua_State *L, int idx);

/* Registre the module. */
LUASEC_API int luaopen_ssl_context(lua_State *L);

#endif
