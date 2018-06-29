/*--------------------------------------------------------------------------
 * LuaSec 0.7
 *
 * Copyright (C) 2006-2018 Bruno Silvestre.
 *
 *--------------------------------------------------------------------------*/

#include "compat.h"
#include "options.h"
#include "ec.h"

/**
 * Registre the module.
 */
LSEC_API int luaopen_ssl_config(lua_State *L)
{
  ssl_option_t *opt;

  lua_newtable(L);

  // Options
  lua_pushstring(L, "options");
  lua_newtable(L);
  for (opt = ssl_options; opt->name; opt++) {
    lua_pushstring(L, opt->name);
    lua_pushboolean(L, 1);
    lua_rawset(L, -3);
  }
  lua_rawset(L, -3);

  // Protocols
  lua_pushstring(L, "protocols");
  lua_newtable(L);

  lua_pushstring(L, "tlsv1");
  lua_pushboolean(L, 1);
  lua_rawset(L, -3);
#if (OPENSSL_VERSION_NUMBER >= 0x1000100fL)
  lua_pushstring(L, "tlsv1_1");
  lua_pushboolean(L, 1);
  lua_rawset(L, -3);
  lua_pushstring(L, "tlsv1_2");
  lua_pushboolean(L, 1);
  lua_rawset(L, -3);
#endif
  lua_rawset(L, -3);

  // Algorithms
  lua_pushstring(L, "algorithms");
  lua_newtable(L);

#ifndef OPENSSL_NO_EC
  lua_pushstring(L, "ec");
  lua_pushboolean(L, 1);
  lua_rawset(L, -3);
#endif
  lua_rawset(L, -3);
 
  // Curves
  lua_pushstring(L, "curves");
  lsec_get_curves(L);
  lua_rawset(L, -3);

  // Capabilities
  lua_pushstring(L, "capabilities");
  lua_newtable(L);

#ifndef OPENSSL_NO_EC
#if defined(SSL_CTRL_SET_ECDH_AUTO) || defined(SSL_CTRL_SET_CURVES_LIST) || defined(SSL_CTX_set1_curves_list)
  lua_pushstring(L, "curves_list");
  lua_pushboolean(L, 1);
  lua_rawset(L, -3);
#ifdef SSL_CTRL_SET_ECDH_AUTO
  lua_pushstring(L, "ecdh_auto");
  lua_pushboolean(L, 1);
  lua_rawset(L, -3);
#endif
#endif
#endif
  lua_rawset(L, -3);

  return 1;
}
