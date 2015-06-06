/*--------------------------------------------------------------------------
 * LuaSec 0.5
 * Copyright (C) 2006-2014 Bruno Silvestre
 *
 *--------------------------------------------------------------------------*/

#ifndef LSEC_CONFIG_H
#define LSEC_CONFIG_H

#if defined(_WIN32)
#define LSEC_API __declspec(dllexport) 
#elif defined(__GNUC__)
#define LSEC_API extern __attribute__((visibility ("default")))
#else
#define LSEC_API extern
#endif

#if (LUA_VERSION_NUM == 501)
#define setfuncs(L, R)    luaL_register(L, NULL, R)
#define lua_rawlen(L, i)  lua_objlen(L, i)
#define luaL_newlib(L, R) do { lua_newtable(L); luaL_register(L, NULL, R); } while(0)
#else
#define setfuncs(L, R) luaL_setfuncs(L, R, 0)
#endif

#endif
