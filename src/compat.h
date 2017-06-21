/*--------------------------------------------------------------------------
 * LuaSec 0.6
 * Copyright (C) 2006-2016 Bruno Silvestre
 *
 *--------------------------------------------------------------------------*/

#ifndef LSEC_COMPAT_H
#define LSEC_COMPAT_H

#if defined(_WIN32)
#define LSEC_API __declspec(dllexport) 
#else
#define LSEC_API extern
#endif

#if (LUA_VERSION_NUM == 501)
#define setfuncs(L, R)    luaL_register(L, NULL, R)
#define lua_rawlen(L, i)  lua_objlen(L, i)
#ifndef luaL_newlib
#define luaL_newlib(L, R) do { lua_newtable(L); luaL_register(L, NULL, R); } while(0)
#endif
#else
#define setfuncs(L, R) luaL_setfuncs(L, R, 0)
#endif

#endif
