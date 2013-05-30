/*--------------------------------------------------------------------------
 *
 * Copyright (C) 2013 Daurnimator
 *
 *--------------------------------------------------------------------------*/

#include <lua.h>
#include <lauxlib.h>

#include "session.h"

static void check_mt(lua_State *L);

void pushSSL_SESSION (lua_State *L, SSL_SESSION *p) {
	check_mt(L);
	*(SSL_SESSION **)lua_newuserdata(L,sizeof(SSL_SESSION *)) = p;
	luaL_getmetatable(L, "SSL:Session");
	lua_setmetatable(L, -2);
}

SSL_SESSION * checkSSL_SESSION (lua_State *L, int narg) {
	return *(SSL_SESSION **)luaL_checkudata(L, narg, "SSL:Session");
}

/**
 * Collect SSL session -- GC metamethod.
 */
static int session_free(lua_State *L)
{
	SSL_SESSION_free(checkSSL_SESSION(L, 1));
	return 0;
}

/**
 * Returns ASN1 representation of session
 */
static int session_asn1(lua_State *L)
{
	SSL_SESSION *sess = checkSSL_SESSION(L, 1);
	int len = i2d_SSL_SESSION(sess , NULL);
	/* Allocate room for ASN1 representation on lua stack */
	void* buff = lua_newuserdata(L,len);
	i2d_SSL_SESSION(sess , (unsigned char**)&buff);
	lua_pushlstring(L, (char*)buff, len);
	return 1;
}

/**
 * SSL session -- tostring metamethod.
 */
static int session_tostring(lua_State *L)
{
  	lua_pushfstring(L, "SSL session: %p", checkSSL_SESSION(L, 1));
	return 1;
}

/**
 * Session metamethods 
 */
static luaL_Reg meta[] = {
	{"__gc",        session_free},
	{"__tostring",  session_tostring},
	{"asn1",        session_asn1},
	{NULL,          NULL}
};

static void check_mt(lua_State *L) {
	if (luaL_newmetatable(L, "SSL:Session")) {
		/* meta.__index = meta */
		lua_pushvalue(L,-1);
		lua_setfield(L,-2,"__index");

		luaL_register(L, NULL, meta);
	}
}
