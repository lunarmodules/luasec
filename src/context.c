/*--------------------------------------------------------------------------
 * LuaSec 0.4.1
 * Copyright (C) 2006-2011 Bruno Silvestre
 *
 *--------------------------------------------------------------------------*/

#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <lua.h>
#include <lauxlib.h>

#include "context.h"
#include "options.h"

/*--------------------------- Auxiliary Functions ----------------------------*/

/**
 * Return the context.
 */
static p_context checkctx(lua_State *L, int idx)
{
  return (p_context)luaL_checkudata(L, idx, "SSL:Context");
}

/**
 * Prepare the SSL options flag.
 */
static int set_option_flag(const char *opt, unsigned long *flag)
{
  ssl_option_t *p;
  for (p = ssl_options; p->name; p++) {
    if (!strcmp(opt, p->name)) {
      *flag |= p->code;
      return 1;
    }
  }
  return 0;
}

/**
 * Find the protocol.
 */
static SSL_METHOD* str2method(const char *method)
{
  if (!strcmp(method, "sslv3"))  return SSLv3_method();
  if (!strcmp(method, "tlsv1"))  return TLSv1_method();
  if (!strcmp(method, "sslv23")) return SSLv23_method();
  return NULL;
}

/**
 * Prepare the SSL handshake verify flag.
 */
static int set_verify_flag(const char *str, int *flag)
{
  if (!strcmp(str, "none")) { 
    *flag |= SSL_VERIFY_NONE;
    return 1;
  }
  if (!strcmp(str, "peer")) {
    *flag |= SSL_VERIFY_PEER;
    return 1;
  }
  if (!strcmp(str, "client_once")) {
    *flag |= SSL_VERIFY_CLIENT_ONCE;
    return 1;
  }
  if (!strcmp(str, "fail_if_no_peer_cert")) { 
    *flag |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    return 1;
  }
  return 0;
}

/**
 * Password callback for reading the private key.
 */
static int passwd_cb(char *buf, int size, int flag, void *udata)
{
  lua_State *L = (lua_State*)udata;
  switch (lua_type(L, 3)) {
  case LUA_TFUNCTION:
    lua_pushvalue(L, 3);
    lua_call(L, 0, 1);
    if (lua_type(L, -1) != LUA_TSTRING)
       return 0;
    /* fallback */
  case LUA_TSTRING:
    strncpy(buf, lua_tostring(L, -1), size);
    buf[size-1] = '\0';
    return (int)strlen(buf);
  }
  return 0;
}

/*------------------------------ Lua Functions -------------------------------*/

/**
 * Create a SSL context.
 */
static int create(lua_State *L)
{
  p_context ctx;
  SSL_METHOD *method;

  method = str2method(luaL_checkstring(L, 1));
  if (!method) {
    lua_pushnil(L);
    lua_pushstring(L, "invalid protocol");
    return 2;
  }
  ctx = (p_context) lua_newuserdata(L, sizeof(t_context));
  if (!ctx) {
    lua_pushnil(L);
    lua_pushstring(L, "error creating context");
    return 2;
  }  
  ctx->context = SSL_CTX_new(method);
  if (!ctx->context) {
    lua_pushnil(L);
    lua_pushstring(L, "error creating context");
    return 2;
  }
  ctx->mode = MD_CTX_INVALID;
  /* No session support */
  SSL_CTX_set_session_cache_mode(ctx->context, SSL_SESS_CACHE_OFF);
  luaL_getmetatable(L, "SSL:Context");
  lua_setmetatable(L, -2);
  return 1;
}

/**
 * Load the trusting certificates.
 */
static int load_locations(lua_State *L)
{
  SSL_CTX *ctx = ctx_getcontext(L, 1);
  const char *cafile = luaL_optstring(L, 2, NULL);
  const char *capath = luaL_optstring(L, 3, NULL);
  if (SSL_CTX_load_verify_locations(ctx, cafile, capath) != 1) {
    lua_pushboolean(L, 0);
    lua_pushfstring(L, "error loading CA locations (%s)",
      ERR_reason_error_string(ERR_get_error()));
    return 2;
  }
  lua_pushboolean(L, 1);
  return 1;
}

/**
 * Load the certificate file.
 */
static int load_cert(lua_State *L)
{
  SSL_CTX *ctx = ctx_getcontext(L, 1);
  const char *filename = luaL_checkstring(L, 2);
  if (SSL_CTX_use_certificate_chain_file(ctx, filename) != 1) {
    lua_pushboolean(L, 0);
    lua_pushfstring(L, "error loading certificate (%s)",
      ERR_reason_error_string(ERR_get_error()));
    return 2;
  }
  lua_pushboolean(L, 1);
  return 1;
}

/**
 * Load the key file -- only in PEM format.
 */
static int load_key(lua_State *L)
{
  int ret = 1;
  SSL_CTX *ctx = ctx_getcontext(L, 1);
  const char *filename = luaL_checkstring(L, 2);
  switch (lua_type(L, 3)) {
  case LUA_TSTRING:
  case LUA_TFUNCTION:
    SSL_CTX_set_default_passwd_cb(ctx, passwd_cb);
    SSL_CTX_set_default_passwd_cb_userdata(ctx, L);
    /* fallback */
  case LUA_TNIL: 
    if (SSL_CTX_use_PrivateKey_file(ctx, filename, SSL_FILETYPE_PEM) == 1)
      lua_pushboolean(L, 1);
    else {
      ret = 2;
      lua_pushboolean(L, 0);
      lua_pushfstring(L, "error loading private key (%s)",
        ERR_reason_error_string(ERR_get_error()));
    }
    SSL_CTX_set_default_passwd_cb(ctx, NULL);
    SSL_CTX_set_default_passwd_cb_userdata(ctx, NULL);
    break;
  default:
    lua_pushstring(L, "invalid callback value");
    lua_error(L);
  }
  return ret;
}

/**
 * Set the cipher list.
 */
static int set_cipher(lua_State *L)
{
  SSL_CTX *ctx = ctx_getcontext(L, 1);
  const char *list = luaL_checkstring(L, 2);
  if (SSL_CTX_set_cipher_list(ctx, list) != 1) {
    lua_pushboolean(L, 0);
    lua_pushfstring(L, "error setting cipher list (%s)",
      ERR_reason_error_string(ERR_get_error()));
    return 2;
  }
  lua_pushboolean(L, 1);
  return 1;
}

/**
 * Set the depth for certificate checking.
 */
static int set_depth(lua_State *L)
{
  SSL_CTX *ctx = ctx_getcontext(L, 1);
  SSL_CTX_set_verify_depth(ctx, luaL_checkint(L, 2));
  lua_pushboolean(L, 1);
  return 1;
}

/**
 * Set the handshake verify options.
 */
static int set_verify(lua_State *L)
{
  int i;
  int flag = 0;
  SSL_CTX *ctx = ctx_getcontext(L, 1);
  int max = lua_gettop(L);
  /* any flag? */
  if (max > 1) {
    for (i = 2; i <= max; i++) {
      if (!set_verify_flag(luaL_checkstring(L, i), &flag)) {
        lua_pushboolean(L, 0);
        lua_pushstring(L, "invalid verify option");
        return 2;
      }
    }
    SSL_CTX_set_verify(ctx, flag, NULL);
  }
  lua_pushboolean(L, 1);
  return 1;
}

/**
 * Set the protocol options.
 */
static int set_options(lua_State *L)
{
  int i;
  unsigned long flag = 0L;
  SSL_CTX *ctx = ctx_getcontext(L, 1);
  int max = lua_gettop(L);
  /* any option? */
  if (max > 1) {
    for (i = 2; i <= max; i++) {
      if (!set_option_flag(luaL_checkstring(L, i), &flag)) {
        lua_pushboolean(L, 0);
        lua_pushstring(L, "invalid option");
        return 2;
      }
    }
    SSL_CTX_set_options(ctx, flag);
  }
  lua_pushboolean(L, 1);
  return 1;
}

/**
 * Set the context mode.
 */
static int set_mode(lua_State *L)
{
  p_context ctx = checkctx(L, 1);
  const char *str = luaL_checkstring(L, 2);
  if (!strcmp("server", str)) {
    ctx->mode = MD_CTX_SERVER;
    lua_pushboolean(L, 1);
    return 1;
  }
  if(!strcmp("client", str)) {
    ctx->mode = MD_CTX_CLIENT;
    lua_pushboolean(L, 1);
    return 1;
  }
  lua_pushboolean(L, 0);
  lua_pushstring(L, "invalid mode");
  return 1;
}   

/**
 * Return a pointer to SSL_CTX structure.
 */
static int raw_ctx(lua_State *L)
{
  p_context ctx = checkctx(L, 1);
  lua_pushlightuserdata(L, (void*)ctx->context);
  return 1;
}

/**
 * Package functions
 */
static luaL_Reg funcs[] = {
  {"create",     create},
  {"locations",  load_locations},
  {"loadcert",   load_cert},
  {"loadkey",    load_key},
  {"setcipher",  set_cipher},
  {"setdepth",   set_depth},
  {"setverify",  set_verify},
  {"setoptions", set_options},
  {"setmode",    set_mode},
  {"rawcontext", raw_ctx},
  {NULL, NULL}
};

/*-------------------------------- Metamethods -------------------------------*/

/**
 * Collect SSL context -- GC metamethod.
 */
static int meth_destroy(lua_State *L)
{
  p_context ctx = checkctx(L, 1);
  if (ctx->context) {
    SSL_CTX_free(ctx->context);
    ctx->context = NULL;
  }
  return 0;
}

/**
 * Object information -- tostring metamethod.
 */
static int meth_tostring(lua_State *L)
{
  p_context ctx = checkctx(L, 1);
  lua_pushfstring(L, "SSL context: %p", ctx);
  return 1;
}

/**
 * Context metamethods.
 */
static luaL_Reg meta[] = {
  {"__gc",       meth_destroy},
  {"__tostring", meth_tostring},
  {NULL, NULL}
};


/*----------------------------- Public Functions  ---------------------------*/

/**
 * Retrieve the SSL context from the Lua stack.
 */
SSL_CTX* ctx_getcontext(lua_State *L, int idx)
{
  p_context ctx = checkctx(L, idx);
  return ctx->context;
}

/**
 * Retrieve the mode from the context in the Lua stack.
 */
char ctx_getmode(lua_State *L, int idx)
{
  p_context ctx = checkctx(L, idx);
  return ctx->mode;
}

/*------------------------------ Initialization ------------------------------*/

/**
 * Registre the module.
 */
int luaopen_ssl_context(lua_State *L)
{
  luaL_newmetatable(L, "SSL:Context");
  luaL_register(L, NULL, meta);
  luaL_register(L, "ssl.context", funcs);
  return 1;
}
