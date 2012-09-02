/*--------------------------------------------------------------------------
 * LuaSec 0.4
 * Copyright (C) 2006-2009 Bruno Silvestre
 *
 *--------------------------------------------------------------------------*/

#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <lua.h>
#include <lauxlib.h>

#include "io.h"
#include "buffer.h"
#include "timeout.h"
#include "socket.h"
#include "ssl.h"

/**
 * Map error code into string.
 */
static const char *ssl_ioerror(void *ctx, int err)
{
  if (err == IO_SSL) {
    p_ssl ssl = (p_ssl) ctx;
    switch(ssl->error) {
    case SSL_ERROR_NONE: return "No error";
    case SSL_ERROR_ZERO_RETURN: return "closed";
    case SSL_ERROR_WANT_READ: return "wantread";
    case SSL_ERROR_WANT_WRITE: return "wantwrite";
    case SSL_ERROR_WANT_CONNECT: return "'connect' not completed";
    case SSL_ERROR_WANT_ACCEPT: return "'accept' not completed";
    case SSL_ERROR_WANT_X509_LOOKUP: return "Waiting for callback";
    case SSL_ERROR_SYSCALL: return "System error";
    case SSL_ERROR_SSL: return ERR_reason_error_string(ERR_get_error());
    default: return "Unknown SSL error";
    }
  }
  return socket_strerror(err);
}

/**
 * Close the connection before the GC collect the object.
 */
static int meth_destroy(lua_State *L)
{
  p_ssl ssl = (p_ssl) lua_touserdata(L, 1);
  if (ssl->ssl) {
    socket_setblocking(&ssl->sock);
    SSL_shutdown(ssl->ssl);
    socket_destroy(&ssl->sock);
    SSL_free(ssl->ssl);
    ssl->ssl = NULL;
  }
  return 0;
}

/**
 * Perform the TLS/SSL handshake
 */
static int handshake(p_ssl ssl)
{
  int err;
  p_timeout tm = timeout_markstart(&ssl->tm);
  if (ssl->state == ST_SSL_CLOSED)
    return IO_CLOSED;
  for ( ; ; ) {
    ERR_clear_error();
    err = SSL_do_handshake(ssl->ssl);
    ssl->error = SSL_get_error(ssl->ssl, err);
    switch(ssl->error) {
    case SSL_ERROR_NONE:
      ssl->state = ST_SSL_CONNECTED;
      return IO_DONE;
    case SSL_ERROR_WANT_READ:
      err = socket_waitfd(&ssl->sock, WAITFD_R, tm);
      if (err == IO_TIMEOUT) return IO_SSL;
      if (err != IO_DONE)    return err;
      break;
    case SSL_ERROR_WANT_WRITE:
      err = socket_waitfd(&ssl->sock, WAITFD_W, tm);
      if (err == IO_TIMEOUT) return IO_SSL;
      if (err != IO_DONE)    return err;
      break;
    case SSL_ERROR_SYSCALL:
      if (ERR_peek_error())  {
        ssl->error = SSL_ERROR_SSL;
        return IO_SSL;
      }
      if (err == 0)
        return IO_CLOSED;
      return socket_error();
    default:
      return IO_SSL;
    }
  }
  return IO_UNKNOWN;
}

/**
 * Send data
 */
static int ssl_send(void *ctx, const char *data, size_t count, size_t *sent,
   p_timeout tm)
{
  int err;
  p_ssl ssl = (p_ssl) ctx;
  if (ssl->state == ST_SSL_CLOSED)
    return IO_CLOSED;
  *sent = 0;
  for ( ; ; ) {
    ERR_clear_error();
    err = SSL_write(ssl->ssl, data, (int) count);
    ssl->error = SSL_get_error(ssl->ssl, err);
    switch(ssl->error) {
    case SSL_ERROR_NONE:
      *sent = err;
      return IO_DONE;
    case SSL_ERROR_WANT_READ: 
      err = socket_waitfd(&ssl->sock, WAITFD_R, tm);
      if (err == IO_TIMEOUT) return IO_SSL;
      if (err != IO_DONE)    return err;
      break;
    case SSL_ERROR_WANT_WRITE:
      err = socket_waitfd(&ssl->sock, WAITFD_W, tm);
      if (err == IO_TIMEOUT) return IO_SSL;
      if (err != IO_DONE)    return err;
      break;
    case SSL_ERROR_SYSCALL:
      if (ERR_peek_error())  {
        ssl->error = SSL_ERROR_SSL;
        return IO_SSL;
      }
      if (err == 0)
        return IO_CLOSED;
      return socket_error();
    default:
      return IO_SSL;
    }
  }
  return IO_UNKNOWN;
}

/**
 * Receive data
 */
static int ssl_recv(void *ctx, char *data, size_t count, size_t *got,
  p_timeout tm)
{
  int err;
  p_ssl ssl = (p_ssl) ctx;
  if (ssl->state == ST_SSL_CLOSED)
    return IO_CLOSED;
  *got = 0;
  for ( ; ; ) {
    ERR_clear_error();
    err = SSL_read(ssl->ssl, data, (int) count);
    ssl->error = SSL_get_error(ssl->ssl, err);
    switch(ssl->error) {
    case SSL_ERROR_NONE:
      *got = err;
      return IO_DONE;
    case SSL_ERROR_ZERO_RETURN:
      *got = err;
      return IO_CLOSED;
    case SSL_ERROR_WANT_READ:
      err = socket_waitfd(&ssl->sock, WAITFD_R, tm);
      if (err == IO_TIMEOUT) return IO_SSL;
      if (err != IO_DONE)    return err;
      break;
    case SSL_ERROR_WANT_WRITE:
      err = socket_waitfd(&ssl->sock, WAITFD_W, tm);
      if (err == IO_TIMEOUT) return IO_SSL;
      if (err != IO_DONE)    return err;
      break;
    case SSL_ERROR_SYSCALL:
      if (ERR_peek_error())  {
        ssl->error = SSL_ERROR_SSL;
        return IO_SSL;
      }
      if (err == 0)
        return IO_CLOSED;
      return socket_error();
    default:
      return IO_SSL;
    }
  }
  return IO_UNKNOWN;
}

/**
 * Create a new TLS/SSL object and mark it as new.
 */
static int meth_create(lua_State *L)
{
  p_ssl ssl;
  int mode = ctx_getmode(L, 1);
  SSL_CTX *ctx = ctx_getcontext(L, 1);

  if (mode == MD_CTX_INVALID) {
    lua_pushnil(L);
    lua_pushstring(L, "invalid mode");
    return 2;
  }
  ssl = (p_ssl) lua_newuserdata(L, sizeof(t_ssl));
  if (!ssl) {
    lua_pushnil(L);
    lua_pushstring(L, "error creating SSL object");
    return 2;
  }
  ssl->ssl = SSL_new(ctx);
  if (!ssl->ssl) {
    lua_pushnil(L);
    lua_pushstring(L, "error creating SSL object");
    return 2;;
  }
  ssl->state = ST_SSL_NEW;
  SSL_set_fd(ssl->ssl, (int) SOCKET_INVALID);
  SSL_set_mode(ssl->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | 
    SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
  if (mode == MD_CTX_SERVER)
    SSL_set_accept_state(ssl->ssl);
  else
    SSL_set_connect_state(ssl->ssl);

  io_init(&ssl->io, (p_send) ssl_send, (p_recv) ssl_recv, 
    (p_error) ssl_ioerror, ssl);
  timeout_init(&ssl->tm, -1, -1);
  buffer_init(&ssl->buf, &ssl->io, &ssl->tm);

  luaL_getmetatable(L, "SSL:Connection");
  lua_setmetatable(L, -2);
  return 1;
}

/**
 * Buffer send function
 */
static int meth_send(lua_State *L) {
  p_ssl ssl = (p_ssl) luaL_checkudata(L, 1, "SSL:Connection");
  return buffer_meth_send(L, &ssl->buf);
}

/**
 * Buffer receive function
 */
static int meth_receive(lua_State *L) {
  p_ssl ssl = (p_ssl) luaL_checkudata(L, 1, "SSL:Connection");
  return buffer_meth_receive(L, &ssl->buf);
}

/**
 * Select support methods
 */
static int meth_getfd(lua_State *L)
{
  p_ssl ssl = (p_ssl) luaL_checkudata(L, 1, "SSL:Connection");
  lua_pushnumber(L, ssl->sock);
  return 1;
}

/**
 * Set the TLS/SSL file descriptor.
 * This is done *before* the handshake.
 */
static int meth_setfd(lua_State *L)
{
  p_ssl ssl = (p_ssl) luaL_checkudata(L, 1, "SSL:Connection");
  if (ssl->state != ST_SSL_NEW)
    luaL_argerror(L, 1, "invalid SSL object state");
  ssl->sock = luaL_checkint(L, 2);
  socket_setnonblocking(&ssl->sock);
  SSL_set_fd(ssl->ssl, (int)ssl->sock);
  return 0;
}

/**
 * Lua handshake function.
 */
static int meth_handshake(lua_State *L)
{
  p_ssl ssl = (p_ssl) luaL_checkudata(L, 1, "SSL:Connection");
  int err = handshake(ssl);
  if (err == IO_DONE) {
    lua_pushboolean(L, 1);
    return 1;
  }
  lua_pushboolean(L, 0);
  lua_pushstring(L, ssl_ioerror((void*)ssl, err));
  return 2;
}

/**
 * Close the connection.
 */
static int meth_close(lua_State *L)
{
  p_ssl ssl = (p_ssl) luaL_checkudata(L, 1, "SSL:Connection");
  meth_destroy(L);
  ssl->state = ST_SSL_CLOSED;
  return 0;
}

/**
 * Set timeout.
 */
static int meth_settimeout(lua_State *L)
{
  p_ssl ssl = (p_ssl) luaL_checkudata(L, 1, "SSL:Connection");
  return timeout_meth_settimeout(L, &ssl->tm);
}

/**
 * Check if there is data in the buffer.
 */
static int meth_dirty(lua_State *L)
{
  int res = 0;
  p_ssl ssl = (p_ssl) luaL_checkudata(L, 1, "SSL:Connection");
  if (ssl->state != ST_SSL_CLOSED)
    res = !buffer_isempty(&ssl->buf) || SSL_pending(ssl->ssl);
  lua_pushboolean(L, res);
  return 1;
}

/**
 * Return the state information about the SSL object.
 */
static int meth_want(lua_State *L)
{
  p_ssl ssl = (p_ssl) luaL_checkudata(L, 1, "SSL:Connection");
  int code = (ssl->state == ST_SSL_CLOSED) ? SSL_NOTHING : SSL_want(ssl->ssl);
  switch(code) {
  case SSL_NOTHING: lua_pushstring(L, "nothing"); break;
  case SSL_READING: lua_pushstring(L, "read"); break;
  case SSL_WRITING: lua_pushstring(L, "write"); break;
  case SSL_X509_LOOKUP: lua_pushstring(L, "x509lookup"); break;
  }
  return 1;
}
  
/**
 * Return a pointer to SSL structure.
 */
static int meth_rawconn(lua_State *L)
{
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  lua_pushlightuserdata(L, (void*)ssl->ssl);
  return 1;
}

/*---------------------------------------------------------------------------*/


/**
 * SSL metamethods 
 */
static luaL_Reg meta[] = {
  {"close",       meth_close},
  {"getfd",       meth_getfd},
  {"dirty",       meth_dirty},
  {"dohandshake", meth_handshake},
  {"receive",     meth_receive},
  {"send",        meth_send},
  {"settimeout",  meth_settimeout},
  {"want",        meth_want},
  {NULL,          NULL}
};

/**
 * SSL functions 
 */
static luaL_Reg funcs[] = {
  {"create",        meth_create},
  {"setfd",         meth_setfd},
  {"rawconnection", meth_rawconn},
  {NULL,            NULL}
};

/**
 * Initialize modules
 */
LUASEC_API int luaopen_ssl_core(lua_State *L)
{
  /* Initialize SSL */
  if (!SSL_library_init()) {
    lua_pushstring(L, "unable to initialize SSL library");
    lua_error(L);
  }
  SSL_load_error_strings();

  /* Initialize internal library */
  socket_open();
   
  /* Registre the functions and tables */
  luaL_newmetatable(L, "SSL:Connection");
  lua_newtable(L);
  luaL_register(L, NULL, meta);
  lua_setfield(L, -2, "__index");
  lua_pushcfunction(L, meth_destroy);
  lua_setfield(L, -2, "__gc");

  luaL_register(L, "ssl.core", funcs);
  lua_pushnumber(L, SOCKET_INVALID);
  lua_setfield(L, -2, "invalidfd");

  return 1;
}

