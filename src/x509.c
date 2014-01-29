/*--------------------------------------------------------------------------
 * LuaSec 0.5
 *
 * Copyright (C) 2014 Kim Alvefur, Paul Aurich, Tobias Markmann
 *                    Matthew Wild, Bruno Silvestre.
 *
 *--------------------------------------------------------------------------*/

#include <string.h>

#if defined(WIN32)
#include <windows.h>
#endif

#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>

#include <lua.h>
#include <lauxlib.h>

#include "x509.h"

static const char* hex_tab = "0123456789abcdef";

/**
 * Push the certificate on the stack.
 */
void lsec_pushx509(lua_State* L, X509 *cert)
{
  p_x509 cert_obj = (p_x509)lua_newuserdata(L, sizeof(t_x509));
  cert_obj->cert = cert;
  cert_obj->encode = LSEC_AI5_STRING;
  luaL_getmetatable(L, "SSL:Certificate");
  lua_setmetatable(L, -2);
}

/**
 * Return the OpenSSL certificate X509.
 */
X509* lsec_checkx509(lua_State* L, int idx)
{
  return ((p_x509)luaL_checkudata(L, idx, "SSL:Certificate"))->cert;
}

/**
 * Return LuaSec certificate X509 representation.
 */
p_x509 lsec_checkp_x509(lua_State* L, int idx)
{
  return (p_x509)luaL_checkudata(L, idx, "SSL:Certificate");
}

/*---------------------------------------------------------------------------*/

/**
 * Convert the buffer 'in' to hexadecimal.
 */
static void to_hex(const char* in, int length, char* out)
{
  int i;
  for (i = 0; i < length; i++) {
    out[i*2] = hex_tab[(in[i] >> 4) & 0xF];
    out[i*2+1] = hex_tab[(in[i]) & 0xF];
  }
}

/**
 * Converts the ASN1_OBJECT into a textual representation and put it
 * on the Lua stack.
 */
static void push_asn1_objname(lua_State* L, ASN1_OBJECT *object, int no_name)
{
  char buffer[256];
  int len = OBJ_obj2txt(buffer, sizeof(buffer), object, no_name);
  len = (len < sizeof(buffer)) ? len : sizeof(buffer);
  lua_pushlstring(L, buffer, len);
}

/**
 * Push the ASN1 string on the stack.
 */
static void push_asn1_string(lua_State* L, ASN1_STRING *string, int encode)
{
  size_t len;
  unsigned char *data;
  if (!string)
    lua_pushnil(L);
  switch (encode) {
  case LSEC_AI5_STRING:
    lua_pushlstring(L, (char*)ASN1_STRING_data(string),
                       ASN1_STRING_length(string));
    break;
  case LSEC_UTF8_STRING:
    len = ASN1_STRING_to_UTF8(&data, string);
    if (len >= 0) {
      lua_pushlstring(L, (char*)data, len);
      OPENSSL_free(data);
    }
  }
}

/**
 * Return a human readable time.
 */
static int push_asn1_time(lua_State *L, ASN1_UTCTIME *tm)
{
  char *tmp;
  long size;
  BIO *out = BIO_new(BIO_s_mem());
  ASN1_TIME_print(out, tm);
  size = BIO_get_mem_data(out, &tmp);
  lua_pushlstring(L, tmp, size);
  BIO_free(out);
  return 1;
}

/**
 * 
 */
static int push_subtable(lua_State* L, int idx)
{
  lua_pushvalue(L, -1);
  lua_gettable(L, idx-1);
  if (lua_isnil(L, -1)) {
    lua_pop(L, 1);
    lua_newtable(L);
    lua_pushvalue(L, -2);
    lua_pushvalue(L, -2);
    lua_settable(L, idx-3);
    lua_replace(L, -2); /* Replace key with table */
    return 1;
  }
  lua_replace(L, -2); /* Replace key with table */
  return 0;
}

/**
 * Retrive the general names from the object.
 */
static int push_x509_name(lua_State* L, X509_NAME *name, int encode)
{
  int i;
  int n_entries;
  ASN1_OBJECT *object;
  X509_NAME_ENTRY *entry;
  lua_newtable(L);
  n_entries = X509_NAME_entry_count(name);
  for (i = 0; i < n_entries; i++) {
    entry = X509_NAME_get_entry(name, i);
    object = X509_NAME_ENTRY_get_object(entry);
    lua_newtable(L);
    push_asn1_objname(L, object, 1);
    lua_setfield(L, -2, "oid");
    push_asn1_objname(L, object, 0);
    lua_setfield(L, -2, "name");
    push_asn1_string(L, X509_NAME_ENTRY_get_data(entry), encode);
    lua_setfield(L, -2, "value");
    lua_rawseti(L, -2, i+1);
  }
  return 1;
}

/*---------------------------------------------------------------------------*/

/**
 * Retrive the Subject from the certificate.
 */
static int meth_subject(lua_State* L)
{
  p_x509 px = lsec_checkp_x509(L, 1);
  return push_x509_name(L, X509_get_subject_name(px->cert), px->encode);
}

/**
 * Retrive the Issuer from the certificate.
 */
static int meth_issuer(lua_State* L)
{
  p_x509 px = lsec_checkp_x509(L, 1);
  return push_x509_name(L, X509_get_issuer_name(px->cert), px->encode);
}

/**
 * Retrieve the extensions from the certificate.
 */
int meth_extensions(lua_State* L)
{
  int j;
  int i = -1;
  int n_general_names;
  OTHERNAME *otherName;
  X509_EXTENSION *extension;
  GENERAL_NAME *general_name;
  STACK_OF(GENERAL_NAME) *values;
  p_x509 px  = lsec_checkp_x509(L, 1);
  X509 *peer = px->cert;

  /* Return (ret) */
  lua_newtable(L);

  while ((i = X509_get_ext_by_NID(peer, NID_subject_alt_name, i)) != -1) {
    extension = X509_get_ext(peer, i);
    if (extension == NULL)
      break;
    values = X509V3_EXT_d2i(extension);
    if (values == NULL)
      break;

    /* Push ret[oid] */
    push_asn1_objname(L, extension->object, 1);
    push_subtable(L, -2);

    /* Set ret[oid].name = name */
    push_asn1_objname(L, extension->object, 0);
    lua_setfield(L, -2, "name");

    n_general_names = sk_GENERAL_NAME_num(values);
    for (j = 0; j < n_general_names; j++) {
      general_name = sk_GENERAL_NAME_value(values, j);
      switch (general_name->type) {
      case GEN_OTHERNAME:
        otherName = general_name->d.otherName;
        push_asn1_objname(L, otherName->type_id, 1);
        if (push_subtable(L, -2)) {
          push_asn1_objname(L, otherName->type_id, 0);
          lua_setfield(L, -2, "name");
        }
        push_asn1_string(L, otherName->value->value.asn1_string, px->encode);
        lua_rawseti(L, -2, lua_rawlen(L, -2) + 1);
        lua_pop(L, 1);
        break;
      case GEN_DNS:
        lua_pushstring(L, "dNSName");
	push_subtable(L, -2);
        push_asn1_string(L, general_name->d.dNSName, px->encode);
        lua_rawseti(L, -2, lua_rawlen(L, -2) + 1);
        lua_pop(L, 1);
        break;
      case GEN_EMAIL:
        lua_pushstring(L, "rfc822Name");
        push_subtable(L, -2);
        push_asn1_string(L, general_name->d.rfc822Name, px->encode);
        lua_rawseti(L, -2, lua_rawlen(L, -2) + 1);
        lua_pop(L, 1);
        break;
      case GEN_URI:
        lua_pushstring(L, "uniformResourceIdentifier");
        push_subtable(L, -2);
        push_asn1_string(L, general_name->d.uniformResourceIdentifier, px->encode);
        lua_rawseti(L, -2, lua_rawlen(L, -2)+1);
        lua_pop(L, 1);
        break;
      case GEN_IPADD:
        lua_pushstring(L, "iPAddress");
        push_subtable(L, -2);
        push_asn1_string(L, general_name->d.iPAddress, px->encode);
        lua_rawseti(L, -2, lua_rawlen(L, -2)+1);
        lua_pop(L, 1);
        break;
      case GEN_X400:
        /* x400Address   */
        /* not supported */
        break;
      case GEN_DIRNAME:
        /* directoryName */
        /* not supported */
        break;
      case GEN_EDIPARTY:
        /* ediPartyName */
        /* not supported */
        break;
      case GEN_RID:
        /* registeredID  */
        /* not supported */
        break;
      }
    }
    lua_pop(L, 1); /* ret[oid] */
    i++;           /* Next extension */
  }
  return 1;
}

/**
 * Convert the certificate to PEM format.
 */
static int meth_pem(lua_State* L)
{
  char* data;
  long bytes;
  X509* cert = lsec_checkx509(L, 1);
  BIO *bio = BIO_new(BIO_s_mem());
  if (!PEM_write_bio_X509(bio, cert)) {
    lua_pushnil(L);
    return 1;
  }
  bytes = BIO_get_mem_data(bio, &data);
  if (bytes > 0)
    lua_pushlstring(L, data, bytes);
  else
    lua_pushnil(L);
  BIO_free(bio);
  return 1;
}

/**
 * Compute the fingerprint.
 */
static int meth_digest(lua_State* L)
{
  unsigned int bytes;
  const EVP_MD *digest = NULL;
  unsigned char buffer[EVP_MAX_MD_SIZE];
  char hex_buffer[EVP_MAX_MD_SIZE*2];
  X509 *cert = lsec_checkx509(L, 1);
  const char *str = luaL_optstring(L, 2, NULL);
  if (!str)
    digest = EVP_sha1();
  else {
    if (!strcmp(str, "sha1"))
      digest = EVP_sha1();
    else if (!strcmp(str, "sha256"))
      digest = EVP_sha256();
    else if (!strcmp(str, "sha512"))
      digest = EVP_sha512();
  }
  if (!digest) {
    lua_pushnil(L);
    lua_pushfstring(L, "digest algorithm not supported (%s)", str);
    return 2;
  }
  if (!X509_digest(cert, digest, buffer, &bytes)) {
    lua_pushnil(L);
    lua_pushfstring(L, "error processing the certificate (%s)",
      ERR_reason_error_string(ERR_get_error()));
    return 2;
  }
  to_hex((char*)buffer, bytes, hex_buffer);
  lua_pushlstring(L, hex_buffer, bytes*2);
  return 1;
}

/**
 * Check if the certificate is valid in a given time.
 */
static int meth_valid_at(lua_State* L)
{
  X509* cert = lsec_checkx509(L, 1);
  time_t time = luaL_checkinteger(L, 2);
  lua_pushboolean(L, (X509_cmp_time(X509_get_notAfter(cert), &time)     >= 0
                      && X509_cmp_time(X509_get_notBefore(cert), &time) <= 0));
  return 1;
}

/**
 * Return the serial number.
 */
static int meth_serial(lua_State *L)
{
  char *tmp;
  BIGNUM *bn;
  ASN1_INTEGER *serial;
  X509* cert = lsec_checkx509(L, 1);
  serial = X509_get_serialNumber(cert);
  bn = ASN1_INTEGER_to_BN(serial, NULL);
  tmp = BN_bn2hex(bn);
  lua_pushstring(L, tmp);
  BN_free(bn);
  OPENSSL_free(tmp);
  return 1;
}

/**
 * Return not before date.
 */
static int meth_notbefore(lua_State *L)
{
  X509* cert = lsec_checkx509(L, 1);
  return push_asn1_time(L, X509_get_notBefore(cert));
}

/**
 * Return not after date.
 */
static int meth_notafter(lua_State *L)
{
  X509* cert = lsec_checkx509(L, 1);
  return push_asn1_time(L, X509_get_notAfter(cert));
}

/**
 * Collect X509 objects.
 */
static int meth_destroy(lua_State* L)
{
  X509_free(lsec_checkx509(L, 1));
  return 0;
}

static int meth_tostring(lua_State *L)
{
  X509* cert = lsec_checkx509(L, 1);
  lua_pushfstring(L, "X509 certificate: %p", cert);
  return 1;
}

/**
 * Set the encode for ASN.1 string.
 */
static int meth_set_encode(lua_State* L)
{
  int succ = 0;
  p_x509 px = lsec_checkp_x509(L, 1);
  const char *enc = luaL_checkstring(L, 2);
  if (strncmp(enc, "ai5", 3) == 0) {
    succ = 1;
    px->encode = LSEC_AI5_STRING;
  } else if (strncmp(enc, "utf8", 4) == 0) {
    succ = 1;
    px->encode = LSEC_UTF8_STRING;
  }
  lua_pushboolean(L, succ);
  return 1;
}

/*---------------------------------------------------------------------------*/

static int load_cert(lua_State* L)
{
  X509 *cert;
  size_t bytes;
  const char* data;
  BIO *bio = BIO_new(BIO_s_mem());
  data = luaL_checklstring(L, 1, &bytes);
  BIO_write(bio, data, bytes);
  cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  if (cert)
    lsec_pushx509(L, cert);
  else
    lua_pushnil(L);
  BIO_free(bio);
  return 1;
}

/*---------------------------------------------------------------------------*/

/**
 * Certificate methods.
 */
static luaL_Reg methods[] = {
  {"digest",     meth_digest},
  {"setencode",  meth_set_encode},
  {"extensions", meth_extensions},
  {"issuer",     meth_issuer},
  {"notbefore",  meth_notbefore},
  {"notafter",   meth_notafter},
  {"pem",        meth_pem},
  {"serial",     meth_serial},
  {"subject",    meth_subject},
  {"validat",    meth_valid_at},
  {NULL,         NULL}
};

/**
 * X509 metamethods.
 */
static luaL_Reg meta[] = {
  {"__gc",       meth_destroy},
  {"__tostring", meth_tostring},
  {NULL, NULL}
};

/**
 * X509 functions.
 */
static luaL_Reg funcs[] = {
  {"load", load_cert},
  {NULL,   NULL}
};

/*--------------------------------------------------------------------------*/

#if (LUA_VERSION_NUM == 501)

LSEC_API int luaopen_ssl_x509(lua_State *L)
{
  /* Register the functions and tables */
  luaL_newmetatable(L, "SSL:Certificate");
  luaL_register(L, NULL, meta);

  lua_newtable(L);
  luaL_register(L, NULL, methods);
  lua_setfield(L, -2, "__index");

  luaL_register(L, "ssl.x509", funcs);

  return 1;
}

#else

LSEC_API int luaopen_ssl_x509(lua_State *L)
{
  /* Register the functions and tables */
  luaL_newmetatable(L, "SSL:Certificate");
  luaL_setfuncs(L, meta, 0);

  lua_newtable(L);
  luaL_setfuncs(L, methods, 0);
  lua_setfield(L, -2, "__index");

  lua_newtable(L);
  luaL_setfuncs(L, funcs, 0);

  return 1;
}

#endif
