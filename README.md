LuaSec 0.6
==========
LuaSec depends  on OpenSSL, and  integrates with LuaSocket to  make it
easy to add secure connections to any Lua applications or scripts.

Documentation: https://github.com/brunoos/luasec/wiki

This version includes:

* Lua 5.2 and 5.3 compatibility

* Context module:
  - Add ctx:checkkey()

* SSL module:
  - Add conn:sni() and conn:getsniname()

* Context options:
  - Add "any" protocol ("sslv23" is deprecated)

* HTTPS module:
  - Using "any" protocol without SSLv2/SSLv3, by default

* X509 module:
  - Human readable IP address
  - Add cert:issued()
  - Add cert:pubkey()

* Some bug fixes


********************************************************************************

PS: 10th anniversary! Thanks to everyone who collaborate with LuaSec.

********************************************************************************
