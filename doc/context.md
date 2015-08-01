Functions
---------

### context.create ###

    ctxt = context.create(method)

Creates a new context. Can fail, in which case it returns nil, followed by an
error.

### context.locations ###

    success, error = context.locations(ctxt, [cafile], [capath])

Set the location of either the CA certificate file, or the directory which
contains said file(s).

### context.loadcert ###

    success, error = context.loadcert(ctxt, filename)

Load a certificate from a file into this context.

### context.loadkey ###

    success, error = context.loadkey(ctxt, filename)
    success, error = context.loadkey(ctxt, filename, string)
    success, error = context.loadkey(ctxt, filename, function() -> string)

Loads a private key from a PEM-format file. The third argument can be either a
string, or a function returning a string producing the password for the key.

### context.checkkey ###

    success = context.checkkey(ctxt)

Returns true if the certificate loaded matches the key loaded.

### context.setcipher ###

    success, error = context.setcipher(ctxt, cipherlist)

Sets the ciphers used when negotiation. For the format of the string
`cipherlist`, see the openssl documentation, and in particular the `openssl
ciphers` command line tool.

### context.setdepth ###

    success = context.setdepth(ctxt)

Set the maximum verification depth for checking certificate chains.

### context.setdhparam ###

    context.setdhparam(ctxt, function(isExport, keyLength) -> params)

Sets a callback to obtain Diffie-Hellman parameters on this context. Once these
parameters are required, the callback gets called with a flag (`isExport`)
indicating whether export-level security is used, and a key length
(`keyLength`). It is then expected to produce a string containg parameters.

For the format of the parameters string, see the openssl documentation.

### context.setcurve ###

    success, error = context.setcurve(ctxt, curve)

Set the curve to use for Elliptic Curve cryptography.

The curve can be one of:

  - `secp112r1`
  - `secp112r2`
  - `secp128r1`
  - `secp128r2`
  - `secp160k1`
  - `secp160r1`
  - `secp160r2`
  - `secp192k1`
  - `secp224k1`
  - `secp224r1`
  - `secp256k1`
  - `secp384r1`
  - `secp521r1`
  - `sect113r1`
  - `sect113r2`
  - `sect131r1`
  - `sect131r2`
  - `sect163k1`
  - `sect163r1`
  - `sect163r2`
  - `sect193r1`
  - `sect193r2`
  - `sect233k1`
  - `sect233r1`
  - `sect239k1`
  - `sect283k1`
  - `sect283r1`
  - `sect409k1`
  - `sect409r1`
  - `sect571k1`
  - `sect571r1`
  - `prime192v1`
  - `prime192v2`
  - `prime192v3`
  - `prime239v1`
  - `prime239v2`
  - `prime239v3`
  - `prime256v1`

### context.setverify ###

    success, error = context.setverify(ctxt, options...)

Sets verification options for this context.

The following options are valid:

 - `none`
 - `peer`
 - `client_once`
 - `fail_if_no_peer_cert`

### context.setoptions ###

    success, error = context.setoptions(ctxt, options...)

Set generic context options for this context.

The following options are valid:

 - `all`
 - `allow_unsafe_legacy_renegotiation`
 - `cipher_server_preference`
 - `cisco_anyconnect`
 - `cookie_exchange`
 - `cryptopro_tlsext_bug`
 - `dont_insert_empty_fragments`
 - `ephemeral_rsa`
 - `legacy_server_connect`
 - `microsoft_big_sslv3_buffer`
 - `microsoft_sess_id_bug`
 - `msie_sslv2_rsa_padding`
 - `netscape_ca_dn_bug`
 - `netscape_challenge_bug`
 - `netscape_demo_cipher_change_bug`
 - `netscape_reuse_cipher_change_bug`
 - `no_compression`
 - `no_query_mtu`
 - `no_session_resumption_on_renegotiation`
 - `no_sslv2`
 - `no_sslv3`
 - `no_ticket`
 - `no_tlsv1`
 - `no_tlsv1_1`
 - `no_tlsv1_2`
 - `pkcs1_check_1`
 - `pkcs1_check_2`
 - `single_dh_use`
 - `single_ecdh_use`
 - `ssleay_080_client_dh_bug`
 - `sslref2_reuse_cert_type_bug`
 - `tls_block_padding_bug`
 - `tls_d5_bug`
 - `tls_rollback_bug`

### context.setmode ###

    success = context.setmode(ctxt, mode)

Set the mode for this context.

Mode can be one of:

 - `client`
 - `server`

Methods
-------

### ctxt:setverifyext ###

    success, error = ctxt:setverifyext(flags...)

Set which extra verification steps to use.

The following flags are valid:

 - `lsec_continue`: Continue with verification errors
 - `lsec_ignore_purpose`: Ignore this certificate's purpose (like server/client)
 - `crl_check`: Check Certification Revocation Lists
 - `crl_check_chain`: Check CRLs for the entire chain
