LuaSec
======

LuaSec is a binding for OpenSSL library to provide TLS/SSL communication. It
takes an already established TCP connection and creates a secure session
between the peers.

Functions
---------

### ssl.newcontext ###

    cfg = {
      protocol = "sslv23" | "sslv3" | "tlsv1" | "tlsv1_1" | "tlsv1_2",
      mode = "server" | "client",
      key = nil | filename,
      password = nil | string | function() -> string,
      certificate = nil | filename,
      cafile = nil | filename,
      capath = nil | path,
      ciphers = ciphers,
      verify = {"none" | "peer" | "client_once" | "fail_if_no_peer_cert", ...},
      options = options,
      depth = number,
      dhparam = function(is_export, keylength) -> dh_params_string,
      curve = curve,
      verifyext = {"lsec_continue" | "lsec_ignore_purpose" | "crl_check" |
          "crl_check_chain", ...},
    }

    context = ssl.newcontext(cfg)

Creates a new context based on the settings in the `cfg` table.
See OpenSSL documentation on specifics on these settings, and see the `openssl
ciphers` command for the list of supported ciphers and its format specifically.

#### options ####
      "all"
      "allow_unsafe_legacy_renegotiation"
      "cipher_server_preference"
      "cisco_anyconnect"
      "cookie_exchange"
      "cryptopro_tlsext_bug"
      "dont_insert_empty_fragments"
      "ephemeral_rsa"
      "legacy_server_connect"
      "microsoft_big_sslv3_buffer"
      "microsoft_sess_id_bug"
      "msie_sslv2_rsa_padding"
      "netscape_ca_dn_bug"
      "netscape_challenge_bug"
      "netscape_demo_cipher_change_bug"
      "netscape_reuse_cipher_change_bug"
      "no_compression"
      "no_query_mtu"
      "no_session_resumption_on_renegotiation"
      "no_sslv2"
      "no_sslv3"
      "no_ticket"
      "no_tlsv1"
      "no_tlsv1_1"
      "no_tlsv1_2"
      "pkcs1_check_1"
      "pkcs1_check_2"
      "single_dh_use"
      "single_ecdh_use"
      "ssleay_080_client_dh_bug"
      "sslref2_reuse_cert_type_bug"
      "tls_block_padding_bug"
      "tls_d5_bug"
      "tls_rollback_bug"

#### curves ####

      "secp112r1"
      "secp112r2"
      "secp128r1"
      "secp128r2"
      "secp160k1"
      "secp160r1"
      "secp160r2"
      "secp192k1"
      "secp224k1"
      "secp224r1"
      "secp256k1"
      "secp384r1"
      "secp521r1"
      "sect113r1"
      "sect113r2"
      "sect131r1"
      "sect131r2"
      "sect163k1"
      "sect163r1"
      "sect163r2"
      "sect193r1"
      "sect193r2"
      "sect233k1"
      "sect233r1"
      "sect239k1"
      "sect283k1"
      "sect283r1"
      "sect409k1"
      "sect409r1"
      "sect571k1"
      "sect571r1"
      "prime192v1"
      "prime192v2"
      "prime192v3"
      "prime239v1"
      "prime239v2"
      "prime239v3"
      "prime256v1"

### ssl.loadcertificate ###
Alias for `cert.load`.

### ssl.wrap ###

    conn = ssl.wrap(socket, cfg)

`ssl.wrap` wraps an existing luasocket socket into a luasec connection object.
`cfg` is defined as for `ssl.newcontext`.
