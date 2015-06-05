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

For a list of options, see `context.setoptions`.

For a list of curves, see `context.setcurve`.

### ssl.loadcertificate ###
Alias for `cert.load`.

### ssl.wrap ###

    conn = ssl.wrap(socket, cfg)

`ssl.wrap` wraps an existing luasocket socket into a luasec connection object.
`cfg` is defined as for `ssl.newcontext`.
