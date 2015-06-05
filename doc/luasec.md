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

### ssl.checkhostname ###

    valid = ssl.checkhostname(cert, hostname)

Check if the certificate is valid for the given hostname. Deals with wildcards
and alternative names.

**NOTE**: It is crucial the hostname is checked to verify the certificate is
not only valid, but belonging to the host connected to.

### ssl.connect ###

    conn, socket = ssl.connect(hostname, port, [flags])

Creates a tcp socket, connects it to the specified hostname and port, wraps it
in an ssl object, does the handshake and verifies the hostname. It makes sure
the mode flag is set to `client`, and defaults verify to `none`, and protocol
to `tlsv1_2`. Can fail, in which case it returns nil, followed by an error.

See `ssl.wrap` and `ssl.checkhostname` for details.

**WARNING**: Peer verification is off by default. It is highly recommended to
specify either a `capath` or a `cafile` in the flags, and turn peer
verification on.
