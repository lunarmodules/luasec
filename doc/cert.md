Functions
---------

### cert.load ###

    cert = cert.load(string)

Loads a PEM-formatted x509 certificate from a string. Returns nil on failure.
See `cert:pem`.

Methods
-------

### cert:digest ###

    digest = cert:digest([format])

Obtain the certificate fingerprint in the specified format. Can fail, in which
case it returns nil, followed by an error message.

Format can be one of:

 - `sha1` (default)
 - `sha256`
 - `sha512`

### cert:setencode ###

    succes = cert:setencode(encoding)

Set the string encoding used for this certificate.

Encoding can be one of:

 - `ai5`
 - `utf8`

### cert:extensions ###

    extensions = cert:extensions()

    -- extensions is of the format

    extensions = {
      [oid] = {
        name = name,
        -- the following are all optional
        dNSName = { dNSName, ... },
        rfc822Name = { rfc822Name, ... },
        uniformResourceIdentifier = { uri, ... },
        iPAddress = { iPAddress, ... },
        [type] = {
          name = typeName,
          value, ...
        },
      },
      ...
    }

Get the extensions supported by this certificate.

### cert:issuer ###

    issuer = cert:issuer()

Return the subject of the issuer of this certificate. See `cert:subject`.
Returned as an x509 name, see the Names section.

### cert:notbefore ###

    time = cert:notbefore()

Get the notBefore date from the certificate, which specifies the time this
certificate becomes valid at (until notAfter). See `cert:notafter`. The time is
specified as a human-readable string.

### cert:notafter ###

    time = cert:notafter()

Get the notAfter date from the certificate, which specifies the time this
certificate ceases to be valid at. See `cert:notbefore`. The time is specified
as a human-readable string.

### cert:pem ###

    pem = cert:pem()

Return the certificate as PEM-formatted string. See `cert.load`.

### cert:pubkey ###

    pem, type, bits = cert:pubkey()

Return the public key as PEM-formatted string. See `cert:pem`. Also returns the
type and the amount of bits used.

Type can be one of:

 - `RSA`: Rivest-Shamir-Adleman
 - `DSA`: Digital Signature Algorithm
 - `DH`: Diffie-Hellman
 - `EC`: Elliptic Curved
 - `Unknown`

### cert:serial ###

    serial = cert:digest()

Returns the certificates serial number as a hex-formatted string.

### cert:subject ###

    subject = cert:subject()

Returns the subject of the certificate, that which the certificate is valid for.
Returned as an x509 name, see the Names section.

### cert:validat ###

    valid = cert:validat(timestamp)

Returns true if the certificate is valid at the given timestamp.

Names
-----

x509 names are represented as a table in luasec. This table is a list of
entries, where every entry is of the following format:

    {
      oid = objectIdAsString,
      name = name,
      value = valueAsString,
    }

One common (no pun intended) entry is the `commonName`, usually corresponding to
the hostname this certificate was given to.
