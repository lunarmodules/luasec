LuaSec 0.5.1
============
- Check if SSLv3 protocol is available.
- Fix push_asn1_string().
- Update samples to use 'sslv23' and 'tlsv1_2'.
- Update MACOSX_VERSION to 10.11 on Makefile.

LuaSec 0.5
==========

LuaSec depends  on OpenSSL, and  integrates with LuaSocket to  make it
easy to add secure connections to any Lua applications or scripts.

This  version  includes:

  * A new certificate (X509) API, which supports:
    - Reading  the subject  (identity) and  issuer of the certificate.
    - Reading  various X509  extensions, including email  and dnsName.
    - Converting  certificates  to and  from  the  standard ASCII  PEM
      format.
    - Generating the fingerprint/digest of a certificate  (using SHA1,
      SHA256 or SHA512).
    - Reading the  certificate's expiration, serial number,  and other
      info.

  * The ability  to get more  detailed information from  OpenSSL about
    why a certificate failed verification, for each certificate in the
    chain.
  
  * Flags to  force acceptance of invalid certificates,  e.g. to allow
    the use of self-signed certificates in a Trust On First Use model.

  * Flags to control checking CRLs for certificate revocation status.
 
  * Support for ECDH cipher suites.
 
  * An API  to get the TLS  'finished' messages used  for SASL channel
    binding (e.g. the SCRAM PLUS mechanisms).

The work in  this release was undertaken by  Kim Alvefur, Paul Aurich,
Tobias Markmann, Bruno Silvestre and Matthew Wild.
