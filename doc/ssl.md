Created using `ssl.create` or `ssl.wrap`.

Methods
----------------------

### conn:close ###

    conn:close()

Closes the connection, releasing the resources.

### conn:getfd ###

    fd = conn:getfd()

Retrieves the file descriptor belonging to this connection.

### conn:getfinished ###

    lastFinishedMsg = conn:getfinished()

Gets the last "Finished" message sent out. Can fail, in which case it returns
nil, followed by an error message.

### conn:getpeercertificate ###

    cert = conn:getpeercertificate()

Return a `cert` object corresponding to the peer's public x509 certificate. Can
fail, in which case it returns nil, followed by an error message.

### conn:getpeerchain ###

    chain = conn:getpeerchain()

Returns a list of `cert` objects. Can fail, in which case it returns nil,
followed by an error message.

### conn:getpeerverification ###

    valid, reason = conn:getpeerverification()

Returns whether the peer's certificate verified successfully. Note that `reason`
can be either a string, or a table of strings.

### conn:getpeerfinished ###

    lastFinishedMsg = conn:getpeerfinished()

Gets the last "Finished" message received. See `conn:getfinished`.

### conn:getsniname ###

    sniName = conn:getsniname()

Returns the server name set using the TLS Server Name Indication (SNI)
extension, if set.

### conn:getstats ###

See luasocket's `conn:getstats`.

### conn:setstats ###

See luasocket's `conn:setstats`.

### conn:dirty ###

    dirty = conn:dirty()

Returns true if there is still information waiting to be sent, return false if
the buffer is empty *and* there is no SSL/TLS traffic pending. Note that a
closed connection if never dirty.

### conn:dohandshake ###

    success, error = conn:dohandshake()

Tries to establish SSL/TLS connection. Do this before using either `conn:send`
or `conn:receive`. This method negotiates with the peer to find and set
connection parameters. Most information obtainable from a `conn` object is only
available after the handshake.

**NOTE**: This method checks for a valid certificate, but does *not* verify if
the certificate belongs to the hostname connected to.

### conn:receive ###

See luasocket's `conn:receive`.

### conn:send ###

See luasocket's `conn:send`.

### conn:settimeout ###

See luasocket's `conn:settimeout`.

### conn:sni ###

    -- client
    conn:sni(serverName)

    -- server
    conn:sni({[serverName] = context, ...}, strict)

On the client, sets the server name to pass to the server using the TLS Server
Name Indication (SNI) extension.

On the server, establishes a mapping between server names and contexts, allowing
context selection based on the client's SNI value. If strict is true, the
indicated server name must be in the table, or the negotiation fails. If strict
is false and the indicated server name is not present in the table, use the
context associated with this `conn` object.

### conn:want ###

    want = conn:want()

Returns luasec's current `want`, if the connection is dirty (see `conn:dirty`).
This can either be `nothing`, `read`, `write` or `x509lookup`.

### conn:checkhostname ###

    valid = conn:checkhostname(hostname)

Checks whether the certificate is valid for the given hostname. Helper for
`ssl.checkhostname`, see `ssl.checkhostname` for more information.
