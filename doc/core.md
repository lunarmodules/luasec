Functions
---------

### core.compression ###

    compression = core.compression(conn)

Returns the compression method used in a particular `conn` object. Can fail,
in which case it returns nil, followed by an error message.

### core.create ###

    conn = core.create(context)

Creates a new core connection object from a context. Use of `ssl.wrap` is
encouraged.

### core.info ###

    buffer, numbits, processedbits, version = core.info(conn)

Returns the information associated with a `conn` object.

### core.setfd ###

    core.setfd(conn, fd)

Set the `conn` object to use the given file descriptor. Usually done by
`ssl.wrap`.

### core.setmethod ###

    core.setmethod(name, value)

Set the the name and value as method/member on `conn` objects. Similar to the
following snippet:

    debug.getmetatable(conn).__index[name] = value

### core.copyright ###

    copyright = core.copyright()

Return copyright information for luasec.
