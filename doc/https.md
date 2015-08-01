Functions
---------

### https.request ###

    res, code, headers, status = https.request(url, [body])

See the luasocket documentation for `http.request`. In the url table, apart
from the usual luasocket flags, luasec flags can be specified. Note that
`proxy` and `redirect` are not supported.

**WARNING**: Peer verification is off by default. It is highly recommended to
specify either a `capath` or a `cafile` in the flags, and turn peer
verification on.
