--
-- Public domain
--
local socket = require("socket")
local ssl    = require("ssl")

local ocsp   = ssl.ocsp

-- Parameters
--   * status:
--     * nil                          (no status was sent by server)
--     * ocsp.status.successful
--     * ocsp.status.malformedrequest
--     * ocsp.status.internalerror
--     * ocsp.status.trylater
--     * ocsp.status.sigrequired
--     * ocsp.status.unauthorized
--
-- Returns
--   * nil: on error
--   * true: status was accepted (continue the handshake)
--   * false: status not accepted (handshake stops with error)
--
local callback = function(status)
  print("Status: ", status)
  print("---")

  if status == nil then
    print("[WARN] No OCSP response")
    return true
  end

  return (status == ocsp.status.successful)
end

local params = {
   mode     = "client",
   protocol = "tlsv1_2",
   verify   = "none",
   options  = "all",
   ocsp     = callback,
}

while true do
  local peer = socket.tcp()
  peer:connect("127.0.0.1", 8443)
  
  peer = assert(ssl.wrap(peer, params))
  assert(peer:dohandshake())
  
  print(peer:receive())
  print("------------")
  peer:close()
end
