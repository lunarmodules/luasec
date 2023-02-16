--
-- Public domain
--
local socket = require("socket")
local ssl    = require("ssl")

local params = {
   mode = "client",
   protocol = "tlsv1_2",
   psk = function(hint, max_psk_len)
      print("PSK Callback: hint=", hint, ", max_psk_len=", max_psk_len)
      return "abcd", "1234"
   end
}

local peer = socket.tcp()
peer:connect("127.0.0.1", 8888)

peer = assert( ssl.wrap(peer, params) )
assert(peer:dohandshake())

print("--- INFO ---")
local info = peer:info()
for k, v in pairs(info) do
   print(k, v)
end
print("---")

peer:close()
