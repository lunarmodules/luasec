--
-- Public domain
--
local socket = require("socket")
local ssl    = require("ssl")

local params = {
   mode = "server",
   protocol = "any",
   options = "all",
   psk = function(identity, max_psk_len)
      print("PSK Callback: identity=", identity, ", max_psk_len=", max_psk_len)
      if identity == "abcd" then
         return "1234"
      end
      return nil
   end
}


-- [[ SSL context
local ctx = assert(ssl.newcontext(params))
--]]

local server = socket.tcp()
server:setoption('reuseaddr', true)
assert( server:bind("127.0.0.1", 8888) )
server:listen()

local peer = server:accept()
peer = assert( ssl.wrap(peer, ctx) )
assert( peer:dohandshake() )

print("--- INFO ---")
local info = peer:info()
for k, v in pairs(info) do
   print(k, v)
end
print("---")

peer:close()
server:close()
