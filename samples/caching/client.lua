--
-- Public domain
--
require("socket")
require("ssl")

local params = {
   mode = "client",
   protocol = "sslv3",
   key = "../certs/clientAkey.pem",
   certificate = "../certs/clientA.pem",
   cafile = "../certs/rootA.pem",
   verify = {"peer", "fail_if_no_peer_cert"},
   options = {"all", "no_sslv2"},
   cache = "client",
}

local session

while true do
   local peer = socket.tcp()
   assert( peer:connect("127.0.0.1", 8888) )

   -- [[ SSL wrapper
   peer = assert( ssl.wrap(peer, params) )
   if session then
      session = peer:setsession(session)
   end
   assert( peer:dohandshake() )
   --]]

   session = peer:getsession()
   print(peer:reused(),session)

   peer:receive("*l")
   peer:close()
end
