--
-- Public domain
--
local socket = require("socket")
local ssl    = require("ssl")

local params = {
   mode = "server",
   protocol = "any",
   key = "../certs/serverAkey.pem",
   certificate = "../certs/serverA.pem",
   cafile = "../certs/rootA.pem",
   verify = {"peer", "fail_if_no_peer_cert"},
   options = "all",
}

local ctx = assert(ssl.newcontext(params))

local server = socket.tcp()
server:setoption('reuseaddr', true)

assert(server:bind("127.0.0.1", 8888))
server:listen()

while true do
  local peer = server:accept()
  peer:setoption('tcp-nodelay', true)

  print("*** New connection")

  peer = assert( ssl.wrap(peer, ctx) )

  print("*** Handshake")
  assert( peer:dohandshake() )

  print("*** Receive")
  while true do
    local str = peer:receive(1024)
    if not str then break end
    socket.sleep(0.1)
  end

  print("*** Done")
  peer:close()
end

server:close()
