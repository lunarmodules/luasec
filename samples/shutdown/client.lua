--
-- Test the conn:shutdown() function
--
-- Public domain
--
local socket = require("socket")
local ssl    = require("ssl")

local params = {
   mode = "client",
   protocol = "tlsv1_2",
   key = "../certs/clientAkey.pem",
   certificate = "../certs/clientA.pem",
   cafile = "../certs/rootA.pem",
   verify = {"peer", "fail_if_no_peer_cert"},
   options = "all",
}

-- Wait until socket is ready (for reading or writing)
local function wait(peer)
   -- What event blocked us?
   local err = peer:want()
   print("Want? ", err)

   if err == "read" then
      socket.select({peer}, nil)
   elseif err == "write" then
      socket.select(nil, {peer})
   elseif err == "nothing" then
      return
   else
      peer:close()
      os.exit(1)
   end
end

-- Send data
local function send(peer, data)
   local offset = 1
   while true do
      local succ, msg, part = peer:send(data, offset)
      if succ then break end
      if part then
         offset = offset + part
         wait(peer)
      end
  end
end

-- Start the TCP connection
local peer = socket.tcp()
peer:setoption('tcp-nodelay', true)

assert(peer:connect("127.0.0.1", 8888))

peer = assert(ssl.wrap(peer, params))
local ctx = assert(ssl.newcontext(params))

peer:settimeout(0.3)

print("*** Handshake")

while true do
   local succ, msg = peer:dohandshake()
   if succ then break end
   wait(peer)
end

print("*** Send data")
for i = 1, 10 do
  send(peer, string.rep('1', 8192))
end

print("*** Shutdown")
while true do
   local succ, msg = peer:shutdown()
   if succ then break end
   print(succ, msg)
   if msg ~= "inprogress" then
      wait(peer)
   end
end

print("*** Done")
peer:close()
