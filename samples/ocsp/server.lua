--
-- Public domain
--
local socket = require("socket")
local ssl    = require("ssl")

local mime   = require("mime")
local ltn12  = require("ltn12")
local http   = require("socket.http")

local ocsp   = ssl.ocsp

--------------------------------------------------------------------------------

local response

function loadresponse(certfile, cafile)
  local f = io.open(cafile)
  local ca = f:read("*a")
  ca = ssl.loadcertificate(ca)
  f:close()
 
  f = io.open(certfile)
  local cert = f:read("*a")
  cert = ssl.loadcertificate(cert)
  f:close()
 
  local res = {}
  local req = ocsp.buildrequest(cert, ca)
  req = mime.b64(req)
 
  local a, b = http.request {
    url = "http://zerossl.ocsp.sectigo.com/" .. req,
    method = "GET",
    sink = ltn12.sink.table(res),
    header = {
      ["Content-Type"] = "application/ocsp-request",
      ["Host"] = "zerossl.ocsp.sectigo.com",
    },
  }
 
  response = table.concat(res)

  local thisupd, nextupd = ocsp.responsetime(response)
  print("This update: ", thisupd)
  print("Next update: ", nextupd)
end

--------------------------------------------------------------------------------

local cafile = "ca.pem"
local certfile = "server.pem"

-- Remember to update 'response' before 'next update'
local callback = function()
  if not response then
    loadresponse(certfile, cafile)
  end
  return response
end

local params = {
   mode = "server",
   protocol = "any",
   key = "server.key",
   certificate = certfile,
   verify = "none",
   options = "all",
   ocsp = callback,
}

--------------------------------------------------------------------------------

local ctx = assert(ssl.newcontext(params))

local server = socket.tcp()
server:setoption('reuseaddr', true)
assert(server:bind("127.0.0.1", 8443))
server:listen()

while true do
  local peer = server:accept()
  peer = assert(ssl.wrap(peer, ctx))
  local succ = peer:dohandshake()
  if succ then
    peer:send("OCSP test\n")
    peer:close()
  end
end
