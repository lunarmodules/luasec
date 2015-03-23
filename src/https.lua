----------------------------------------------------------------------------
-- LuaSec 0.5
-- Copyright (C) 2009-2014 PUC-Rio
--
-- Author: Pablo Musa
-- Author: Tomas Guisasola
---------------------------------------------------------------------------

local socket = require("socket")
local ssl    = require("ssl")
local ltn12  = require("ltn12")
local http   = require("socket.http")
local url    = require("socket.url")

local table  = require("table")

local try          = socket.try
local type         = type
local pairs        = pairs
local getmetatable = getmetatable

module("ssl.https")

_VERSION   = "0.5"
_COPYRIGHT = "LuaSec 0.5 - Copyright (C) 2009-2014 PUC-Rio"

-- Default settings
PORT = 443

local cfg = {
  protocol = "tlsv1",
  options  = "all",
  verify   = "none",
}

--------------------------------------------------------------------
-- Auxiliar Functions
--------------------------------------------------------------------

-- Convert an URL to a table according to Luasocket needs.
local function urlstring_totable(url, body, result_table)
   url = {
      url = url,
      method = body and "POST" or "GET",
      sink = ltn12.sink.table(result_table)
   }
   if body then
      url.source = ltn12.source.string(body)
      url.headers = {
         ["content-length"] = #body,
         ["content-type"] = "application/x-www-form-urlencoded",
      }
   end
   return url
end

-- Forward calls to the real connection object.
local function reg(conn)
   local mt = getmetatable(conn.sock).__index
   for name, method in pairs(mt) do
      if type(method) == "function" then
         conn[name] = function (self, ...)
                         return method(self.sock, ...)
                      end
      end
   end
end

-- Return a function which performs the SSL/TLS connection.
local function tcp(params)
   params = params or {}
   -- Default settings
   for k, v in pairs(cfg) do 
      params[k] = params[k] or v
   end
   -- Force client mode
   params.mode = "client"
   -- upvalue to track https -> http redirection
   local washttps = false
   -- 'create' function for LuaSocket
   return function (reqt)
      local u = url.parse(reqt.url)
      if (reqt.scheme or u.scheme) == "https" then
        -- https, provide an ssl wrapped socket
        local conn = {}
        conn.sock = try(socket.tcp())
        local st = getmetatable(conn.sock).__index.settimeout
        function conn:settimeout(...)
           return st(self.sock, ...)
        end
        -- Replace TCP's connection function
        function conn:connect(host, port)
           try(self.sock:connect(host, port))
           self.sock = try(ssl.wrap(self.sock, params))
           try(self.sock:dohandshake())
           reg(self, getmetatable(self.sock))
           return 1
        end
        -- insert https default port, overriding http port inserted by LuaSocket
        if not u.port then
           u.port = PORT
           reqt.url = url.build(u)
           reqt.port = PORT 
        end
        washttps = true
        return conn
      else
        -- regular http, needs just a socket...
        if washttps and params.redirect ~= "all" then
          try(nil, "Unallowed insecure redirect https to http")
        end
        return socket.tcp()
      end  
   end
end

--------------------------------------------------------------------
-- Main Function
--------------------------------------------------------------------

-- Make a HTTP request over secure connection.  This function receives
--  the same parameters of LuaSocket's HTTP module (except 'proxy' and
--  'redirect') plus LuaSec parameters.
--
-- @param url mandatory (string or table)
-- @param body optional (string)
-- @return (string if url == string or 1), code, headers, status
--
function request(url, body)
  local result_table = {}
  local stringrequest = type(url) == "string"
  if stringrequest then
    url = urlstring_totable(url, body, result_table)
  end
  if http.PROXY or url.proxy then
    return nil, "proxy not supported"
  end
  -- New 'create' function to establish the proper connection
  url.create = url.create or tcp(url)
  local res, code, headers, status = http.request(url)
  if res and stringrequest then
    return table.concat(result_table), code, headers, status
  end
  return res, code, headers, status
end
