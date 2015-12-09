------------------------------------------------------------------------------
-- LuaSec 0.5
-- Copyright (C) 2006-2014 Bruno Silvestre
--
------------------------------------------------------------------------------

local core    = require("ssl.core")
local context = require("ssl.context")
local x509    = require("ssl.x509")

module("ssl", package.seeall)

_VERSION   = "0.5.PR"
_COPYRIGHT = core.copyright()

-- Export
loadcertificate = x509.load

-- We must prevent the contexts to be collected before the connections,
-- otherwise the C registry will be cleared.
local registry = setmetatable({}, {__mode="k"})

--
--
--
local function optexec(func, param, ctx)
  if param then
    if type(param) == "table" then
      return func(ctx, unpack(param))
    else
      return func(ctx, param)
    end
  end
  return true
end

local function tolengthstring(table)
    local str = ""

    for k,v in ipairs(table) do
      local len = #v

      if len > 255 then
        return nil, "invalid value: " .. v
      end

      str = str .. string.char(len) .. v
    end

    return str
end

--
--
--
function newcontext(cfg)
   local succ, msg, ctx
   -- Create the context
   ctx, msg = context.create(cfg.protocol)
   if not ctx then return nil, msg end
   -- Mode
   succ, msg = context.setmode(ctx, cfg.mode)
   if not succ then return nil, msg end
   -- Load the key
   if cfg.key then
      if cfg.password and
         type(cfg.password) ~= "function" and
         type(cfg.password) ~= "string"
      then
         return nil, "invalid password type"
      end
      succ, msg = context.loadkey(ctx, cfg.key, cfg.password)
      if not succ then return nil, msg end
   end
   -- Load the certificate
   if cfg.certificate then
      succ, msg = context.loadcert(ctx, cfg.certificate)
      if not succ then return nil, msg end
   end
   -- Load the CA certificates
   if cfg.cafile or cfg.capath then
      succ, msg = context.locations(ctx, cfg.cafile, cfg.capath)
      if not succ then return nil, msg end
   end
   -- Set SSL ciphers
   if cfg.ciphers then
      succ, msg = context.setcipher(ctx, cfg.ciphers)
      if not succ then return nil, msg end
   end
   -- Set the verification options
   succ, msg = optexec(context.setverify, cfg.verify, ctx)
   if not succ then return nil, msg end
   -- Set SSL options
   succ, msg = optexec(context.setoptions, cfg.options, ctx)
   if not succ then return nil, msg end
   -- Set the depth for certificate verification
   if cfg.depth then
      succ, msg = context.setdepth(ctx, cfg.depth)
      if not succ then return nil, msg end
   end

   -- NOTE: Setting DH parameters and elliptic curves needs to come after
   -- setoptions(), in case the user has specified the single_{dh,ecdh}_use
   -- options.

   -- Set DH parameters
   if cfg.dhparam then
      if type(cfg.dhparam) ~= "function" then
         return nil, "invalid DH parameter type"
      end
      context.setdhparam(ctx, cfg.dhparam)
   end
   -- Set elliptic curve
   if cfg.curve then
      succ, msg = context.setcurve(ctx, cfg.curve)
      if not succ then return nil, msg end
   end
   -- Set extra verification options
   if cfg.verifyext and ctx.setverifyext then
      succ, msg = optexec(ctx.setverifyext, cfg.verifyext, ctx)
      if not succ then return nil, msg end
   end
   if cfg.alpn then
    local str, msg = tolengthstring(cfg.alpn)
    if not str then return nil, msg end

    succ, msg = context.setalpn(ctx, str)
    if not succ then return nil, msg end
   end
   if cfg.alpn_cb then
    if type(cfg.alpn_cb) ~= "function" then
      return nil, "invalid alpn_cb parameter type"
    end

    context.setalpncb(ctx, function (str)
      local protocols = {}
      local i = 1

      while i < #str do
        local len = str:byte(i)
        protocols[#protocols + 1] = str:sub(i + 1, i + len)
        i = i + len + 1
      end

      local ret = cfg.alpn_cb(protocols)
      return tolengthstring({ret})
    end)
   elseif cfg.mode == "server" and cfg.alpn then
    context.setalpncb(ctx, function ()
      return tolengthstring(cfg.alpn)
    end)
   end

   return ctx
end

--
--
--
function wrap(sock, cfg)
   local ctx, msg
   if type(cfg) == "table" then
      ctx, msg = newcontext(cfg)
      if not ctx then return nil, msg end
   else
      ctx = cfg
   end
   local s, msg = core.create(ctx)
   if s then
      core.setfd(s, sock:getfd())
      sock:setfd(core.invalidfd)
      registry[s] = ctx
      return s
   end
   return nil, msg 
end

--
-- Extract connection information.
--
local function info(ssl, field)
  local str, comp, err, protocol
  comp, err = core.compression(ssl)
  if err then
    return comp, err
  end
  -- Avoid parser
  if field == "compression" then
    return comp
  end
  local info = {compression = comp}
  str, info.bits, info.algbits, protocol, alpn = core.info(ssl)
  if str then
    info.cipher, info.protocol, info.key,
    info.authentication, info.encryption, info.mac =
        string.match(str, 
          "^(%S+)%s+(%S+)%s+Kx=(%S+)%s+Au=(%S+)%s+Enc=(%S+)%s+Mac=(%S+)")
    info.export = (string.match(str, "%sexport%s*$") ~= nil)
  end
  if protocol then
    info.protocol = protocol
  end
  if alpn then
    info.alpn = alpn
  end
  if field then
    return info[field]
  end
  -- Empty?
  return ( (next(info)) and info )
end

--
-- Set method for SSL connections.
--
core.setmethod("info", info)

