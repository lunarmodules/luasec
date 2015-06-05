------------------------------------------------------------------------------
-- LuaSec 0.5
-- Copyright (C) 2006-2014 Bruno Silvestre
--
------------------------------------------------------------------------------

local socket  = require("socket")
local core    = require("ssl.core")
local context = require("ssl.context")
local x509    = require("ssl.x509")

local unpack  = table.unpack or unpack

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

--
--
--
local function newcontext(cfg)
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
     if cfg.key and context.checkkey then
       succ = context.checkkey(ctx)
       if not succ then return nil, "private key does not match public key" end
     end
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

   return ctx
end

--
--
--
local function wrap(sock, cfg)
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
      sock:setfd(-1)
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
  str, info.bits, info.algbits, protocol = core.info(ssl)
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
  if field then
    return info[field]
  end
  -- Empty?
  return ( (next(info)) and info )
end

--
-- Verify host name against a common name
--
local function checkhostname_single(hostname, cn)
  if cn:match("^%*%.") then
    -- If it's a wildcard domain name, strip the first element of the hostname
    -- and the cn, then check neither are empty.
    hostname = hostname:match("%.(.+)$")
    cn = cn:match("%.(.+)$")
    if cn == "" or hostname == "" then return false end
  end
  return cn == hostname
end

--
-- Verify host name against certificate
--
local function checkhostname(cert, hostname)
  local subject, ext
  subject = cert:subject()
  for i, v in ipairs(subject) do
    if v.name == "commonName" then
      if checkhostname_single(hostname, v.value) then
        return true
      end
      break
    end
  end
  -- If we got here, the cn doesn't match, check for the dNSName extension
  ext = (cert:extensions() or {})["2.5.29.17"]
  if not ext or not ext.dNSName then return false end
  for i, v in ipairs(ext.dNSName) do
    if checkhostname_single(hostname, v) then
      return true
    end
  end
  return false
end

--
-- Verify host name against peer certificate
--
local function checkhostname_ssl(ssl, hostname)
  return checkhostname(ssl:getpeercertificate(), hostname)
end

--
-- Connect helper
--
local function connect(hostname, port, flags)
  local sock, conn, success, err
  sock = socket.tcp()
  success, err = sock:connect(hostname, port)
  if not success then
    return nil, err
  end
  flags = flags or {}
  flags.mode = "client"
  flags.verify = flags.verify or "none"
  flags.protocol = flags.protocol or "tlsv1_2"
  conn, err = ssl.wrap(sock, flags or {})
  if not conn then
    sock:close()
    return nil, err
  end
  success, err = conn:dohandshake()
  if not success then
    return nil, err
  end
  if not conn:checkhostname(hostname) then
    sock:close()
    return nil, "hostname does not match certificate"
  end
  return conn, sock
end

--
-- Set method for SSL connections.
--
core.setmethod("info", info)
core.setmethod("checkhostname", checkhostname_ssl)

--------------------------------------------------------------------------------
-- Export module
--

local _M = {
  _VERSION        = "0.5",
  _COPYRIGHT      = core.copyright(),
  loadcertificate = x509.load,
  newcontext      = newcontext,
  wrap            = wrap,
  checkhostname   = checkhostname,
  connect         = connect,
}

return _M
