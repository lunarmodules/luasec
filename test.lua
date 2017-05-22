local https = require("ssl.https")

local function doreq(url)
  local reqt = {
      url = url,
      --redirect = "all",     --> allows https-> http redirect
      target = {},
  }
  reqt.sink = ltn12.sink.table(reqt.target)

  local result, code, headers, status = https.request(reqt)
  print("Fetching:",url,"==>",code, status)
  if headers then
    print("HEADERS")
    for k,v in pairs(headers) do print("",k,v) end
  end
  return result, code, headers, status
end

--local result, code, headers, status = doreq("http://goo.gl/UBCUc5")   -- http --> https redirect
-- local result, code, headers, status = doreq("https://goo.gl/UBCUc5")  -- https --> https redirect
local result, code, headers, status = doreq("https://goo.gl/tBfqNu")  -- https --> http security test case