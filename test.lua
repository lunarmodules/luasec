https = require "ssl.https"

function show_html(url)

  local response, code, headers, status = https.request(url)

  if code == 200 then
    print ("Response :", response)
    print ("HTTP Code :", code)
    print ("Headers :", headers)
    print ("Status :", status)
    return nil 
  end

  -- print(response)
end

show_html("https://rnikhil275.github.io")