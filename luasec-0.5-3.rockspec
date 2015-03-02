package = "LuaSec"
version = "0.5-3"
source = {
   url = "git://github.com/brunoos/luasec.git",
   tag = "luasec-0.5"
}
description = {
   summary = "A binding for OpenSSL library to provide TLS/SSL communication over LuaSocket.",
   detailed = "This version delegates to LuaSocket the TCP connection establishment between the client and server. Then LuaSec uses this connection to start a secure TLS/SSL session.",
   homepage = "https://github.com/brunoos/luasec/wiki",
   license = "MIT"
}
dependencies = {
   "lua >= 5.1", "luasocket"
}
external_dependencies = {
   OPENSSL = {
      header = "openssl/ssl.h",
      library = "ssl",
   },
}
build = {
   type = "builtin",
   copy_directories = {
      "samples"
   },
   platforms = {
      unix = {
         install = {
            lib = {
               "ssl.so"
            },
            lua = {
               "src/ssl.lua", ['ssl.https'] = "src/https.lua"
            }
         },
         modules = {
            ssl = {
               incdirs = {
                  "$(OPENSSL_INCDIR)", "src/", "src/luasocket",
               },
               libdirs = {
                  "$(OPENSSL_LIBDIR)"
               },
               libraries = {
                  "ssl", "crypto"
               },
               sources = {
                  "src/x509.c", "src/context.c", "src/ssl.c", 
                  "src/luasocket/buffer.c", "src/luasocket/io.c",
                  "src/luasocket/timeout.c", "src/luasocket/usocket.c"
               }
            }
         }
      },
      windows = {
         install = {
            lib = {
               "ssl.dll"
            },
            lua = {
               "src/ssl.lua", ['ssl.https'] = "src/https.lua"
            }
         },
         modules = {
            ssl = {
               defines = {
                  "WIN32", "NDEBUG", "_WINDOWS", "_USRDLL", "LSEC_EXPORTS", "BUFFER_DEBUG", "LSEC_API=__declspec(dllexport)"
               },
               libdirs = {
                  "$(OPENSSL_LIBDIR)",
               },
               libraries = {
                  "ssl", "crypto", "ws2_32",
               },
               incdirs = {
                  "$(OPENSSL_INCDIR)", "src/", "src/luasocket"
               },
               sources = {
                  "src/x509.c", "src/context.c", "src/ssl.c", 
                  "src/luasocket/buffer.c", "src/luasocket/io.c",
                  "src/luasocket/timeout.c", "src/luasocket/wsocket.c"
               }
            }
         }
      }
   }
}
