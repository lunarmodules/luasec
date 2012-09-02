# Inform the location to intall the modules
LUAPATH=/usr/local/share/lua/5.1
LUACPATH=/usr/local/lib/lua/5.1

# Edit the lines below to inform new path, if necessary
#
#INCDIR=-I/usr/local/lua-5.1/include -I/usr/local/openssl-0.9.8/include
#LIBDIR=-L/usr/local/openssl-0.9.8/lib -R/usr/local/openssl-0.9.8/lib

# For Mac OS X: set the system version
MACOSX_VERSION=10.4

DEFS=-DBUFFER_DEBUG

#----------------------
# Do not edit this part

.PHONY: all clean install none linux bsd macosx

all: none

none:
	@echo "Usage: $(MAKE) <platform>"
	@echo "  * linux"
	@echo "  * bsd"
	@echo "  * macosx"

install:
	@cd src ; $(MAKE) LUACPATH="$(LUACPATH)" LUAPATH="$(LUAPATH)" install

linux:
	@echo "---------------------"
	@echo "** Build for Linux **"
	@echo "---------------------"
	@cd src ; $(MAKE) INCDIR="$(INCDIR)" LIBDIR="$(LIBDIR)" DEFS="$(DEFS)" $@

bsd:
	@echo "-------------------"
	@echo "** Build for BSD **"
	@echo "-------------------"
	@cd src ; $(MAKE) INCDIR="$(INCDIR)" LIBDIR="$(LIBDIR)" DEFS="$(DEFS)" $@

macosx:
	@echo "------------------------------"
	@echo "** Build for Mac OS X $(MACOSX_VERSION) **"
	@echo "------------------------------"
	@cd src ; $(MAKE) INCDIR="$(INCDIR)" LIBDIR="$(LIBDIR)" DEFS="$(DEFS)" MACVER="$(MACOSX_VERSION)" $@

clean:
	@cd src ; $(MAKE) clean
