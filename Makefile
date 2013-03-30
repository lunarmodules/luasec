# Inform the location to intall the modules
LUAPATH=/usr/local/share/lua/5.1
LUACPATH=/usr/local/lib/lua/5.1

# Compile with build-in LuaSocket's help files.
# Comment this lines if you will link with non-internal LuaSocket's help files
#  and edit INCDIR and LIBDIR properly.
EXTRA=luasocket
DEFS=-DWITH_LUASOCKET

# Edit the lines below to inform new path, if necessary.
# Path below points to internal LuaSocket's help files.
INCDIR=-I.
LIBDIR=-L./luasocket

# For Mac OS X: set the system version
MACOSX_VERSION=10.4

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
	@cd src && $(MAKE) LUACPATH="$(LUACPATH)" LUAPATH="$(LUAPATH)" install

linux:
	@echo "---------------------"
	@echo "** Build for Linux **"
	@echo "---------------------"
	@cd src && $(MAKE) INCDIR="$(INCDIR)" LIBDIR="$(LIBDIR)" DEFS="$(DEFS)" EXTRA="$(EXTRA)" $@

bsd:
	@echo "-------------------"
	@echo "** Build for BSD **"
	@echo "-------------------"
	@cd src && $(MAKE) INCDIR="$(INCDIR)" LIBDIR="$(LIBDIR)" DEFS="$(DEFS)" EXTRA="$(EXTRA)" $@

macosx:
	@echo "------------------------------"
	@echo "** Build for Mac OS X $(MACOSX_VERSION) **"
	@echo "------------------------------"
	@cd src && $(MAKE) INCDIR="$(INCDIR)" LIBDIR="$(LIBDIR)" MACVER="$(MACOSX_VERSION)" DEFS="$(DEFS)" EXTRA="$(EXTRA)" $@

clean:
	@cd src && $(MAKE) clean
