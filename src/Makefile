CMOD=ssl.so
LMOD=ssl.lua

OBJS= \
 timeout.o \
 buffer.o \
 io.o \
 usocket.o \
 context.o \
 ssl.o

LIBS=-lssl -lcrypto

WARN=-Wall -pedantic

BSD_CFLAGS=-O2 -fpic $(WARN) $(INCDIR) $(DEFS)
BSD_LDFLAGS=-O -shared -fpic $(LIBDIR)

LNX_CFLAGS=-O2 -fpic $(WARN) $(INCDIR) $(DEFS)
LNX_LDFLAGS=-O -shared -fpic $(LIBDIR)

MAC_ENV=env MACOSX_DEPLOYMENT_TARGET='$(MACVER)'
MAC_CFLAGS=-O2 -fno-common $(WARN) $(INCDIR) $(DEFS)
MAC_LDFLAGS=-bundle -undefined dynamic_lookup $(LIBDIR)

CC=gcc
LD=$(MYENV) gcc
CFLAGS=$(MYCFLAGS)
LDFLAGS=$(MYLDFLAGS)

.PHONY: all clean install none linux bsd macosx

all:

install: $(CMOD) $(LMOD)
	mkdir -p $(LUAPATH)/ssl
	cp $(CMOD) $(LUACPATH)
	cp $(LMOD) $(LUAPATH)
	cp https.lua $(LUAPATH)/ssl

linux:
	@$(MAKE) $(CMOD) MYCFLAGS="$(LNX_CFLAGS)" MYLDFLAGS="$(LNX_LDFLAGS)"

bsd:
	@$(MAKE) $(CMOD) MYCFLAGS="$(BSD_CFLAGS)" MYLDFLAGS="$(BSD_LDFLAGS)"

macosx:
	@$(MAKE) $(CMOD) MYCFLAGS="$(MAC_CFLAGS)" MYLDFLAGS="$(MAC_LDFLAGS)" MYENV="$(MAC_ENV)"


$(CMOD): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

clean:
	rm -f $(OBJS) $(CMOD)

buffer.o: buffer.c buffer.h io.h timeout.h
io.o: io.c io.h timeout.h
timeout.o: timeout.c timeout.h
usocket.o: usocket.c socket.h io.h timeout.h usocket.h
context.o: context.c context.h
ssl.o: ssl.c socket.h io.h timeout.h usocket.h buffer.h context.h context.c
