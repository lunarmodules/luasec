OBJS= \
 io.o \
 buffer.o \
 timeout.o \
 usocket.o

CC=gcc
CFLAGS=$(MYCFLAGS) -DLUASOCKET_DEBUG

.PHONY: all clean

all: libluasocket.a

libluasocket.a: $(OBJS)
	ar rcu $@ $(OBJS)
	ranlib $@

clean:
	rm -f $(OBJS) libluasocket.a

buffer.o: buffer.c buffer.h io.h timeout.h
io.o: io.c io.h timeout.h
timeout.o: timeout.c timeout.h
usocket.o: usocket.c socket.h io.h timeout.h usocket.h
