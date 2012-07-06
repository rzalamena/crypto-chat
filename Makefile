CC	 =	/usr/bin/gcc
RM	 =	/bin/rm -f
MAKE	 =	/usr/bin/make

CFLAGS	+=	-Wall
CFLAGS  +=      -Wstrict-prototypes -Wmissing-prototypes
CFLAGS  +=      -Wmissing-declarations -Wshadow
CFLAGS  +=      -Wpointer-arith -Wcast-qual
CFLAGS  +=      -Wsign-compare
LDFLAGS	+=	-lssl -lcrypto

OBJS	 =	main.o
BIN	 =	messenger

.PHONY: clean

.c.o:
	$(CC) $(CFLAGS) -c $<;

all: $(BIN)

$(BIN): $(PULIB) $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $@;

clean:
	$(RM) $(BIN) $(OBJS) cscope.*
