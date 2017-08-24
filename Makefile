BP=../firmware
CC=gcc
LDFLAGS=-Llib -lpitchfork
INCS=-Ilib
CFLAGS=-Wall -Wextra -pedantic -Wstrict-overflow -fno-strict-aliasing -Wshadow

all: lib/libpitchfork.so pitchfork armor dearmor

lib/libpitchfork.so:
	make -C lib

pitchfork: main.c
	$(CC) $(INCS) $(CFLAGS) main.c -o $@ $(LDFLAGS)

armor: armor.c forkutils.o
	$(CC) $(CFLAGS) -o armor armor.c forkutils.o

dearmor: dearmor.c forkutils.o
	$(CC) $(CFLAGS) -o dearmor dearmor.c forkutils.o

clean:
	make -C lib clean
	@rm -f pitchfork armor dearmor

.PHONY: clean
