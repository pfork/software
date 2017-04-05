LDFLAGS=-lusb-1.0 -lsodium
CFLAGS=-Ilib -Isphincs -I../firmware/crypto -I../firmware/lib/newhope -I. -I/usr/include/sodium/  -Wall -Wextra -pedantic -Wstrict-overflow -fno-strict-aliasing -Wshadow

sphincsobjs = sphincs/consts.o sphincs/hash.o sphincs/horst.o sphincs/permute.o sphincs/prg.o sphincs/sign.o sphincs/wots.o

all: pitchfork

pitchfork: $(sphincsobjs) lib/pitchfork.o main.c
	$(CC) $(CFLAGS) main.c -o $@ $(sphincsobjs) lib/pitchfork.o $(LDFLAGS)

clean:
	@rm -f $(sphincsobjs) lib/pitchfork.o pitchfork

.PHONY: clean
