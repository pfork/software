LDFLAGS=-lusb-1.0 -lsodium
CFLAGS=-Ilib -Isphincs -I. # -Wall -Wextra -pedantic -Wstrict-overflow -fno-strict-aliasing -Wshadow

sphincsobjs = sphincs/consts.o sphincs/hash.o sphincs/horst.o sphincs/permute.o sphincs/prg.o sphincs/sign.o sphincs/wots.o

all: pitchfork

pitchfork: $(sphincsobjs) lib/pitchfork.o main.c
	$(CC) $(CFLAGS) main.c -o $@ $(sphincsobjs) lib/pitchfork.o $(LDFLAGS)

clean:
	@rm $(sphincsobjs) lib/pitchfork.o pitchfork || true

.PHONY: clean
