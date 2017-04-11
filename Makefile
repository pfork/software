BP=../firmware
LDFLAGS=-lusb-1.0 -lsodium
CFLAGS=-Ilib -I$(BP)/lib/sphincs -I$(BP)/crypto -I$(BP)/lib/newhope -I. -I/usr/include/sodium/  -Wall -Wextra -pedantic -Wstrict-overflow -fno-strict-aliasing -Wshadow

sphincsobjs = crypto_stream_chacha20.o wots.o prg.o hash.o horst.o sign.o permute.o

all: pitchfork

pitchfork: $(sphincsobjs) lib/pitchfork.o main.c
	$(CC) $(CFLAGS) main.c -o $@ $(sphincsobjs) lib/pitchfork.o $(LDFLAGS)

crypto_stream_chacha20.o: $(BP)/lib/sphincs/crypto_stream_chacha20.c
	gcc $(CFLAGS) -o $@ -c $<

wots.o: $(BP)/lib/sphincs/wots.c
	gcc $(CFLAGS) -o $@ -c $<

prg.o: $(BP)/lib/sphincs/prg.c
	gcc $(CFLAGS) -o $@ -c $<
	
hash.o: $(BP)/lib/sphincs/hash.c
	gcc $(CFLAGS) -o $@ -c $<

horst.o: $(BP)/lib/sphincs/horst.c
	gcc $(CFLAGS) -o $@ -c $<

sign.o: $(BP)/lib/sphincs/sign.c
	gcc $(CFLAGS) -o $@ -c $<

permute.o: $(BP)/lib/sphincs/permute.c
	gcc $(CFLAGS) -o $@ -c $<

clean:
	@rm -f $(sphincsobjs) lib/pitchfork.o pitchfork

.PHONY: clean
