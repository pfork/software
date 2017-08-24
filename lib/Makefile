BP=../../firmware
LDFLAGS=-lusb-1.0 -lsodium
INCS=-Ilib -I$(BP)/lib/sphincs -I$(BP)/crypto -I$(BP)/lib/newhope -I. -I/usr/include/sodium/
CFLAGS=-Wall -Wextra -pedantic -Wstrict-overflow -fno-strict-aliasing -Wshadow -fpic

sphincsobjs = crypto_stream_chacha20.o wots.o prg.o hash.o horst.o sign.o permute.o

all: libpitchfork.so

libpitchfork.so: $(sphincsobjs) pitchfork.o
	$(CC) -shared $(INCS) $(CFLAGS) -o $@ $(sphincsobjs) pitchfork.o $(LDFLAGS)

pitchfork.o: pitchfork.c
	gcc $(INCS) $(CFLAGS) -o $@ -c $<

crypto_stream_chacha20.o: $(BP)/lib/sphincs/crypto_stream_chacha20.c
	gcc $(INCS) $(CFLAGS) -o $@ -c $<

wots.o: $(BP)/lib/sphincs/wots.c
	gcc $(INCS) $(CFLAGS) -o $@ -c $<

prg.o: $(BP)/lib/sphincs/prg.c
	gcc $(INCS) $(CFLAGS) -o $@ -c $<

hash.o: $(BP)/lib/sphincs/hash.c
	gcc $(INCS) $(CFLAGS) -o $@ -c $<

horst.o: $(BP)/lib/sphincs/horst.c
	gcc $(INCS) $(CFLAGS) -o $@ -c $<

sign.o: $(BP)/lib/sphincs/sign.c
	gcc $(INCS) $(CFLAGS) -o $@ -c $<

permute.o: $(BP)/lib/sphincs/permute.c
	gcc $(INCS) $(CFLAGS) -o $@ -c $<

forkutils.o: forkutils.c
	gcc $(INCS) $(CFLAGS) -o $@ -c $<

lib/pitchfork.o: lib/pitchfork.c
	gcc $(INCS) $(CFLAGS) -o $@ -c $<

clean:
	@rm -f $(sphincsobjs) pitchfork.o libpitchfork.so

.PHONY: clean
