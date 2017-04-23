TARGET=pitchfork-p11.so
CC=gcc
CFLAGS= -Werror -Wall -fPIC -Wextra -pedantic -Wstrict-overflow -fno-strict-aliasing -Wshadow -Wno-unused-parameter
LDFLAGS=-Wl,-soname,$(TARGET)
OBJS=pkcs11.o

all: $(TARGET)

%.o: %.c
	$(CC) -c $< $(CFLAGS)

$(TARGET): $(OBJS)
	$(CC) -shared $(OBJS) -o $(TARGET) $(LDFLAGS)

test: test.c $(TARGET)
	$(CC) -o test test.c $(TARGET) -lusb-1.0
	LD_LIBRARY_PATH=. ./test

clean:
	rm -f $(TARGET) $(OBJS)
