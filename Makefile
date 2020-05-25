CC=gcc
CFLAGS=-O2 -ggdb -Wall -Wextra -pedantic -I/usr/local/opt/openssl/include
LDFLAGS=-L/usr/local/opt/openssl/lib

# CFLAGS += -DRLDISABLED

all: extractcc tlscc

extractcc: extractcc.o
	$(CC) extractcc.o -o extractcc -lpcap

tlscc: tlscc.o
	$(CC) $(LDFLAGS) tlscc.o -o tlscc -lcrypto

clean:
	rm -f tlscc.o extractcc.o tlscc extractcc core
