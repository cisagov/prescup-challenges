
CC=gcc
CFLAGS=-O2 -Wall -Wextra
all: rawsock joiner
rawsock: rawsock.c
	$(CC) $(CFLAGS) -o rawsock rawsock.c
joiner: joiner.c
	$(CC) $(CFLAGS) -o joiner joiner.c
clean:
	rm -f rawsock joiner
