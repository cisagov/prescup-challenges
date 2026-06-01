
CC=gcc
CFLAGS=-O2 -fPIC -Wall -Wextra -D_GNU_SOURCE
BIN=bin

all: $(BIN)/agent_daemon $(BIN)/libldshim.so $(BIN)/optic_helper

$(BIN):
	mkdir -p $(BIN)

$(BIN)/agent_daemon: src/agent_daemon.c src/util.c src/util.h src/rot13.h
	$(CC) $(CFLAGS) -o $@ src/agent_daemon.c src/util.c

$(BIN)/libldshim.so: src/ldshim.c src/util.c src/util.h
	$(CC) $(CFLAGS) -shared -o $@ src/ldshim.c src/util.c -ldl

$(BIN)/optic_helper: src/optic_helper.c
	$(CC) $(CFLAGS) -o $@ src/optic_helper.c -ldl

clean:
	rm -rf $(BIN)
