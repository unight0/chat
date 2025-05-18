CC=gcc
CCFLAGS=-Wall -Wextra #-fsanitize=address -g
WINCC=x86_64-w64-mingw32-gcc
WINCCFLAGS=
WINLDFLAGS=-lws2_32

.PHONY:all

all: server client

client: client.c
	$(CC) $(CCFLAGS) $? -o $@

win-client: client.c
	$(WINCC) $(WINCCFLAGS) $? -o $@ $(WINLDFLAGS)

server: server.c
	$(CC) $(CCFLAGS) $? -o $@