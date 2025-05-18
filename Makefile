CC=gcc
CCFLAGS=-Wall -Wextra -fsanitize=address -g

.PHONY:all

all: server client

client: client.c
	$(CC) $(CCFLAGS) $? -o $@

server: server.c
	$(CC) $(CCFLAGS) $? -o $@