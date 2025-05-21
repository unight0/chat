CC=gcc
CCFLAGS=-Wall -Wextra -DGUI_CLIENT -lraylib -lm -Wno-unused-parameter #-fsanitize=address -g
GUICCFLAGS=-DGUI_CLIENT -Wno-unused-parameter
GUILDFLAGS=-lraylib -lm
WINCC=x86_64-w64-mingw32-gcc
WINCCFLAGS=
WINLDFLAGS=-lws2_32

.PHONY:all

all: server client gui-client

client: client.c
	$(CC) $(CCFLAGS) $? -o $@

gui-client: client.c
	$(CC) $(CCFLAGS) $(GUICCFLAGS) $(GUILDFLAGS) $? -o $@

win-gui-client: client.c
	$(WINCC) $(WINCCFLAGS) $(GUICCFLAGS) $? -o $@ $(WINLDFLAGS) $(GUILDFLAGS)

win-client: client.c
	$(WINCC) $(WINCCFLAGS) $? -o $@ $(WINLDFLAGS)

server: server.c
	$(CC) $(CCFLAGS) $? -o $@
