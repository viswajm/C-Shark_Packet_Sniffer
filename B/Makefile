CC=gcc
CFLAGS=-Wall -Wextra -I..
LDFLAGS=-lpcap

all: cshark

cshark: cshark.c
	$(CC) $(CFLAGS) -o cshark cshark.c $(LDFLAGS)

clean:
	-rm -f cshark