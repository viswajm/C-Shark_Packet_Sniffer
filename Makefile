CC=gcc
CFLAGS=-Wall -Wextra -I..
LDFLAGS=-lpcap -pthread

all: cshark

# Directories
SRC_DIR = src

cshark: $(SRC_DIR)/cshark.c
	$(CC) $(CFLAGS) -o cshark $(SRC_DIR)/cshark.c $(LDFLAGS)

clean:
	-rm -f cshark