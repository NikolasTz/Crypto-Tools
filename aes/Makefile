CC = gcc
DBUG = -g
CCFLAGS = -O2 -Wall -pedantic
LIBSSL = -lssl -lcrypto

TARGETS = aes


all: $(TARGETS)

aes: aes.c
	$(CC) $(CCFLAGS) $(DBUG) -o $@ $< $(LIBSSL)

clean:
	rm -f $(TARGETS)
