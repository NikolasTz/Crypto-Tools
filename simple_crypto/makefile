CC=gcc
CFLAGS=-I.

%.o: %.c simple_crypto.h
	$(CC) -Wall -c -o $@ $< $(CFLAGS)

demo: simple_crypto.o demo.o 
	$(CC) -Wall -o demo simple_crypto.o demo.o 

clean:
	rm -f *.o demo simple_crypto