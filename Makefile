CFLAGS = -lpthread -Wall
LIBS=

SRC=$(wildcard *.c)

arp_util: $(SRC)
	gcc -o $@ $^ $(CFLAGS) $(LIBS)
	
clean:
	rm -f *.o
	rm -f arp_util