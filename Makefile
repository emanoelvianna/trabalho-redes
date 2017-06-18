all:
	gcc -o arp_sniffer arp_sniffer.c -Wall
	gcc -o arp_discover arp_discover.c -Wall -lm -lpthread
	gcc -o arp_poisoning arp_poisoning.c -Wall
clean:
	rm -f arp_sniffer arp_discover arp_poisoning