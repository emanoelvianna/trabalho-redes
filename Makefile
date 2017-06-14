all:
	gcc -o arpsniffer arpsniffer.c -Wall
	gcc -o arpdiscover arpdiscover.c -Wall -lm -lpthread
clean:
	rm -f arpsniffer arpdiscover