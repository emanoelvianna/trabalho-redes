#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <pthread.h>

/* utilizando os utilitarios */
#include "generico.h"
#include "arp_sniffer.h"
#include "arp_discover.h"

char ifname[IFNAMSIZ];
char target_ip[15];
char router_ip[15];

/* retorna o mac do ip passado pelo parametro */
int getMac(char *ip)
{
    return 0;
};

/* preparando para realizar o ataque */
int poisoning()
{
    return 0;
};

void get_mac_address(struct ifreq *ethernet, char *iface, unsigned char source_eth_addr[ETHERNET_ADDR_LEN])
{
    int file_descriptor = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strncpy(ethernet->ifr_name, iface, IF_NAMESIZE);

    /* Copies the MAC address into ethernet ifreq struct object */
    if (ioctl(file_descriptor, SIOCGIFHWADDR, ethernet) == -1)
    {
        fprintf(stderr, "Error: Cannot get ethernet address: ");
        exit(1);
    }

    sprintf(
        (char *)source_eth_addr, "%s",
        (char *)ethernet->ifr_hwaddr.sa_data);

    close(file_descriptor);
}

void usage(char *exec)
{
    printf("%s -arp_discover <interface de rede>\n", exec);
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        usage(argv[0]);
    }
    else
    {
        /* -arp_sniffer */
        if (!strcmp(argv[1], "-arp_sniffer"))
        {
            if (argc < 3)
            {
                printf("%s -arp_sniffer <interface de rede>\n", argv[0]);
            }
            else
            {
                arp_sniffer(argv[2]);
            }
        }
        /* -arp_discover */
        if (!strcmp(argv[1], "-arp_discover"))
        {
            if (argc < 3)
            {
                printf("%s -arp_discover <interface de rede>\n", argv[0]);
            }
            else
            {
                arp_discover(argv[2]);
            }
        }
    }
    return 0;
}
