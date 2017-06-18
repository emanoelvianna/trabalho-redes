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
//#include "arp_discover.c"

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

int arp_discover(char *input_ifname)
{
    return 0;
};

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        printf("Informe a interface de rede: %s iface\n", argv[0]);
        return 1;
    }
    strcpy(ifname, argv[1]);
    printf("%s\n", ifname);
    strcpy(target_ip, argv[2]);
    printf("%s\n", target_ip);
    strcpy(router_ip, argv[3]);
    printf("%s\n", router_ip);

    return 0;
}
