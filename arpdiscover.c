#include <pthread.h>
#include <string.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>

#define ETHERNET_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define ARP_PADDING_SIZE 18

pthread_t thread[2];
char ifname[IFNAMSIZ];

struct estrutura_pacote_arp
{
	/* Cabeçalho Ethernet */
	unsigned char target_ethernet_address[ETHERNET_ADDR_LEN];
	unsigned char source_ethernet_address[ETHERNET_ADDR_LEN];
	unsigned short ethernet_type;
	/* Pacote ARP */
	unsigned short hardware_type; // tipo_hardware
	unsigned short protocol_type; // tipo_protocolo

	unsigned char hardware_address_length; // comprimento_endereco_mac
	unsigned char protocol_address_length; // comprimento_endereco_logico

	unsigned short arp_options; // tipo_da_operacao

	unsigned char source_hardware_address[ETHERNET_ADDR_LEN]; // endereco_fisico_origem
	unsigned char source_protocol_address[IP_ADDR_LEN];		  // endereco_logico_origem

	unsigned char target_hardware_address[ETHERNET_ADDR_LEN]; // endereco_fisico_destino
	unsigned char target_protocol_address[IP_ADDR_LEN];		  // endereco_logico_destino
};

void *sendRequests()
{
	int arp_socket, ifreq_socket, optval;
	struct estrutura_pacote_arp pacote;
	struct ifreq ifr;
	struct sockaddr sa;

	//Get MAC address
	if ((ifreq_socket = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP))) < 0)
	{
		perror("ERROR al abrir socket");
		return (void *)-1;
	}

	strcpy(ifr.ifr_name, ifname);
	if (ioctl(ifreq_socket, SIOCGIFHWADDR, &ifr) < 0)
	{
		perror("ERROR al obtener MAC origen");
		return (void *)-1;
	}

	if (ioctl(ifreq_socket, SIOCGIFADDR, &ifr) < 0)
	{
		perror("ERROR al obtener IP origen");
		return (void *)-1;
	}

	memcpy(&pacote.source_ethernet_address, &ifr.ifr_hwaddr.sa_data, ETHERNET_ADDR_LEN);
	memcpy(&pacote.source_hardware_address, &ifr.ifr_hwaddr.sa_data, ETHERNET_ADDR_LEN);
	memcpy(&pacote.source_protocol_address, &ifr.ifr_hwaddr.sa_data[2], IP_ADDR_LEN);

	close(ifreq_socket);

	//Fill most of the packet
	memset(&pacote.target_ethernet_address, 0xff, ETHERNET_ADDR_LEN);
	pacote.ethernet_type = htons(ETH_P_ARP);
	pacote.hardware_type = htons(ARPHRD_ETHER);
	pacote.protocol_type = htons(ETH_P_IP);
	pacote.hardware_address_length = ETHERNET_ADDR_LEN;
	pacote.protocol_address_length = IP_ADDR_LEN;
	pacote.arp_options = htons(ARPOP_REQUEST);
	memset(&pacote.target_hardware_address, 0x00, ETHERNET_ADDR_LEN);

	//Establish subnet
	memcpy(&pacote.target_protocol_address, &pacote.source_protocol_address, 3);

	//Send 254 ARP requests
	int i = 1;

	while (i < 255)
	{
		pacote.target_protocol_address[3] = i;

		if ((arp_socket = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP))) < 0)
		{
			perror("ERROR al abrir socket");
			return (void *)-1;
		}

		if (setsockopt(arp_socket, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) < 0)
		{
			perror("ERROR en la funcion setsockopt");
			return (void *)-1;
		}

		memset(&sa, 0x00, sizeof(sa));
		strcpy(sa.sa_data, ifname);

		if (sendto(arp_socket, &pacote, sizeof(pacote), 0, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		{
			perror("ERROR al enviar");
			return (void *)-1;
		}

		i++;

		close(arp_socket);
	}
}

void *receiveReplies()
{
	int s, n, i;
	struct estrutura_pacote_arp pacote;
	struct sockaddr sa;
	unsigned char source_hardware_address[ETHERNET_ADDR_LEN];
	unsigned char source_protocol_address[IP_ADDR_LEN];

	if ((s = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP))) < 0)
	{
		perror("ERROR al abrir socket");
		return (void *)-1;
	}

	i = 0;
	do
	{
		memset(&sa, 0x00, sizeof(sa));
		memset(&pacote, 0x00, sizeof(pacote));
		n = sizeof(sa);
		if (recvfrom(s, &pacote, sizeof(pacote), 0, (struct sockaddr *)&sa, &n) < 0)
		{
			perror("ERROR al recibir");
			return (void *)-1;
		}
		if ((ntohs(pacote.arp_options) == ARPOP_REPLY))
		{
			i++;

			memcpy(source_hardware_address, &pacote.source_hardware_address, ETHERNET_ADDR_LEN);
			memcpy(source_protocol_address, &pacote.source_protocol_address, IP_ADDR_LEN);

			printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
				   source_hardware_address[0],
				   source_hardware_address[1],
				   source_hardware_address[2],
				   source_hardware_address[3],
				   source_hardware_address[4],
				   source_hardware_address[5]);
				   
			printf("IP: %u.%u.%u.%u\n",
				   source_protocol_address[0],
				   source_protocol_address[1],
				   source_protocol_address[2],
				   source_protocol_address[3]);
		}

	} while (1);
}

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		printf("Usage: %s iface\n", argv[0]);
		return 1;
	}
	strcpy(ifname, argv[1]);

	int err;
	err = pthread_create(&(thread[0]), NULL, &sendRequests, NULL);
	if (err != 0)
		printf("\n Não é possível criar a thread :[%s]", strerror(err));
	else
		printf("\n--Eviando o pacote--\n");

	err = pthread_create(&(thread[1]), NULL, &receiveReplies, NULL);
	if (err != 0)
		printf("\n Não é possível criar a thread :[%s]", strerror(err));
	else
		printf("\n--Recebendo os pacotes--\n");

	sleep(30);
}
