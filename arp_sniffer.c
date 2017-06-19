/**
 * comando de compilação:
 * gcc -o arpsniffer arpsniffer.c -Wall
 * comando de execução:
 * ./arpsniffer <interface_de_rede>
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
/* arquivo de interface */
#include "generico.h"
#include "arp_sniffer.h"

int arp_sniffer(char *input_ifname)
{
	int fd;
	unsigned char buffer[BUFFER_SIZE];
	struct ifreq ifr;
	char ifname[IFNAMSIZ];

	strcpy(ifname, input_ifname);

	/* Cria um descritor de socket do tipo RAW */
	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0)
	{
		fprintf(stderr, "Erro ao tentar criar o socket!");
		exit(1);
	}

	/* Obtem o indice da interface de rede */
	strcpy(ifr.ifr_name, ifname);
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
	{
		perror("ioctl");
		exit(1);
	}

	/* Obtem as flags da interface */
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
	{
		perror("ioctl");
		exit(1);
	}

	/* Coloca a interface em modo promiscuo */
	ifr.ifr_flags |= IFF_PROMISC;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
	{
		perror("ioctl");
		exit(1);
	}

	printf(" Esperando pacotes ... \n");
	while (1)
	{
		struct estrutura_pacote_arp pacote;

		/* Recebe pacotes */
		if (recv(fd, (char *)&buffer, BUFFER_SIZE, 0) < 0)
		{
			perror("recv");
			close(fd);
			exit(1);
		}

		/* Copia o conteudo do Ethernet e protocolo ARP */
		memcpy(&pacote, buffer, sizeof(buffer));
		pacote.ethernet_type = ntohs(pacote.ethernet_type);

		if (pacote.ethernet_type == ETHERTYPE)
		{
			printf("\n ----------------------------------------- \n");
			printf("\n -- Cabecalho Ethernet -- \n");
			printf("MAC destino: %02x:%02x:%02x:%02x:%02x:%02x\n",
				   pacote.target_ethernet_address[0],
				   pacote.target_ethernet_address[1],
				   pacote.target_ethernet_address[2],
				   pacote.target_ethernet_address[3],
				   pacote.target_ethernet_address[4],
				   pacote.target_ethernet_address[5]);
			printf("MAC origem:  %02x:%02x:%02x:%02x:%02x:%02x\n",
				   pacote.source_ethernet_address[0],
				   pacote.source_ethernet_address[1],
				   pacote.source_ethernet_address[2],
				   pacote.source_ethernet_address[3],
				   pacote.source_ethernet_address[4],
				   pacote.source_ethernet_address[5]);
			printf("Tipo do protocolo ethernet: 0x%04x\n", pacote.ethernet_type);
			printf("\n -- Pacote ARP -- \n");
			printf("Tipo de hardware: %04x\n", ntohs(pacote.hardware_type));
			printf("Tipo de protocolo: %04x\n", ntohs(pacote.protocol_type));
			printf("Comprimento do endereço arp: %02x\n", pacote.hardware_address_length);
			printf("Comprimento do protocolo arp: %02x\n", pacote.protocol_address_length);
			printf("Tipo da operação: %04x\n", ntohs(pacote.arp_options));
			printf("Endereço fisico de origem:  %02x:%02x:%02x:%02x:%02x:%02x\n",
				   pacote.source_hardware_address[0],
				   pacote.source_hardware_address[1],
				   pacote.source_hardware_address[2],
				   pacote.source_hardware_address[3],
				   pacote.source_hardware_address[4],
				   pacote.source_hardware_address[5]);
			printf("Endereço logico origem:  %d.%d.%d.%d\n",
				   pacote.source_protocol_address[0],
				   pacote.source_protocol_address[1],
				   pacote.source_protocol_address[2],
				   pacote.source_protocol_address[3]);
			printf("Endereço fisico de destino: %02x:%02x:%02x:%02x:%02x:%02x\n",
				   pacote.target_hardware_address[0],
				   pacote.target_hardware_address[1],
				   pacote.target_hardware_address[2],
				   pacote.target_hardware_address[3],
				   pacote.target_hardware_address[4],
				   pacote.target_hardware_address[5]);
			printf("Endereço logico destino:  %d.%d.%d.%d\n",
				   pacote.target_protocol_address[0],
				   pacote.target_protocol_address[1],
				   pacote.target_protocol_address[2],
				   pacote.target_protocol_address[3]);
			printf("Dados do pacote: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
				   pacote.padding[0],
				   pacote.padding[1],
				   pacote.padding[2],
				   pacote.padding[3],
				   pacote.padding[4],
				   pacote.padding[5],
				   pacote.padding[6],
				   pacote.padding[7],
				   pacote.padding[8],
				   pacote.padding[9],
				   pacote.padding[10],
				   pacote.padding[11],
				   pacote.padding[12],
				   pacote.padding[13],
				   pacote.padding[14],
				   pacote.padding[15],
				   pacote.padding[16],
				   pacote.padding[17]);
			printf("\n ----------------------------------------- \n");
			printf("\n");
		}
	}

	close(fd);
	return 0;
}
