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

#define BUFFER_SIZE 1600 /** tamanho do buffer de leitura do pacote arp **/
#define ETHERTYPE 0x0806 /** indicando que é do tipo arp **/

/** Estrutura de dados de um pacote Ethernet encapsulando um pacote ARP **/
#define ETHERNET_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define ARP_PADDING_SIZE 18

struct estrutura_pacote_arp
{

	/* Cabeçalho Ethernet */
	unsigned char source_ethernet_address[ETHERNET_ADDR_LEN]; // endereco_fisico
	unsigned char target_ethernet_address[ETHERNET_ADDR_LEN]; // endereco_logico
	unsigned short ethernet_type;							  // tipo_protocolo_ethernet

	/* Cabeçalho ARP */
	unsigned short int hardware_type; // tipo_hardware
	unsigned short int protocol_type; // tipo_protocolo

	unsigned char hardware_address_length; // comprimento_endereco_mac
	unsigned char protocol_address_length; // comprimento_endereco_logico

	unsigned short int arp_options; // tipo_da_operacao

	unsigned char source_hardware_address[ETHERNET_ADDR_LEN]; // endereco_fisico_origem
	unsigned char source_protocol_address[IP_ADDR_LEN];		  // endereco_logico_origem

	unsigned char target_hardware_address[ETHERNET_ADDR_LEN]; // endereco_fisico_destino
	unsigned char target_protocol_address[IP_ADDR_LEN];		  // endereco_logico_destino

	unsigned char padding[ARP_PADDING_SIZE]; // dados_de_preenchimento
};

int main(int argc, char *argv[])
{
	int fd;
	unsigned char buffer[BUFFER_SIZE];
	struct ifreq ifr;
	char ifname[IFNAMSIZ];

	if (argc != 2)
	{
		printf("Informe a interface de rede: %s iface\n", argv[0]);
		return 1;
	}
	strcpy(ifname, argv[1]);

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
