/**
 * comando de compilação:
 * gcc -o arpdiscover arpdiscover.c -Wall -lm -lpthread
 * comando de execução:
 * ./arpdiscover <interface_de_rede>
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
#include <pthread.h>
/* arquivo de interface */
#include "generico.h"
#include "arp_discover.h"

pthread_t thread_send;
pthread_t thread_receive;
char ifname[IFNAMSIZ];
struct estrutura_host *hosts;
int capacidade = 5;
int posicao = 0;

/** realizando um request na rede **/
void *sendRequests()
{
	int arp_socket, ifreq_socket, optval;
	struct estrutura_pacote_arp pacote;
	struct ifreq ifr;
	struct sockaddr sa;

	/* Cria um descritor de socket do tipo RAW */
	if ((ifreq_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
	{
		perror("Erro ao tentar criar o socket!");
		return (void *)-1;
	}

	/* Obtem o endereco MAC da interface local */
	strcpy(ifr.ifr_name, ifname);
	if (ioctl(ifreq_socket, SIOCGIFHWADDR, &ifr) < 0)
	{
		perror("Erro ao tentar obter MAC de origem!");
		return (void *)-1;
	}

	/* Obtem o endereco IP da interface local */
	if (ioctl(ifreq_socket, SIOCGIFADDR, &ifr) < 0)
	{
		perror("ERROR ao tentar obter IP de origem!");
		return (void *)-1;
	}

	/** montando o pacote ARP **/
	memcpy(&pacote.source_ethernet_address, &ifr.ifr_hwaddr.sa_data, ETHERNET_ADDR_LEN);
	memcpy(&pacote.source_hardware_address, &ifr.ifr_hwaddr.sa_data, ETHERNET_ADDR_LEN);
	memcpy(&pacote.source_protocol_address, &ifr.ifr_hwaddr.sa_data[2], IP_ADDR_LEN);

	close(ifreq_socket);

	memset(&pacote.target_ethernet_address, 0xff, ETHERNET_ADDR_LEN);
	pacote.ethernet_type = htons(ETHERTYPE);
	pacote.hardware_type = htons(ARPHRD_ETHER);
	pacote.protocol_type = htons(ETH_P_IP);
	pacote.hardware_address_length = ETHERNET_ADDR_LEN;
	pacote.protocol_address_length = IP_ADDR_LEN;
	pacote.arp_options = htons(ARPOP_REQUEST);
	memset(&pacote.target_hardware_address, 0x00, ETHERNET_ADDR_LEN);

	memcpy(&pacote.target_protocol_address, &pacote.source_protocol_address, 3);

	/** buscando host na rede **/
	int i = 1;
	while (i < 255)
	{
		/** variando os valores de endereço **/
		pacote.target_protocol_address[3] = i;

		/** criando um socket arp utilizando Internet Protocol v4 **/
		if ((arp_socket = socket(AF_INET, SOCK_PACKET, htons(ETHERTYPE))) < 0)
		{
			perror("ERROR ao abrir o socket");
			return (void *)-1;
		}

		/** setando opções no socket arp **/
		/** SO_BROADCAST mensagem broadcast. **/
		if (setsockopt(arp_socket, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) < 0)
		{
			perror("ERROR ao abrir o socket");
			return (void *)-1;
		}

		memset(&sa, 0x00, sizeof(sa));
		strcpy(sa.sa_data, ifname);

		/** enviar dados(mensagens/pacote) **/
		if (sendto(arp_socket, &pacote, sizeof(pacote), 0, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		{
			perror("ERROR ao enviar o pacote");
			return (void *)-1;
		}

		i++;

		close(arp_socket); /** fim da conexão **/
	}

	pthread_exit(NULL);
}

/** recebendo as respostas **/
void *receiveReplies()
{
	int fd, n, i;
	struct estrutura_pacote_arp pacote;
	/** Aloca espaço para 5 estruturas **/
	hosts = (struct estrutura_host *)realloc(hosts, sizeof(struct estrutura_host) * capacidade);
	struct sockaddr sa;
	unsigned char source_hardware_address[ETHERNET_ADDR_LEN];
	unsigned char source_protocol_address[IP_ADDR_LEN];

	if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE))) < 0)
	{
		perror("ERROR ao abrir o socket");
		return (void *)-1;
	}

	i = 0;
	do
	{
		/* garantindo que não ira existir lixo */
		memset(&sa, 0x00, sizeof(sa));
		memset(&pacote, 0x00, sizeof(pacote));
		n = sizeof(sa);

		/** 
		* Recebendo os endereços no buffer
		* @param &pacote Ponteiro para o buffer que recebe as mensagens.
		* @param sizeof(pacote) tamanho do buffer.
 		* @param &sa Ponteiro refere-se ao endereco de origem da mensagem que sera recebida.
 		**/
		if (recvfrom(fd, &pacote, sizeof(pacote), 0, (struct sockaddr *)&sa, &n) < 0)
		{
			perror("ERROR ao receber o pacote");
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

			/* preenchendo o array com as informações de MAC e IP */
			memcpy(hosts[posicao].hardware_address, source_hardware_address, ETHERNET_ADDR_LEN);
			memcpy(hosts[posicao].protocol_address, source_protocol_address, IP_ADDR_LEN);
			posicao++;
			if (posicao >= capacidade)
			{
				capacidade *= 1;
				hosts = (estrutura_host *)malloc(sizeof(estrutura_host) * capacidade);
			}
		}

	} while (1);

	close(fd);
	pthread_exit(NULL);
}

/* retorna os hosts descobertos */
struct estrutura_host *getHosts()
{
	return hosts;
}

int arp_discover(char *input_ifname)
{
	strcpy(ifname, input_ifname);

	if (pthread_create(&(thread_send), NULL, &sendRequests, NULL) != 0)
		printf("\n Não é possível criar a thread. \n ");
	else
		printf("\n--Eviando o pacote--\n");

	if (pthread_create(&(thread_receive), NULL, &receiveReplies, NULL) != 0)
		printf("\n Não é possível criar a thread. \n ");
	else
		printf("\n--Recebendo os pacotes--\n");

	sleep(10);

	free(hosts);

	return 0;
}
