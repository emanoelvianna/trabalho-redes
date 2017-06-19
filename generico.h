/* declaracao das constantes */
#define ETHERNET_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define ARP_PADDING_SIZE 18
#define ETHERTYPE 0x0806 /** indicando que é do tipo arp **/
#define ARPHRD_ETHER 1
#define ETH_P_IP 0x0800
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2

#define BUFFER_SIZE 1600 /** tamanho do buffer de leitura do pacote arp **/

/* declaracao das estruturas */
struct estrutura_pacote_arp
{
    /* Cabeçalho Ethernet */
    unsigned char target_ethernet_address[ETHERNET_ADDR_LEN]; // endereco_fisico_destino
    unsigned char source_ethernet_address[ETHERNET_ADDR_LEN]; // endereco_fisico_origem
    unsigned short ethernet_type;                             // tipo_protocolo_ethernet
    /* Pacote ARP */
    unsigned short hardware_type; // tipo_hardware
    unsigned short protocol_type; // tipo_protocolo

    unsigned char hardware_address_length; // comprimento_endereco_mac
    unsigned char protocol_address_length; // comprimento_endereco_logico

    unsigned short arp_options; // tipo_da_operacao

    unsigned char source_hardware_address[ETHERNET_ADDR_LEN]; // endereco_fisico_origem
    unsigned char source_protocol_address[IP_ADDR_LEN];       // endereco_logico_origem

    unsigned char target_hardware_address[ETHERNET_ADDR_LEN]; // endereco_fisico_destino
    unsigned char target_protocol_address[IP_ADDR_LEN];       // endereco_logico_destino

    unsigned char padding[ARP_PADDING_SIZE]; // dados_de_preenchimento
};