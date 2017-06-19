/* declaracao das estruturas */
typedef struct estrutura_host
{
    unsigned char hardware_address[ETHERNET_ADDR_LEN]; // endereco_fisico_origem
    unsigned char protocol_address[IP_ADDR_LEN];       // endereco_logico_origem
} estrutura_host;

/* declaracao dos métodos */
void *sendRequests();
void *receiveReplies();
struct estrutura_host *getHosts();
int arp_discover(char *input_ifname);
