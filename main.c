#include "arp_lib.h"


int main(int argc, char* argv[])
{
	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	uint8_t MAC_addr[6] = {0,};
	uint8_t senders_MAC[6] = {0,};
	uint8_t broadcast_MAC[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
	struct in_addr my_IP;
	struct in_addr sender_ip;
	struct in_addr target_ip;
	int i;
	char sender_string[100] = {0,};
	char num_string[10] = {0,};
		
	if(argc != 3)
	{
		printf("Usage: ./send_arp [interface] [ip_addr]\n");
		return 0;
	}



	
	handle = pcap_open_live(argv[1],BUFSIZ,1,1000,errbuf);
	get_addr(MAC_addr,&my_IP ,argv[1]);

	printf("%s\n",inet_ntoa(my_IP));
	for(i=0; i<256; i++)
	{
		memset(sender_string,0,100);
		strcpy(sender_string, argv[2]);
		sprintf(num_string,".%d", i);
		strcat(sender_string,num_string);
		printf("send packet: %s\n",sender_string);
		inet_aton(sender_string,&sender_ip);
		rs_ARP(handle,MAC_addr,broadcast_MAC,&my_IP , &sender_ip,1);
		printf("aa\n");
	}// request mode
	get_senders_mac(handle,5);
	
	return 0;
}
