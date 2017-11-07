#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <stdint.h>
#include <net/ethernet.h>



#define HW_ADDR_LEN 16

#ifndef __get_mac_addr_h__
#define __get_mac_addr_h__

void get_addr(unsigned char MAC_addr[6],struct in_addr *IP_addr ,char* interface);

#endif

#ifndef __request_ARP_h__
#define __request_ARP_h__

void rs_ARP(pcap_t* handle, unsigned char MAC_addr[6], struct in_addr* IP1, struct in_addr* IP2,int mode);
#endif
