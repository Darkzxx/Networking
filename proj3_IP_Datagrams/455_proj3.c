#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>

#define BUF_SIZ		65536
#define SEND 0
#define RECV 1
#define IP_SIZE 	4
#define MAC_SIZE 	6

struct arp_header {
	uint16_t ar_hrd;
	uint16_t ar_pro;
	unsigned char ar_hln;
	unsigned char ar_pln;
	uint16_t ar_op;
	unsigned char ar_sha[6];
	unsigned char ar_sip[4];
	unsigned char ar_tha[6];
	unsigned char ar_tip[4];
};

// function to get index of source interface
struct ifreq get_interface(char *if_name, int sockfd){
	struct ifreq if_idx;

	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, if_name, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0){
		perror("SIOCGIFINDEX\n");
		exit(1);
	}
	
	return if_idx;
}

// function to get MAC address
struct ifreq get_mac(char *if_name, int sockfd){
	struct ifreq if_mac;

	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, if_name, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0){
		perror("SIOCGIFHWADDR\n");
		exit(1);
	}

	return if_mac;
}

// function to get netmask
unsigned int get_netmask(char *if_name, int sockfd){
	struct ifreq if_netmask;
	
	memset(&if_netmask, 0, sizeof(struct ifreq));
	strncpy(if_netmask.ifr_name, if_name, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFNETMASK, &if_netmask) < 0){
		perror("SIOCGIFNETMASK\n");
		exit(1);
	}

	return ((struct sockaddr_in *)&if_netmask.ifr_netmask)->sin_addr.s_addr;
}

// function to get IP
unsigned int get_IPv4(char *if_name, int sockfd){
	struct ifreq if_ip;

	memset(&if_ip, 0, sizeof(struct ifreq));
	strncpy(if_ip.ifr_name, if_name, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFADDR, &if_ip) < 0){
		perror("SIOCGIFADDR\n");
		exit(1);
	}
	
	return ((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr.s_addr;
}

// check if src and dest IP is on the same network by using netmask
// return 0 for false, 1 for true
int sameNetwork(unsigned int srcIP, unsigned int destIP, unsigned int netmask){
	unsigned int count = 0;
	// shift left until encounter '1' bit
	while(netmask % 2 == 0){
		count++;
		netmask = netmask >> 1;
	}

	// shift left equal to netmask and check if src and dest ip have the same network
	if ((srcIP >> count) == (destIP >> count))
		return 1;
	
	return 0;	
}

// function use to print arp dataframe
void printARP(int byteRecv, struct ether_header *eh, struct arp_header *ah){
	int n;

	// display received
	printf("receive %d bytes\n\n", byteRecv);

	printf("------- ETHER HEADER --------\n");
	printf("Destination MAC = ");
	for(n=0; n<5; n++)
		printf("%hhx:", eh->ether_dhost[n]);
	printf("%hhx\n", eh->ether_dhost[n]);
	printf("Source MAC = ");
	for(n=0; n<5; n++)
		printf("%hhx:", eh->ether_shost[n]);
	printf("%hhx\n", eh->ether_shost[n]);
	printf("Type = 0x%04x\n\n", ntohs(eh->ether_type));

	printf("--------- ARP HEADER --------\n");
	printf("Hardware type = 0x%04x\n", ntohs(ah->ar_hrd));
	printf("Protocol type = 0x%04x\n", ntohs(ah->ar_pro));
	printf("Hardware size = %u\n", ah->ar_hln);
	printf("Protocol size = %u\n", ah->ar_pln);
	printf("Opcode = %d\n", ntohs(ah->ar_op));
	printf("Sender MAC address = ");
	for(n=0; n<5; n++)
		printf("%hhx:", ah->ar_sha[n]);
	printf("%hhx\n", ah->ar_sha[n]);
	printf("Sender IP address = ");
	for(n=0; n<3; n++)
		printf("%hhd:", ah->ar_sip[n]);
	printf("%hhd\n", ah->ar_sip[n]);
	printf("Target MAC address = ");
	for(n=0; n<5; n++)
		printf("%hhx:", ah->ar_tha[n]);
	printf("%hhx\n", ah->ar_tha[n]);
	printf("Target IP address = ");
	for(n=0; n<3; n++)
		printf("%hhd:", ah->ar_tip[n]);
	printf("%hhd\n", ah->ar_tip[n]);
}

// function use to print ip packet
void printIPpacket(int byteRecv, struct ether_header *eh, struct ip *iph, char *data){
	int n;

	// display received
	printf("receive %d bytes\n\n", byteRecv);

	printf("------- ETHER HEADER --------\n");
	printf("Destination MAC = ");
	for(n=0; n<5; n++)
		printf("%hhx:", eh->ether_dhost[n]);
	printf("%hhx\n", eh->ether_dhost[n]);
	printf("Source MAC = ");
	for(n=0; n<5; n++)
		printf("%hhx:", eh->ether_shost[n]);
	printf("%hhx\n", eh->ether_shost[n]);
	printf("Type = 0x%04x\n\n", ntohs(eh->ether_type));

	printf("------ IP HEADER ------\n");
	printf("IP version: %d\n", iph->ip_v);
}

// checksum
int16_t checksum(void * vdata, size_t length){
	char *data = (char *)vdata;
	uint16_t word;
	uint32_t acc = 0xffff;

	for (size_t i=0; i+1 < length; i+=2){
		memcpy(&word, data+i, 2);
		acc += ntohs(word);
		if (acc > 0xffff)
			acc -= 0xffff;
	}

	if (length & 1){
		word = 0;
		memcpy(&word, data+length-1, 1);
		acc += ntohs(word);
		if (acc > 0xffff)
			acc -= 0xffff;
	}

	printf("checksum = %d\n", ~acc);
	return htons(~acc);
}

// build ether header of the dataframe
struct ether_header *build_ether_header(struct ifreq if_mac, uint8_t destMAC[MAC_SIZE], uint16_t type){
	struct ether_header *eh = (struct ether_header *)malloc(sizeof(struct ether_header));

	// set source mac address
	memcpy(eh->ether_shost, if_mac.ifr_hwaddr.sa_data, MAC_SIZE);
	// set destination mac address to destination mac address
	memcpy(eh->ether_dhost, destMAC, MAC_SIZE);
	// set type
	eh->ether_type = htons(type);

	return eh;
}

// build arp header
struct arp_header *build_ARP_header(struct ifreq if_mac, unsigned int src_addr, struct in_addr dest_addr)
{
	struct arp_header *ah = (struct arp_header *)malloc(sizeof(struct arp_header));

	ah->ar_hrd = htons(0x01);	// hardware type = 1 (ethernet)
	ah->ar_pro = htons(0x0800); // Protocol type = IPv4
	ah->ar_hln = MAC_SIZE;		// hardware size = 6
	ah->ar_pln = IP_SIZE;		// protocol size = 4
	ah->ar_op = htons(0x01);	// Opcode = 1 for request

	memcpy(ah->ar_sha, if_mac.ifr_hwaddr.sa_data, MAC_SIZE);	// Sender MAC Address
	memcpy(ah->ar_sip, &src_addr, IP_SIZE);		// Sender IP
	memset(ah->ar_tha, 0x00, MAC_SIZE); 		// Dest MAC addr
	memcpy(ah->ar_tip, &dest_addr, IP_SIZE);	// Dest IP

	return ah;
}

// build ip header 
struct ip *build_ip_header(struct in_addr ipSrc, struct in_addr ipDest){
	struct ip *iph = (struct ip *)malloc(sizeof(struct ip));

	iph->ip_v = 4;		// ip version
	iph->ip_hl = 5;		// ip header (min is 5 rows)

	iph->ip_tos = 0;	// ip type of service
	iph->ip_len = htons(0);			// ip total length, initialize with 0
	iph->ip_id = htons(40012);		// id of this packet
	iph->ip_off = htons(0x4000);	// dont fragment flag
	iph->ip_ttl = 64;	// ip  time to live
	iph->ip_p = 253;		// ip protocol for ICMP (17 for UDP, 6 for TCP)
	iph->ip_sum = 0;	// ip checksum initialize with 0

	memcpy(&(iph->ip_src), &ipSrc, sizeof(struct in_addr));	// get src ip
	memcpy(&(iph->ip_dst), &ipDest, sizeof(struct in_addr));	// get dest ip

	return iph;
}

void send_arp_request(int sockfd, char *if_name, unsigned int src_addr, struct in_addr dest_addr, uint8_t destMac[]){
	int sendLen, byteSent;
	char sendbuf[BUF_SIZ];
	struct ifreq if_idx, if_mac;
	struct ether_header *eh;
	struct arp_header *ah;
	struct in_addr addr;
	struct sockaddr_ll sk_addr;
	int sk_addr_size = sizeof(struct sockaddr_ll);
	// uint8_t broadcast[MAC_SIZE];

	// get socket interface for send
	if_idx = get_interface(if_name, sockfd);
	// get source mac address
	if_mac = get_mac(if_name, sockfd);	
	
	// broadcast for destination MAC address
	// memset(broadcast, 0xff, MAC_SIZE);
	// build ether header
	eh = build_ether_header(if_mac, destMac, ETH_P_ARP);
	
	// building ARP header
	ah = build_ARP_header(if_mac, src_addr, dest_addr);

	// put everything in frame(sendbuf)
	memcpy(sendbuf, eh, sizeof(struct ether_header));
	sendLen = sizeof(struct ether_header);
	memcpy(&(sendbuf[sendLen]), ah, sizeof(struct arp_header));
	sendLen += sizeof(struct arp_header);

	// send
	memset(&sk_addr, 0, sk_addr_size);
	sk_addr.sll_ifindex = if_idx.ifr_ifindex;
	sk_addr.sll_halen = ETH_ALEN;
	byteSent = sendto(sockfd, sendbuf, sendLen, 0, (struct sockaddr*)&sk_addr, 
				sizeof(struct sockaddr_ll));
	
	if (byteSent < 0)
		printf("Send failed\n");	
	
}

void recv_arp_reply(int sockfd, char *if_name, uint8_t getdestMac[]){
	int byteRecv = -1;
	size_t eh_size = sizeof(struct ether_header);
	char buf[BUF_SIZ];
	struct ifreq if_mac;
	struct sockaddr_ll sk_addr;
	int sk_addr_size = sizeof(struct sockaddr_ll);
	struct ether_header *eh = (struct ether_header *)malloc(sizeof(struct ether_header));
	struct arp_header *ah = (struct arp_header *)malloc(sizeof(struct arp_header));

	// Get index of MAC address to receive on
	if_mac = get_mac(if_name, sockfd);
	
	// wait til receive
	while(byteRecv < 0){
		printf("waiting for arp reply...\n");
		byteRecv = recvfrom(sockfd, buf, BUF_SIZ, 0, (struct sockaddr*)&sk_addr,
					&sk_addr_size);
		// get ether header to check if the destination mac is this mac
		memcpy(eh, buf, eh_size);
		if (memcmp(eh->ether_dhost, if_mac.ifr_hwaddr.sa_data, MAC_SIZE)){
			byteRecv = -1;
			continue;
		}
		// check if ether type is ARP type
		if (eh->ether_type != htons(ETH_P_ARP)){
			byteRecv = -1;
			continue;
		}
		// get ARP header to check if opcode is reply
		memcpy(ah, &(buf[eh_size]), sizeof(struct arp_header));
		if (ah->ar_op != htons(0x02))
			byteRecv = -1;
	}
	
	// return sender mac address
	memcpy(getdestMac, eh->ether_shost, MAC_SIZE);
}

// send ip_data frame after ARP for destination mac address
void send_message(char *if_name, char *destIP, char* routerIP, char* data){
	int sockfd, sockip, bit_num, sendLen, byteSent;
	int buffer_icmp_begin, icmp_cksum_size;
	char sendbuf[BUF_SIZ];
	unsigned int src_addr, netmask;
	uint16_t datalen = strlen(data);
	uint8_t destMac[MAC_SIZE];
	struct ifreq if_idx, if_mac;
	struct in_addr dest_addr, rout_addr;
	struct ether_header *eh;
	struct ip *iph;
	struct sockaddr_ll sk_addr;
	int sk_addr_size = sizeof(struct sockaddr_ll);

	// check DestIP format is correct
	if (inet_aton(destIP, &dest_addr) == 0){
		perror("ERROR: Invalid Destination IP Address!!!\n");
		exit(1);
	}
	// check RouterIP format is correct
	if (inet_aton(routerIP, &rout_addr) == 0){
		perror("ERROR: Invalid Destination IP Address!!!\n");
		exit(1);
	}

	// Open RAW socket to send on
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		perror("socket() failed\n");
	
	// Open RAW socket to send on
	if ((sockip = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		perror("socket() failed\n");
	
	// get netmask
	netmask = get_netmask(if_name, sockfd);
	// get src ip
	src_addr = get_IPv4(if_name, sockfd);
	// broadcast for destination MAC address
	memset(destMac, 0xff, MAC_SIZE);

	// check if src and dest are on the same network
	if (sameNetwork(ntohl(src_addr), ntohl((unsigned int)dest_addr.s_addr), ntohl(netmask))){
		// same network, ARP directly to dest host 
		send_arp_request(sockfd, if_name, src_addr, dest_addr, destMac);
	}
	else{
		// different networks, ARP to router
		send_arp_request(sockfd, if_name, src_addr, rout_addr, destMac);
	}
	
	// wait for arp reply
	recv_arp_reply(sockfd, if_name, destMac);

	//sockfd = sockip;

	// get socket interface for send
	if_idx = get_interface(if_name, sockfd);
	// get source mac address
	if_mac = get_mac(if_name, sockfd);	

	// build ether header
	eh = build_ether_header(if_mac, destMac, ETH_P_IP);
	// build ip header
	iph = build_ip_header(*(struct in_addr *)&src_addr, dest_addr);

	// ip header total length
	iph->ip_len = htons(sizeof(struct ip) +  datalen);

	// combine all headers and data to one frame
	//memcpy(sendbuf, eh, sizeof(struct ether_header));
	//sendLen = sizeof(struct ether_header);
	memcpy(&(sendbuf[sendLen]), iph, sizeof(struct ip));
	sendLen = sizeof(struct ip);
	memcpy(&(sendbuf[sendLen]), data, datalen);
	sendLen += datalen;

	// get checksum
	iph->ip_sum = checksum(sendbuf, sendLen);

	// add the new ip header with checksum into frame
	//memcpy(&(sendbuf[sizeof(struct ether_header)]), iph, sizeof(struct ip));
	memcpy(sendbuf, iph, sizeof(struct ip));

	// send
	memset(&sk_addr, 0, sk_addr_size);
	sk_addr.sll_ifindex = if_idx.ifr_ifindex;
	sk_addr.sll_halen = ETH_ALEN;
	byteSent = sendto(sockip, sendbuf, sendLen, 0, (struct sockaddr*)&sk_addr, 
				sizeof(struct sockaddr_ll));
	
	if (byteSent < 0)
		printf("Send failed\n");

	
	close(sockfd);
}

// receive ip dataframe
void recv_message(char *if_name){
	int sockfd, byteRecv = -1, n;
	unsigned int src_addr;
	size_t eh_size = sizeof(struct ether_header);
	char buf[BUF_SIZ], data[BUF_SIZ];
	struct ifreq if_mac;
	struct sockaddr_ll sk_addr;
	int sk_addr_size = sizeof(struct sockaddr_ll);
	struct ether_header *eh = (struct ether_header *)malloc(sizeof(struct ether_header));
	struct ip *iph = (struct ip *)malloc(sizeof(struct ip));

	// Open RAW socket to send on
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		perror("socket() failed\n");

	// Get index of MAC address to receive on
	if_mac = get_mac(if_name, sockfd);
	// get src ip
	src_addr = get_IPv4(if_name, sockfd);
	
	// wait til receive
	while(byteRecv < 0){
		printf("listening...\n");
		byteRecv = recvfrom(sockfd, buf, BUF_SIZ, 0, (struct sockaddr*)&sk_addr,
					&sk_addr_size);
		
		// get IP header and compare if dest ip is this ip
		memcpy(iph, &(buf[eh_size]), sizeof(struct ip));
		if (memcmp(&(iph->ip_dst), (struct in_addr *)&src_addr, sizeof(struct in_addr))){
			byteRecv = -1;
			continue;
		}
		// get ether header 
		memcpy(eh, buf, eh_size);
		// check if ether type is IP type
		printf("ether_type = 0x%04x\n", ntohs(eh->ether_type));
		if (eh->ether_type != htons(ETH_P_IP))
			byteRecv = -1;
	}
	
	// get data
	n = eh_size + sizeof(struct ip);
	strcpy(data, &(buf[n]));

	printf("data = %s\n", data);
	


	close(sockfd);
}


int main(int argc, char *argv[])
{
	int correct = 0;

	if (argc > 1){
		if (!strcmp(argv[1], "Send")){
			if (argc == 6){
				send_message(argv[2], argv[3], argv[4], argv[5]);
				correct = 1;
			}
		}
		else if (!strcmp(argv[1], "Recv")){
			if (argc == 3){
				recv_message(argv[2]);
				correct = 1;
			}
		}
	}

	if (!correct){
		fprintf(stderr, "./a.out Send <InterfaceName> <DestIP> <RouterIP> <Message>\n");
		fprintf(stderr, "./a.out Recv <InterfaceName>\n");
		exit(1);
	}
	

	return 0;
}

