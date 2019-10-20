#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>

#define BUF_SIZ		65536
#define SEND 0
#define RECV 1

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

void buildARP(struct arp_header *ah)
{
	ah->ar_hrd = htons(0x01);	// hardware type = 1 (ethernet)
	ah->ar_pro = htons(0x0800); // Protocol type = IPv4
	ah->ar_hln = 6;				// hardware size = 6
	ah->ar_pln = 4;				// protocol size = 4

}

// example >> print_ifreq(&if_idx)
void print_ifreq(struct ifreq *ifq){
	struct sockaddr_in *addr_in = (struct sockaddr_in *)(&(ifq->ifr_addr));
	
	//struct sockaddr_in6
	char *s = inet_ntoa(addr_in->sin_addr);
	if(strlen(s) > 0)
		printf("addr = %s\n", s);
}

int arp_request(char *if_name, char *ip_addr){
	int sockfd, sendLen, byteSent;
	char sendbuf[BUF_SIZ];
	struct ifreq if_idx, if_mac, if_ip;
	struct ether_header *eh = (struct ether_header *)malloc(sizeof(struct ether_header));
	struct arp_header *ah = (struct arp_header *)malloc(sizeof(struct arp_header));
	struct in_addr addr;
	struct sockaddr_ll sk_addr;
	int sk_addr_size = sizeof(struct sockaddr_ll);

	// check that input ip is incorrect format
	if (inet_aton(ip_addr, &addr) == 0){
		perror("Invalid Address!!!\n");
		exit(1);
	}

	// Open RAW socket to send on
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		perror("socket() failed\n");

	// Get index of the interface to send on
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, if_name, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX\n");

	// Get index of MAC address to send on
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, if_name, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
		perror("SIOCGIFHWADDR\n");
	
	// Get index of IP address to send on
	memset(&if_ip, 0, sizeof(struct ifreq));
	strncpy(if_ip.ifr_name, if_name, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFADDR, &if_ip) < 0)
		perror("SIOCGIFADDR\n");
	
	// src host
	eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	
	// dest host
	memset(eh->ether_dhost, 0xff, 6);	// set dest MAC to ff:ff:ff:ff:ff:ff (broadcast)

	// type
	eh->ether_type = htons(ETH_P_ARP);	// ARP type
	
	// building ARP 
	buildARP(ah);

	ah->ar_op = htons(0x01);	// Opcode = 1 for request
	memcpy(ah->ar_sha, eh->ether_shost, 6);	// Sender MAC Address
	
	print_ifreq(&if_ip);
	memcpy(ah->ar_sip, &(((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr.s_addr), 4);	// Sender IP
	memset(ah->ar_tha, 0x00, 6); 	// Dest MAC addr
	inet_aton(ip_addr, &addr); 		// convert to binary format
	memcpy(ah->ar_tip, &addr, 4);	// Dest IP	

	// put everythin in frame(sendbuf)
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
	
	return sockfd;
}

int arp_receive(char *if_name, int sockfd){
	int byteRecv = -1, n;
	size_t eh_size = sizeof(struct ether_header);
	char buf[BUF_SIZ];
	struct ifreq if_mac, if_ip;
	struct sockaddr_ll sk_addr;
	int sk_addr_size = sizeof(struct sockaddr_ll);
	struct ether_header *eh = (struct ether_header *)malloc(sizeof(struct ether_header));
	struct arp_header *ah = (struct arp_header *)malloc(sizeof(struct arp_header));

	// Get index of MAC address to receive on
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, if_name, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
		perror("SIOCGIFHWADDR\n");

	// Get index of IP address to receive on
	memset(&if_ip, 0, sizeof(struct ifreq));
	strncpy(if_ip.ifr_name, if_name, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFADDR, &if_ip) < 0)
		perror("SIOCGIFADDR\n");
	
	// wait til receive
	while(byteRecv < 0){
		printf("listening...\n");
		byteRecv = recvfrom(sockfd, buf, BUF_SIZ, 0, (struct sockaddr*)&sk_addr,
					&sk_addr_size);
		// get ether header to check if the destination mac is this mac
		memcpy(eh, buf, eh_size);
		for(n=0; n<6; n++){
			if (eh->ether_dhost[n] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[n])
				byteRecv = -1;
		}
	}
	// if received, get ARP header
	memcpy(ah, &(buf[eh_size]), sizeof(struct arp_header));

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

	close(sockfd);

}


int main(int argc, char *argv[])
{
	int sockfd, mode;
	char hw_addr[6];
	char interfaceName[IFNAMSIZ];
	char buf[BUF_SIZ];
	memset(buf, 0, BUF_SIZ);
	
	int correct = 0;
	if (argc != 3){
		printf("Error: wrong input format => ./a,out <interfaceName> <DestIP>\n");
		printf("Eg. ./a.out h1x1-eth0 10.0.0.2\n");
		exit(1);
	}

	sockfd = arp_request(argv[1], argv[2]);
	arp_receive(argv[1], sockfd);

	return 0;
}

