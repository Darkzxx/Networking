#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define BUF_SIZ		65536
#define SEND 0
#define RECV 1
#define IP_SIZE 	4
#define MAC_SIZE 	6
#define WIN_SIZE	10
#define LINE_LEN	80
#define R_PORT		4000
#define S_PORT		2424

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

struct window {
	uint16_t seq_num;
	uint8_t ack;
	char data[LINE_LEN];
};

struct window_send {
	uint16_t seq_num;
	char data[LINE_LEN];
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

	//printf("checksum = %d\n", ~acc);
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
	iph->ip_p = 17;		// ip protocol (17 for UDP, 6 for TCP)
	iph->ip_sum = 0;	// ip checksum initialize with 0

	memcpy(&(iph->ip_src), &ipSrc, sizeof(struct in_addr));	// get src ip
	memcpy(&(iph->ip_dst), &ipDest, sizeof(struct in_addr));	// get dest ip

	return iph;
}

// build udp header
struct udphdr *build_udp_header(uint16_t src_port, uint16_t dest_port){
	struct udphdr *udph = (struct udphdr *)malloc(sizeof(struct udphdr));

	udph->uh_sport = htons(src_port);	// source port
	udph->uh_dport = htons(dest_port);	// dest port
	udph->uh_sum = 0;				// initialize checksum
	// later edit udph->uh_ulen = udp header length

	return udph;
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

// return acknowledge sequence number
void recv_ack(char *if_name, struct window window_slide[]){
	int sockfd, byteRecv = -1, n;
	unsigned int src_addr;
	size_t eh_size = sizeof(struct ether_header);
	char buf[BUF_SIZ];
	struct ifreq if_mac;
	struct sockaddr_ll sk_addr;
	int sk_addr_size = sizeof(struct sockaddr_ll);
	struct ether_header *eh = (struct ether_header *)malloc(sizeof(struct ether_header));
	struct ip *iph = (struct ip *)malloc(sizeof(struct ip));
	uint16_t ack_seq, seq;
	struct timeval tv;

	// Open RAW socket to receive on
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		perror("socket() failed\n");
	
	// setting timeout for recvfrom
	tv.tv_sec = 0;
	tv.tv_usec = 80000;
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
		perror("Can't set recv timeout");

	// Get index of MAC address to receive on
	if_mac = get_mac(if_name, sockfd);
	// get src ip
	src_addr = get_IPv4(if_name, sockfd);
	
	// wait til receive
	while(1){
		byteRecv = -1;
		while(byteRecv < 0){
			printf("waiting for ack...\n");
			byteRecv = recvfrom(sockfd, buf, BUF_SIZ, 0, (struct sockaddr*)&sk_addr,
						&sk_addr_size);

			// break if time out
			if (byteRecv == -1)
				break;
			
			// get IP header and compare if dest ip is this ip
			memcpy(iph, &(buf[eh_size]), sizeof(struct ip));
			if (memcmp(&(iph->ip_dst), (struct in_addr *)&src_addr, sizeof(struct in_addr))){
				byteRecv = -1;
				continue;
			}
			// get ether header 
			memcpy(eh, buf, eh_size);
			// check if ether type is IP type
			//printf("ether_type = 0x%04x\n", ntohs(eh->ether_type));
			if (eh->ether_type != htons(ETH_P_IP))
				byteRecv = -1;
		}

		// break if time out
		if (byteRecv == -1)
			break;

		// get acknowledge sequence
		n = eh_size + sizeof(struct ip) + sizeof(struct udphdr);
		memcpy(&seq, &(buf[n]), sizeof(uint16_t));
		seq = ntohs(seq);
		printf("%d\n", seq);
		
		// fill in array of that index
		window_slide[seq % WIN_SIZE].ack = 1;
	}

	close(sockfd);

}

// send ack
void send_ack(int sock, struct ifreq if_idx, struct ether_header *eh, struct ip *iph, struct udphdr *udph,
				uint16_t seq_num){
	char sendbuf[BUF_SIZ];
	int sendLen = 0;
	ssize_t byteSent;
	struct sockaddr_ll sk_addr;
	int sk_addr_size = sizeof(struct sockaddr_ll);
	

	// udp header length
	udph->uh_ulen = htons(sizeof(struct udphdr) + sizeof(uint16_t));
	// ip header total length
	iph->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + sizeof(uint16_t));
	seq_num = htons(seq_num);

	// combine all headers and data to one frame
	memcpy(sendbuf, eh, sizeof(struct ether_header));
	sendLen = sizeof(struct ether_header);
	memcpy(&(sendbuf[sendLen]), iph, sizeof(struct ip));
	sendLen += sizeof(struct ip);
	memcpy(&(sendbuf[sendLen]), udph, sizeof(struct udphdr));
	sendLen += sizeof(struct udphdr);
	memcpy(&(sendbuf[sendLen]), &seq_num, sizeof(uint16_t));
	sendLen += sizeof(uint16_t);

	// get udp checksum
	udph->uh_sum = checksum(&(sendbuf[sizeof(struct ip)]), sizeof(struct udphdr) + sizeof(uint16_t));
	// add the new udp header with checksum into frame
	memcpy(&(sendbuf[sizeof(struct ether_header) + sizeof(struct ip)]), udph, sizeof(struct udphdr));

	// get ip checksum
	iph->ip_sum = checksum(&(sendbuf[sizeof(struct ether_header)]), sendLen - sizeof(struct ether_header));

	// add the new ip header with checksum into frame
	memcpy(&(sendbuf[sizeof(struct ether_header)]), iph, sizeof(struct ip));

	// send
	memset(&sk_addr, 0, sk_addr_size);
	sk_addr.sll_ifindex = if_idx.ifr_ifindex;
	sk_addr.sll_halen = ETH_ALEN;
	byteSent = sendto(sock, sendbuf, sendLen, 0, (struct sockaddr*)&sk_addr, 
				sizeof(struct sockaddr_ll));
	
	if (byteSent < 0)
		printf("Send failed\n");
}

// send message
void send_msg(int sock, struct ifreq if_idx, struct ether_header *eh, struct ip *iph, struct udphdr *udph,
				struct window_send *w_send){
	char sendbuf[BUF_SIZ];
	int sendLen = 0;
	ssize_t byteSent;
	struct sockaddr_ll sk_addr;
	int sk_addr_size = sizeof(struct sockaddr_ll);

	// udp header length
	udph->uh_ulen = htons(sizeof(struct udphdr) + sizeof(struct window_send));
	// ip header total length
	iph->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct window_send));

	// combine all headers and data to one frame
	memcpy(sendbuf, eh, sizeof(struct ether_header));
	sendLen = sizeof(struct ether_header);
	memcpy(&(sendbuf[sendLen]), iph, sizeof(struct ip));
	sendLen += sizeof(struct ip);
	memcpy(&(sendbuf[sendLen]), udph, sizeof(struct udphdr));
	sendLen += sizeof(struct udphdr);
	memcpy(&(sendbuf[sendLen]), w_send, sizeof(struct window_send));
	sendLen += sizeof(struct window_send);

	// get udp checksum
	udph->uh_sum = checksum(&(sendbuf[sizeof(struct ip)]), sizeof(struct udphdr) + sizeof(struct window_send));
	// add the new udp header with checksum into frame
	memcpy(&(sendbuf[sizeof(struct ether_header) + sizeof(struct ip)]), udph, sizeof(struct udphdr));

	// get ip checksum
	iph->ip_sum = checksum(&(sendbuf[sizeof(struct ether_header)]), sendLen - sizeof(struct ether_header));

	// add the new ip header with checksum into frame
	memcpy(&(sendbuf[sizeof(struct ether_header)]), iph, sizeof(struct ip));

	// send
	memset(&sk_addr, 0, sk_addr_size);
	sk_addr.sll_ifindex = if_idx.ifr_ifindex;
	sk_addr.sll_halen = ETH_ALEN;
	byteSent = sendto(sock, sendbuf, sendLen, 0, (struct sockaddr*)&sk_addr, 
				sizeof(struct sockaddr_ll));
	
	if (byteSent < 0)
		printf("Send failed\n");
}

// open file and send content to destination address
void send_file(char *if_name, char *destIP, char *fname){
	int sockfd, i;
	char data[LINE_LEN];
	unsigned int src_addr, netmask;
	uint16_t datalen, ack_seq, lowestNotAck = 0, lowestNotSent = 0, fail_num;
	uint8_t destMac[MAC_SIZE];
	FILE *fp;
	struct ifreq if_idx, if_mac;
	struct in_addr dest_addr;
	struct ether_header *eh;
	struct ip *iph;
	struct udphdr *udph;
	struct window_send *window_s = (struct window_send*)malloc(sizeof(struct window_send));
	struct window window_slide[WIN_SIZE];

	// check DestIP format is correct
	if (inet_aton(destIP, &dest_addr) == 0){
		perror("ERROR: Invalid Destination IP Address!!!\n");
		exit(1);
	}

	// Open RAW socket to send on
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		perror("socket() failed\n");
	

	// open file for read
	fp = fopen(fname, "r");
	if (fp == NULL){
		fprintf(stderr, "Fail to open file: %s\n", fname);
		exit(1);
	}
	
	// get netmask
	netmask = get_netmask(if_name, sockfd);
	// get src ip
	src_addr = get_IPv4(if_name, sockfd);
	// broadcast for destination MAC address
	memset(destMac, 0xff, MAC_SIZE);

	// ARP to dest host
	send_arp_request(sockfd, if_name, src_addr, dest_addr, destMac);
	// get return dest Mac
	recv_arp_reply(sockfd, if_name, destMac);

	// get socket interface for send
	if_idx = get_interface(if_name, sockfd);
	// get source mac address
	if_mac = get_mac(if_name, sockfd);	

	// build ether header
	eh = build_ether_header(if_mac, destMac, ETH_P_IP);
	// build ip header
	iph = build_ip_header(*(struct in_addr *)&src_addr, dest_addr);
	// build udp header
	udph = build_udp_header(S_PORT, R_PORT);

	// init window slide
	for (i = 0; i < WIN_SIZE; i++)
		window_slide[i].ack = 0;

	memset(data, 0, LINE_LEN);
	memset(window_s->data, 0, LINE_LEN);

	// start window sliding
	while (fgets(data, 80, fp) != NULL){
		// if 10 slides sent, wait til there is space
		if (lowestNotSent - lowestNotAck >= WIN_SIZE){
			// keep sending current window until lowestNotAck is acknowledged
			while(1){
				// fill ack in window_slide
				recv_ack(if_name, window_slide);
				// if lowestNotAck is still not ack, we send current window again
				if (window_slide[lowestNotAck % WIN_SIZE].ack == 0){
					for (i = lowestNotAck; i < lowestNotSent; i++){
						// only those that aren't acknowledged
						if (window_slide[i % WIN_SIZE].ack == 0){
							// change to send format
							window_s->seq_num = htons(window_slide[i % WIN_SIZE].seq_num);
							memset(window_s->data, 0, LINE_LEN);
							strcpy(window_s->data, window_slide[i % WIN_SIZE].data);
					
							// send
							send_msg(sockfd, if_idx, eh, iph, udph, window_s);
						}
					}
				}
				// else break to adjust new window
				else
					break;
			}

			// sliding through all acknowledged frames
			while(window_slide[lowestNotAck % WIN_SIZE].ack == 1){
				window_slide[lowestNotAck % WIN_SIZE].ack = 0;
				lowestNotAck++;
			}
		}

		// now space available
		// save into window frame
		window_slide[lowestNotSent % WIN_SIZE].seq_num = lowestNotSent;
		window_slide[lowestNotSent % WIN_SIZE].ack = 0;
		strcpy(window_slide[lowestNotSent % WIN_SIZE].data, data);

		// change to send format
		window_s->seq_num = htons(lowestNotSent);
		memset(window_s->data, 0, LINE_LEN);
		strcpy(window_s->data, data);
			
		// send
		send_msg(sockfd, if_idx, eh, iph, udph, window_s);

		lowestNotSent++;
		memset(data, 0, LINE_LEN);
	}

	// if file empty
	if (lowestNotSent == 0){
		fprintf(stderr, "Empty file: %s\n", fname);
		exit(1);
	}

	// clear the rest
	while (lowestNotAck < lowestNotSent){
		// keep sending current window until lowestNotAck is acknowledged
		while(1){
			// fill ack in window_slide
			recv_ack(if_name, window_slide);
			// if lowestNotAck is still not ack, we send current window again
			if (window_slide[lowestNotAck % WIN_SIZE].ack == 0){
				for (i = lowestNotAck; i < lowestNotSent; i++){
					// only those that aren't acknowledged
					if (window_slide[i % WIN_SIZE].ack == 0){
						// change to send format
						window_s->seq_num = htons(window_slide[i % WIN_SIZE].seq_num);
						memset(window_s->data, 0, LINE_LEN);
						strcpy(window_s->data, window_slide[i % WIN_SIZE].data);
				
						// send
						send_msg(sockfd, if_idx, eh, iph, udph, window_s);
					}
				}
			}
			// else break to adjust new window
			else
				break;
		}

		// sliding through all acknowledged frames
		while(window_slide[lowestNotAck % WIN_SIZE].ack == 1){
			window_slide[lowestNotAck % WIN_SIZE].ack = 0;
			lowestNotAck++;
		}
	}

	// send termination symbols
	window_s->seq_num = htons(lowestNotSent);
	memset(window_s->data, 0, LINE_LEN);
	strcpy(window_s->data, "0xFFFF");
	send_msg(sockfd, if_idx, eh, iph, udph, window_s);

	do {
		recv_ack(if_name, window_slide);
		if (window_slide[lowestNotAck % WIN_SIZE].ack == 0)
			send_msg(sockfd, if_idx, eh, iph, udph, window_s);
		else
			break;
	} while (1);

	fclose(fp);
	close(sockfd);
}

// receive file and send acknowledgement
void recv_file(char *if_name, char *fname){
	int sockfd, byteRecv = -1, n, wait = 1, finish = 0;
	unsigned int src_addr;
	uint16_t lowestNotRecv = 0;
	size_t eh_size = sizeof(struct ether_header), ip_size = sizeof(struct ip);
	size_t udp_size = sizeof(struct udphdr);
	char buf[BUF_SIZ], data[BUF_SIZ];
	struct ifreq if_idx, if_mac;
	struct sockaddr_ll sk_addr;
	int sk_addr_size = sizeof(struct sockaddr_ll);
	struct ether_header *eh = (struct ether_header *)malloc(sizeof(struct ether_header));
	struct ether_header *eh_send = NULL;
	struct ip *iph = (struct ip *)malloc(sizeof(struct ip));
	struct ip *iph_send = NULL;
	struct udphdr *udph = (struct udphdr *)malloc(sizeof(struct udphdr));
	struct udphdr *udph_send = NULL;
	FILE *fp;
	struct window_send window_s[WIN_SIZE];
	struct window_send *window_r = (struct window_send*)malloc(sizeof(struct window_send)); 
	struct timeval tv;

	// Open RAW socket to receive on
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		perror("socket() failed\n");

	// open file for read
	fp = fopen(fname, "w");
	if (fp == NULL){
		fprintf(stderr, "Fail to open file: %s\n", fname);
		exit(1);
	}

	// get socket interface for send
	if_idx = get_interface(if_name, sockfd);
	// Get index of MAC address to receive on
	if_mac = get_mac(if_name, sockfd);
	// get src ip
	src_addr = get_IPv4(if_name, sockfd);

	while (1) {
		byteRecv = -1;
		// wait til receive
		while(byteRecv < 0){
			printf("listening...\n");
			byteRecv = recvfrom(sockfd, buf, BUF_SIZ, 0, (struct sockaddr*)&sk_addr,
									&sk_addr_size);
			// using socket without timeout until first message arrive
			if (wait == 0){		
				// change back to socket without timeout when timeout
				if (byteRecv == -1){
					// break if finish
					if (finish == 1)
						break;
					wait = 1;
					// setting timeout for recvfrom
					tv.tv_sec = 0;
					tv.tv_usec = 0;
					if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
						perror("Can't set file recv timeout");

					// check and update lowestNotRecv
					while(window_s[lowestNotRecv % WIN_SIZE].seq_num == lowestNotRecv){
						// write to file
						fprintf(fp, "%s", window_s[lowestNotRecv % WIN_SIZE].data);
						// send acknowledgement
						send_ack(sockfd, if_idx, eh_send, iph_send, udph_send, lowestNotRecv);
						lowestNotRecv++;
					}
				}
			}
				
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

		if (wait == 1){
			// change to scoket with timeout
			wait = 0;
			// setting timeout for recvfrom
			tv.tv_sec = 0;
			tv.tv_usec = 8000;
			if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
				perror("Can't set file recv timeout");
		}

		// break if time out and finish
		if (finish == 1 && byteRecv < 0)
			break;

		// get ip header
		n = eh_size;
		memcpy(iph, &(buf[n]), ip_size);
		// get udp header
		n += ip_size;
		memcpy(udph, &(buf[n]), udp_size);
		// get data
		n += udp_size;
		memcpy(window_r, &(buf[n]), sizeof(struct window_send));
		window_r->seq_num = ntohs(window_r->seq_num);
		
		// new headers if not already exist
		if(eh_send == NULL)
			eh_send = build_ether_header(if_mac, eh->ether_shost, ETH_P_IP);
		if(iph_send == NULL)
			iph_send = build_ip_header(iph->ip_dst, iph->ip_src);
		if(udph_send == NULL)
			udph_send = build_udp_header(R_PORT, S_PORT);

		// break if termination recv
		if (strcmp(window_r->data, "0xFFFF") == 0){
			finish = 1;
			send_ack(sockfd, if_idx, eh_send, iph_send, udph_send, window_r->seq_num);
		}

		// if received seq less than lowestNotRecv then send ack
		if (window_r->seq_num < lowestNotRecv){
			send_ack(sockfd, if_idx, eh_send, iph_send, udph_send, window_r->seq_num);
			continue;
		}

		// copy to window_slide
		memcpy(&(window_s[window_r->seq_num % WIN_SIZE]), window_r, sizeof(struct window_send));
		
	}

	fclose(fp);
	close(sockfd);
}


int main(int argc, char *argv[])
{
	int correct = 0;

	if (argc > 1){
		if (!strcmp(argv[1], "Send")){
			if (argc == 5){
				send_file(argv[2], argv[3], argv[4]);
				correct = 1;
			}
		}
		else if (!strcmp(argv[1], "Recv")){
			if (argc == 4){
				recv_file(argv[2], argv[3]);
				correct = 1;
			}
		}
	}

	if (!correct){
		fprintf(stderr, "./a.out Send <InterfaceName> <DestIP> <Filename>\n");
		fprintf(stderr, "./a.out Recv <InterfaceName> <Filename>\n");
		exit(1);
	}
	

	return 0;
}

