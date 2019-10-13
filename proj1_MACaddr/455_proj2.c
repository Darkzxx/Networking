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

void send_message(char *if_name, char hw_addr[], char *buf){
	int sockfd, sendLen, byteSent;
	struct ifreq if_idx, if_mac;
	char sendbuf[BUF_SIZ], *data;
	struct ether_header *eh = (struct ether_header *) sendbuf;
	struct sockaddr_ll sk_addr;
	int sk_addr_size = sizeof(struct sockaddr_ll);

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
	
	// Ethernet header
	memset(sendbuf, 0, BUF_SIZ);
	// send host
	eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	// destination host
	eh->ether_dhost[0] = hw_addr[0];
	eh->ether_dhost[1] = hw_addr[1];
	eh->ether_dhost[2] = hw_addr[2];
	eh->ether_dhost[3] = hw_addr[3];
	eh->ether_dhost[4] = hw_addr[4];
	eh->ether_dhost[5] = hw_addr[5];

	printf("buf = %s\n", buf);

	// Ether-type
	eh->ether_type = htons(ETH_P_IP);
	// send length
	sendLen = sizeof(struct ether_header);
	strcpy(&(sendbuf[sendLen]), buf);
	printf("sendbuf[sendlen] = %s\n", &(sendbuf[sendLen]));
	sendLen += strlen(buf);

	// send
	memset(&sk_addr, 0, sk_addr_size);
	sk_addr.sll_ifindex = if_idx.ifr_ifindex;
	sk_addr.sll_halen = ETH_ALEN;
	byteSent = sendto(sockfd, sendbuf, sendLen, 0, (struct sockaddr*)&sk_addr, 
				sizeof(struct sockaddr_ll));
	
	if (byteSent < 0)
		printf("Send failed\n");

}

void recv_message(char *if_name){
	int sockfd, byteRecv = -1, n;
	char buf[BUF_SIZ];
	struct ifreq if_mac;
	struct ether_header *eh = (struct ether_header *) buf;
	struct sockaddr_ll sk_addr;
	int sk_addr_size = sizeof(struct sockaddr_ll);

	// Open RAW socket to listen for ether type
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
		perror("listener socket failed\n");
		return;
	}

	// Get index of MAC address to receive on
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, if_name, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
		perror("SIOCGIFHWADDR\n");

	// wait til receive
	while(byteRecv < 0){
		printf("listening...\n");
		byteRecv = recvfrom(sockfd, buf, BUF_SIZ, 0, (struct sockaddr*)&sk_addr,
					&sk_addr_size);
		for(n=0; n<6; n++){
			if (eh->ether_dhost[n] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[n])
				byteRecv = -1;
		}

	}
	// display received
	printf("receive %d bytes\n", byteRecv);

	printf("mac_addr = ");
	for(n=0; n<5; n++)
		printf("%hhx:", eh->ether_shost[n]);
	printf("%hhx\n", eh->ether_shost[n]);

	printf("type = 0x%04x\n", ntohs(eh->ether_type));

	n = sizeof(struct ether_header);
	printf("data = %s\n", &(buf[n]));
	
	close(sockfd);
	return;
}

int main(int argc, char *argv[])
{
	int mode;
	char hw_addr[6];
	char interfaceName[IFNAMSIZ];
	char buf[BUF_SIZ];
	memset(buf, 0, BUF_SIZ);
	
	int correct=0;
	if (argc > 1){
		if (strncmp(argv[1],"Send", 4)==0){
			if (argc == 5){
				mode=SEND; 
				sscanf(argv[3], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &hw_addr[0], &hw_addr[1], &hw_addr[2], &hw_addr[3], &hw_addr[4], &hw_addr[5]);
				strncpy(buf, argv[4], BUF_SIZ);
				correct=1;
				printf("  buf: %s\n", buf);
			}
		}
		else if (strncmp(argv[1],"Recv", 4)==0){
			if (argc == 3){
				mode=RECV;
				correct=1;
			}
		}
		strncpy(interfaceName, argv[2], IFNAMSIZ);
	}
	if (!correct){
		fprintf(stderr, "./455_proj2 Send <InterfaceName>  <DestHWAddr> <Message>\n");
		fprintf(stderr, "./455_proj2 Recv <InterfaceName>\n");
		exit(1);
	}

	//Do something here

	if (mode == SEND){
		send_message(interfaceName, hw_addr, buf);
	}
	else if (mode == RECV){
		recv_message(interfaceName);
	}

	return 0;
}

