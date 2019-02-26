#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>

int set_promiscuous_mode(int soc, struct ifreq *req) {
	if (ioctl(soc, SIOCGIFFLAGS, req) < 0) {
		perror("ioctl");
		close(soc);
		return -1;
	}
	req->ifr_flags = req->ifr_flags | IFF_PROMISC;
	if (ioctl(soc, SIOCSIFFLAGS, req) < 0) {
		perror("ioctl");
		close(soc);
		return -1;
	}
	return 0;
}

int initialize_raw_socket(char *device) {
	struct ifreq ifreq;
	struct sockaddr_ll sa;
	int soc;

	if((soc = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		perror("socket");
		return -1;
	}

	memset(&ifreq, 0, sizeof(struct ifreq));
	if (strlen(device) >= sizeof(ifreq.ifr_name)) {
		fprintf(stderr, "%s: too long interface name.\n", device);
		close(soc);
		return -1;
	}
	strcpy(ifreq.ifr_name, device);

	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_ALL);
	if (ioctl(soc, SIOCGIFINDEX, &ifreq) < 0) {
		perror("ioctl");
		close(soc);
		return -1;
	}
	sa.sll_ifindex = ifreq.ifr_ifindex;
	if (bind(soc, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind");
		close(soc);
		return -1;
	}

	if(set_promiscuous_mode(soc, &ifreq)) {
		return -1;
	}
	return soc;
}

char *get_mac_addr_str(u_char *hwaddr, char *buf, socklen_t size) {
	snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
			hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
	return buf;
}

int print_ethernet(struct ether_header *eh, FILE *fp) {
	char buf[80];
	fprintf(fp, "ether_header------------------------------------------\n");
	fprintf(fp, "dest=%s\n", get_mac_addr_str(eh->ether_dhost, buf, sizeof(buf)));
	fprintf(fp, "src=%s\n", get_mac_addr_str(eh->ether_shost, buf, sizeof(buf)));
	fprintf(fp, "type=%02X", ntohs(eh->ether_type));
	switch(ntohs(eh->ether_type)) {
		case ETHERTYPE_IP:
			fprintf(fp, "(IP)\n");
			break;
		case ETHERTYPE_IPV6:
			fprintf(fp, "(IPv6)\n");
			break;
		case ETHERTYPE_ARP:
			fprintf(fp, "(ARP)\n");
			break;
		case ETHERTYPE_VLAN:
			fprintf(fp, "(VLAN)\n");
			break;
		default:
			fprintf(fp, "(unknown)\n");
			break;
	}
	return 0;
}

int main(int argc, char *argv[]) {
	int soc, size;
	u_char buf[2048];
	if (argc <= 1) {
		fprintf(stderr, "input device-name.");
		return 1;
	}
	if((soc = initialize_raw_socket(argv[1])) == -1) {
		fprintf(stderr, "initialize_raw_socket: error:%s\n", argv[1]);
		return -1;
	}
	while(1) {
		if ((size = read(soc, buf, sizeof(buf))) <= 0) {
			perror("read");
		} else {
			if (size >= sizeof(struct ether_header)) {
				print_ethernet((struct ether_header *)buf, stdout);
			} else {
				fprintf(stderr, "read size(%d) < %ld\n", size, sizeof(struct ether_header));
			}
		}
	}
	close(soc);
	return 0;
}
