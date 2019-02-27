#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <pcap.h>

#define CAPTURE_FILE_NAME "test.pcap"
#define TCPDUMP_MAGIC 0xa1b2c3d4

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
	FILE *cap_fp;
	struct pcap_file_header pcap_header;
	uint32_t jp_timezone;

	if (argc != 3) {
		char *help_msg = "---example---\n sudo ./etherdump eth0 1";
		fprintf(stderr, "input device-name and pcap flag.\n");
		fprintf(stderr, "%s\n", help_msg);
		return 1;
	}
	if((soc = initialize_raw_socket(argv[1])) == -1) {
		fprintf(stderr, "initialize_raw_socket: error:%s\n", argv[1]);
		return -1;
	}
	if (!strcmp("1", argv[2])) {
		cap_fp = fopen(CAPTURE_FILE_NAME, "wb+");
		if (cap_fp == NULL) {
			perror("fopen");
			close(soc);
			return -1;
		}
		memset(&pcap_header, 0, sizeof(struct pcap_file_header));
		pcap_header.magic = TCPDUMP_MAGIC;
		pcap_header.version_major = PCAP_VERSION_MAJOR;
		pcap_header.version_minor = PCAP_VERSION_MINOR;
		jp_timezone = 3600 * 9;
		pcap_header.thiszone = jp_timezone;
		pcap_header.sigfigs = 0;
		pcap_header.snaplen = 2048;
		pcap_header.linktype = DLT_EN10MB;
		fwrite(&pcap_header, sizeof(struct pcap_file_header), 1, cap_fp);
	}
	while(1) {
		struct pcap_pkthdr pcap_pkt_hdr;
		if ((size = read(soc, buf, sizeof(buf))) <= 0) {
			perror("read");
		} else {
			if (sizeof(struct ether_header) <= size) {
				print_ethernet((struct ether_header *)buf, stdout);
				if (!strcmp("1", argv[2])) {
					gettimeofday(&pcap_pkt_hdr.ts, NULL);
					pcap_pkt_hdr.len = pcap_pkt_hdr.caplen = size;
					fwrite(&pcap_pkt_hdr, sizeof(struct pcap_pkthdr), 1, cap_fp);
					fwrite(buf, size, 1, cap_fp);
				}
			} else {
				fprintf(stderr, "read size(%d) < %ld\n", size, sizeof(struct ether_header));
			}
		}
	}
	close(soc);
	fclose(cap_fp);
	return 0;
}
