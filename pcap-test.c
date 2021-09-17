#include <libnet.h>
#include <pcap.h>

char *input(int argc, char *argv[]) {
	if(argc != 2) {
		printf("syntax: pcap-test <interface>\n");
		printf("sample: pcap-test wlan0\n");
		exit(1);
	}

	return argv[1];
}

pcap_t *my_pcap_open(char *dev) {
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* ret = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if(ret == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
		exit(1);
	}

	return ret;
}

int my_pcap_next(pcap_t *pcap, struct pcap_pkthdr **header, const u_char **packet) {
	int res = pcap_next_ex(pcap, header, packet);

	if(res == 0)
		return 0;

	if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
		printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
		pcap_close(pcap);
		exit(1);
	}

	return 1;
}

int isTCP(const u_char *packet, struct libnet_ethernet_hdr **ethernet, struct libnet_ipv4_hdr **ipv4, struct libnet_tcp_hdr ** tcp) {
	*ethernet = (struct libnet_ethernet_hdr *)packet;
	if(ntohs((*ethernet) -> ether_type) != 0x0800)
		return 0;
	
	*ipv4 = (struct libnet_ipv4_hdr *) (*ethernet + 1);
	if((*ipv4) -> ip_p != 0x06)
		return 0;

	*tcp = (struct libnet_tcp_hdr *) (*ipv4 + 1);

	return 1;
}

void printbyoctet(char *msg, void *begin, uint8_t size) {
	printf("%s", msg);

	for(uint8_t i = 0; size--; i ^= 1) {
		printf("%02X ", *(u_int8_t *) begin++);
		if(i)
			printf(" ");
	}

	printf("\n");
}

void payload(struct libnet_tcp_hdr *tcp, struct libnet_ipv4_hdr *ipv4) {
	uint16_t size = ntohs(ipv4 -> ip_len) - (ipv4 -> ip_hl) - (tcp -> th_off) * 32;
	printbyoctet("Payload          : ", (uint8_t *) tcp + tcp -> th_off * 4, size < 8 ? size : 8);
}

void getpacket(pcap_t *pcap) {
	struct pcap_pkthdr *header;
	const u_char *packet;
	struct libnet_ethernet_hdr *ethernet;
	struct libnet_ipv4_hdr *ipv4;
	struct libnet_tcp_hdr *tcp;

	while(1) {
		if(my_pcap_next(pcap, &header, &packet)
			&& isTCP(packet, &ethernet, &ipv4, &tcp)) {

			printbyoctet("Ethernet src  MAC: ", ethernet -> ether_shost, 6);
			printbyoctet("Ethernet dst  MAC: ", ethernet -> ether_dhost, 6);

			printf("IPv4     src   IP: %s\n", inet_ntoa(ipv4 -> ip_src));
			printf("IPv4     dst   IP: %s\n", inet_ntoa(ipv4 -> ip_dst));

			uint16_t tmp = ntohs(tcp -> th_sport);
			printbyoctet("TCP      src port: ", &tmp, 2);
			tmp = ntohs(tcp -> th_dport);
			printbyoctet("TCP      src port: ", &tmp, 2);

			payload(tcp, ipv4);
			printf("===\n");
		}
	}
}

int main(int argc, char *argv[]) {
	char *dev = input(argc, argv);

	pcap_t *pcap = my_pcap_open(dev);

	getpacket(pcap);
	
	pcap_close(pcap);

	return 0;
}
