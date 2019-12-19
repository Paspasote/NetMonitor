#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <pcap.h>
#include <time.h>
#include <pthread.h>
#include <semaphore.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/igmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <Configuration.h>
#include <sniffer.h>
#include <PacketList.h>
#include <DefaultView.h>
#include <IPGroupedView.h>


// Function prototypes
void catch_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

// Global vars
extern int visual_mode;
int ll_header_type;
bpf_u_int32 mask;		/* The netmask of our sniffing device */
bpf_u_int32 own_ip;		/* The IP of our sniffing device */


void *sniffer(void *ptr_dev) {
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct pcap_pkthdr header;
	const u_char *packet;
	int ret_loop_val;
	struct bpf_program fp;
	char filter_exp[] = "inbound";
	char s_ownip[INET_ADDRSTRLEN];
	char s_netmask[INET_ADDRSTRLEN];

	// Try to open de net device for sniffing
	dev = (char *)ptr_dev;
	handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
	// It works??
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open network device %s:\n%s\n", dev, errbuf);
		exit(1);
	}

	// Get link-layer header type
	if ((ll_header_type = pcap_datalink(handle)) == -1) {		
			fprintf(stderr, "Couldn't get link-layer header type: %s\n", pcap_geterr(handle));
			exit(1);
	}

	// Apply filter (only incomming connections)
	if (pcap_lookupnet(dev, &own_ip, &mask, errbuf) == -1) {
		own_ip = 0;
		mask = 0;
	}

	inet_ntop(AF_INET, &own_ip, s_ownip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &mask, s_netmask, INET_ADDRSTRLEN);

	
	if (pcap_compile(handle, &fp, filter_exp, 1, mask) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			exit(1);
	}
	
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(1);
	}
	

	// Main loop for getting packets and inteface
	do {	
		// Set callback function (catch only one packet)
		ret_loop_val = pcap_loop(handle, 1, catch_packet, NULL);
	} while (!ret_loop_val);
	
	fprintf(stderr, "SNIFFER THREAD HAS FINISHED!!!!!!!!\n");
	exit(1);

	// Close the sniffer
	pcap_close(handle);

	pthread_exit(NULL);

}

// Callback function for getting packets
void catch_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) 
{	
	const struct ether_header *ethernet; /* The ethernet header */
	const struct ip *ip; /* The IP header */
	const struct icmp *icmp_header; /* ICMP header */
	const struct tcphdr *tcp_header; /* TCP header */
	const struct udphdr *udp_header; /* UDP header */
	const struct igmp *igmp_header; /* IGMP header */
	uint eth_header_size = ETHER_HDR_LEN;
	unsigned total_bytes;
	unsigned single_port;
	unsigned priority;


	u_int size_ip_header;

	if (ll_header_type == 113) {
		eth_header_size = eth_header_size + 2;
	}

	// Point to ethernet header
	ethernet = (struct ether_header*)(packet);

	// Point to ip header
	ip = (struct ip *)(packet + eth_header_size);
	// ip header size valid?
	size_ip_header = ip->ip_hl*4;
	if (size_ip_header < 20) {
		// fprintf(stderr, "* Invalid IP header length: %u bytes\n", size_ip_header);
		return;
	}
	total_bytes = eth_header_size + ip->ip_len;	

	// Protocol?
	switch (ip->ip_p) {
		case IPPROTO_ICMP:
			icmp_header = (struct icmp *)(packet + eth_header_size + size_ip_header);
			single_port = icmp_header->icmp_type;
			break;
		case IPPROTO_TCP:
			tcp_header = (struct tcphdr *)(packet + eth_header_size + size_ip_header);
			single_port = ntohs(tcp_header->th_dport);
			break;
		case IPPROTO_UDP:
			udp_header = (struct udphdr *)(packet + eth_header_size + size_ip_header);
			single_port = ntohs(udp_header->uh_dport);
			break;
		case IPPROTO_IGMP:
			igmp_header = (struct igmp *)(packet + eth_header_size + size_ip_header);
			single_port = igmp_header->igmp_type;
			break;
		default:
			single_port = 0;
	} 

	// Package wanted?
	priority = packetAllowed(ip->ip_p, single_port);
	if (!priority) {
		return;
	}

	switch (visual_mode) {
		case -1:
			// Debug mode. Prints all info
			addPacket(ethernet, ip, icmp_header, tcp_header, udp_header, igmp_header);
			break;
		case 0:
			// Default view. Store packet using DefaultView Module
			DV_addPacket(ethernet, ip, icmp_header, tcp_header, udp_header, igmp_header, total_bytes, priority);
			break;
		case 1:
			// IP Source view. Store packet using IPGroupedView Module
			IPG_addPacket(ethernet, ip, icmp_header, tcp_header, udp_header, igmp_header, total_bytes, priority);
			break;
	}

	return;

}