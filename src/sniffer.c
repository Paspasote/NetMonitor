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

#include <debug.h>
#include <Configuration.h>
#include <NetMonitor.h>
#include <sniffer.h>
#include <PacketList.h>
#include <DefaultView.h>
#include <IPGroupedView.h>
#include <OutboundView.h>


// Function prototypes
pcap_t * change_sniffer_type(int sniffer_type, char *dev_internet, char *dev_intranet);
void catch_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

// Global vars
extern int visual_mode;
int ll_header_type;
int last_visual_mode=-2;
bpf_u_int32 own_ip;

void *sniffer(void *ptr_paramt) {
	char *dev_internet, *dev_intranet;
	pcap_t *handle=NULL;
	int ret_loop_val;
	int last_sniffer_type=0, sniffer_type;

	dev_internet = ((struct param_thread *)ptr_paramt)->internet_dev;
	dev_intranet = ((struct param_thread *)ptr_paramt)->intranet_dev;

	// Main loop for getting packets
	do {	
		// Has visual mode changed?
		if (last_visual_mode != visual_mode) {
			// Yes. Type of sniffer?
			switch (visual_mode) {
				case 2:
					sniffer_type = 2;
					break;
				default:
					sniffer_type = 1;				
			}
			// Must sniffer type be changed?
			if (last_sniffer_type != sniffer_type) {
				// Yes
				handle = change_sniffer_type(sniffer_type, dev_internet, dev_intranet);
				last_sniffer_type = sniffer_type;
			}
			last_visual_mode = visual_mode;
		}
		// Set callback function (catch only one packet)
		if (handle != NULL) {
			ret_loop_val = pcap_loop(handle, 1, catch_packet, (u_char *)&sniffer_type);
		}
		else {
			ret_loop_val = 0;
		}
	} while (!ret_loop_val);
	
	fprintf(stderr, "SNIFFER THREAD HAS FINISHED!!!!!!!!\n");
	exit(1);

	// Close the sniffer
	pcap_close(handle);

	pthread_exit(NULL);

}

pcap_t * change_sniffer_type(int sniffer_type, char *dev_internet, char *dev_intranet) {
	char *dev_net;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	bpf_u_int32 mask;
	char s_ownip[INET_ADDRSTRLEN];
	char s_netmask[INET_ADDRSTRLEN];
	char filter_exp[150];
	struct bpf_program fp;

	switch (sniffer_type) {
		case 1:
			// Inspect all packets from internet
			dev_net = dev_internet;

			// Get network device address
			if (pcap_lookupnet(dev_net, &own_ip, &mask, errbuf) == -1) {
				own_ip = 0;
				mask = 0;
			}
			inet_ntop(AF_INET, &own_ip, s_ownip, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &mask, s_netmask, INET_ADDRSTRLEN);

			// Set filter
			
			strcpy(filter_exp, "");

			break;
		case 2:
			// Inspect outgoing packets from intranet to internet

			// Is there intranet device?
			if (dev_intranet == NULL) return NULL;

			dev_net = dev_intranet;

			// Get network device address
			if (pcap_lookupnet(dev_net, &own_ip, &mask, errbuf) == -1) {
				own_ip = 0;
				mask = 0;
			}
			inet_ntop(AF_INET, &own_ip, s_ownip, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &mask, s_netmask, INET_ADDRSTRLEN);

			// Set filter
			sprintf(filter_exp, "src net %s mask %s and not dst net %s mask %s", s_ownip, s_netmask, s_ownip, s_netmask);

			break;
	}

	// Try to open the internetnet device for sniffing
	handle = pcap_open_live(dev_net, BUFSIZ, 0, 1000, errbuf);
	// It works??
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open network device %s:\n%s\n", dev_net, errbuf);
		exit(1);
	}

	// Get link-layer header type
	if ((ll_header_type = pcap_datalink(handle)) == -1) {		
			fprintf(stderr, "Couldn't get link-layer header type: %s\n", pcap_geterr(handle));
			exit(1);
	}

	// Compile filter 
	if (pcap_compile(handle, &fp, filter_exp, 1, mask) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			exit(1);
	}

	// Set filter
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(1);
	}

	/***************************  DEBUG ****************************/
	if (visual_mode != -1)
	{
		char m[255];
		sprintf(m, "Device: %s   IP: %s   Mask: %s   Filter: %s", dev_net, s_ownip, s_netmask, filter_exp);
		debugMessageXY(0, 0, m, NULL, 1);
	}
	else {
		if (DEBUG > 0) {
			printf("Device: %s   IP: %s   Mask: %s   Filter: %s\n", dev_net, s_ownip, s_netmask, filter_exp);
		}
	}
	/*****************************************************************/

	return handle;
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
	int priority;
	int inbound;
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

	// ¿Inbound?
	inbound = *((int *)args) == 1;

	// Package wanted?
	priority = 1;
	if (visual_mode != -1) {
		if (ip->ip_p == IPPROTO_TCP || ip->ip_p == IPPROTO_UDP) {
			if (inbound) {
				priority = incoming_packetAllowed(ip->ip_p, single_port);
			}
			else {
				priority = outgoing_packetAllowed(ip->ip_src, ip->ip_p, single_port, 0);
			}
		}
		else {
			if (!inbound) {
				priority = outgoing_packetAllowed(ip->ip_src, ip->ip_p, single_port, 1);
			}
		}
	}
	if (!priority) {
		// Not wanted
		return;
	}

	switch (visual_mode) {
		case -1:
			// Debug mode. Prints all info
			if (last_visual_mode == visual_mode) {
				addPacket(ethernet, ip, icmp_header, tcp_header, udp_header, igmp_header);
			}
			break;
		case 0:
			// Default view. Store packet using DefaultView Module
			if (last_visual_mode == visual_mode) {
				DV_addPacket(own_ip, ethernet, ip, icmp_header, tcp_header, udp_header, igmp_header, total_bytes, priority);
			}
			break;
		case 1:
			// IP Source view. Store packet using IPGroupedView Module
			if (last_visual_mode == visual_mode) {
				IPG_addPacket(own_ip, ethernet, ip, icmp_header, tcp_header, udp_header, igmp_header, total_bytes, priority);
			}
			break;
		case 2:
			// Outbound view. Store packet using OutboundView Module
			if (last_visual_mode == visual_mode) {
				OV_addPacket(ethernet, ip, icmp_header, tcp_header, udp_header, igmp_header, total_bytes, priority);
			}
			break;
	}

	return;

}
