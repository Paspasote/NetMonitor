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

#include <GlobalVars.h>
#include <Configuration.h>
#include <NetMonitor.h>
#include <PacketList.h>
#ifdef DEBUG
#include <debug.h>
#endif

#include <sniffer.h>

// EXTERNAL Global vars
extern struct const_global_vars c_globvars;
extern struct write_global_vars w_globvars;

// Global vars
int ll_header_type_internet, ll_header_type_intranet;

// Function prototypes
pcap_t * set_sniffer_type(int internet);
void catch_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


void *sniffer(void *ptr_paramt) {
	pcap_t *handle=NULL;
	int ret_loop_val;
	int is_internet;

	is_internet = *((int *)ptr_paramt);
	
	handle = set_sniffer_type(is_internet);

	// Main loop for getting packets
	do {	
		// Set callback function (catch only one packet)
		if (handle != NULL) {
			ret_loop_val = pcap_loop(handle, 1, catch_packet, (u_char *)&is_internet);
		}
		else {
			ret_loop_val = 1;
		}
	} while (!ret_loop_val);
	
	if (is_internet)
	{
		fprintf(stderr, "INTERNET SNIFFER THREAD HAS FINISHED!!!!!!!!\n");
	}
	else
	{
		fprintf(stderr, "INTRANET SNIFFER THREAD HAS FINISHED!!!!!!!!\n");
	}
	
	// Terminate all threads and process
	exit(1);

/*
	// Close the sniffer
	pcap_close(handle);

	pthread_exit(NULL);
*/
}

pcap_t * set_sniffer_type(int internet)
{
	char *dev_net;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	bpf_u_int32 mask;
	char s_ownip[INET_ADDRSTRLEN];
	char s_netmask[INET_ADDRSTRLEN];
	char filter_exp[150];
	struct bpf_program fp;
	int *ll_header_type;

	switch (internet) {
		case 1:
			// Inspect all packets from internet device
			dev_net = c_globvars.internet_dev;
			mask = c_globvars.own_mask_internet;

			inet_ntop(AF_INET, &c_globvars.own_ip_internet, s_ownip, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &c_globvars.own_mask_internet, s_netmask, INET_ADDRSTRLEN);

			// Set filter (no filter, because we are inspecting ALL packets)			
			strcpy(filter_exp, "");

			ll_header_type = &ll_header_type_internet;
			break;
		case 0:
			// Inspect all packets from intranet <------> internet

			// Is there intranet device?
			if (c_globvars.intranet_dev == NULL) return NULL;

			dev_net = c_globvars.intranet_dev;
			mask = c_globvars.own_mask_intranet;

			inet_ntop(AF_INET, &c_globvars.network_intranet, s_ownip, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &c_globvars.own_mask_intranet, s_netmask, INET_ADDRSTRLEN);

			// Set filter
			sprintf(filter_exp, "not src net %s mask %s or not dst net %s mask %s", s_ownip, s_netmask, s_ownip, s_netmask);

			ll_header_type = &ll_header_type_intranet;
			break;
	}

	// Try to open the device for sniffing
	handle = pcap_open_live(dev_net, BUFSIZ, 0, 1000, errbuf);
	// It works??
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open network device %s:\n%s\n", dev_net, errbuf);
		exit(1);
	}

	// Get link-layer header type
	if ((*ll_header_type = pcap_datalink(handle)) == -1) {		
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

	return handle;
}

// Callback function for getting packets
void catch_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) 
{
	int internet;
	const struct ether_header *ethernet = NULL; /* The ethernet header */
	const struct ip *ip = NULL; /* The IP header */
	const struct icmp *icmp_header = NULL; /* ICMP header */
	const struct tcphdr *tcp_header = NULL; /* TCP header */
	const struct udphdr *udp_header = NULL; /* UDP header */
	const struct igmp *igmp_header = NULL; /* IGMP header */
	uint eth_header_size = ETHER_HDR_LEN;
	unsigned total_bytes;
	u_int size_ip_header;

	internet = *((int *)args);

	if (internet)
	{
#ifdef DEBUG
		/***************************  DEBUG ****************************/
		{
			char m[150];

			sprintf(m, "Internet sniffer: catch_packet start...");
			debugMessageModule(INTERNET_SNIFFER, m, NULL, 1);
		}
#endif

		if (ll_header_type_internet == 113) {
			eth_header_size = eth_header_size + 2;
		}
	}
	else
	{
#ifdef DEBUG
		/***************************  DEBUG ****************************/
		{
			char m[150];

			sprintf(m, "Intranet sniffer: catch_packet start...");
			debugMessageModule(INTRANET_SNIFFER, m, NULL, 1);
		}
#endif

		if (ll_header_type_intranet == 113) {
			eth_header_size = eth_header_size + 2;
		}
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
	//total_bytes = eth_header_size + ntohs(ip->ip_len);
	total_bytes = header->len;

	// Protocol?
	switch (ip->ip_p) 
	{
		case IPPROTO_ICMP:
			icmp_header = (struct icmp *)(packet + eth_header_size + size_ip_header);
			break;
		case IPPROTO_TCP:
			tcp_header = (struct tcphdr *)(packet + eth_header_size + size_ip_header);
			break;
		case IPPROTO_UDP:
			udp_header = (struct udphdr *)(packet + eth_header_size + size_ip_header);
			break;
		case IPPROTO_IGMP:
			igmp_header = (struct igmp *)(packet + eth_header_size + size_ip_header);
			break;
	} 

#ifdef DEBUG
	/***************************  DEBUG ****************************/
	if (internet)
	{
		char m[150];

		sprintf(m, "Internet sniffer: catch_packet finished");
		debugMessageModule(INTERNET_SNIFFER, m, NULL, 1);
	}
	else
	{
		char m[150];

		sprintf(m, "Intranet sniffer: catch_packet finished");
		debugMessageModule(INTRANET_SNIFFER, m, NULL, 1);
	}
	/*****************************************************************/
#endif

	PL_addPacket(internet, ethernet, ip, icmp_header, tcp_header, udp_header, igmp_header, total_bytes);          
}
