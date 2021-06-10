#ifndef __OUTBOUND_VIEW_H
#define __OUTBOUND_VIEW_H

#include <time.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/igmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <DoubleList.h>
#include <WhoIs.h>

// Constants
#define BANDWIDTH_PRECISION 0.001

struct OV_info_bandwidth {
	time_t time;
	unsigned n_bytes;
};

struct OV_info {
	unsigned priority;

	time_t time;						/* Time stamp of last package */

	unsigned long hits;					/* Number of Outconming packages */
	unsigned long total_bytes;			/* Total bytes of all connections (of this kind) */

	double_list last_connections;		/* Connections in the last MAX_INTERVAL_BANDWITH seconds */
	float bandwidth;					/* Current connection bandwith */

	char country[MAX_LEN_COUNTRY+1];	/* Country code where this packet is coming from */
	char netname[MAX_VISIBLE_NETNAME+1];	/* Net name this packet is coming from */  

   	uint8_t ip_protocol;				/* protocol */

	struct in_addr ip_src;				/* source IP address */
	struct in_addr ip_dst;				/* destination IP address */

	union {
		struct {
  			uint8_t type;				/* message type */
  			uint8_t code;				/* type sub-code */
		} icmp_info;

		struct {
        	uint16_t sport;				/* source port */
        	uint16_t dport;				/* destination port */
			uint8_t flags;
		} tcp_info;

		struct {
        	uint16_t sport;				/* source port */
        	uint16_t dport;				/* destination port */
		} udp_info;

	} shared_info;
};

// Function prototypes
void OV_Init();
void OV_Reset();
void OV_addPacket(const struct ether_header *ethernet,const struct ip *ip,const struct icmp *icmp_header,
				  const struct tcphdr *tcp_header,const struct udphdr *udp_header,const struct igmp *igmp_header, unsigned n_bytes, unsigned priority);
void OV_ShowInfo();
void OV_Purge();

#endif