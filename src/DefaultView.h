#ifndef __DEFAULT_VIEW_H
#define __DEFAULT_VIEW_H

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

struct DV_info_bandwidth {
	time_t time;
	unsigned n_bytes;
};

struct DV_info {
	unsigned priority;

	time_t time;						/* Time stamp of last package */

	unsigned long hits;					/* Number of Inconming packages */
	unsigned long total_bytes;			/* Total bytes of all connections (of this kind) */

	double_list last_connections;		/* Connections in the last INTERVAL_BANDWITH seconds */
	float bandwidth;					/* Current connection bandwith */

	char country[MAX_LEN_COUNTRY+1];	/* Country code where this packet is coming from */
	char netname[MAX_VISIBLE_NETNAME+1];	/* Net name this packet is coming from */  

	int response;						/* 1 if incoming connection is a respond of a previous outcoming 
										   0 in another case */

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

struct DV_info_outbound {
	time_t time;						/* Time stamp of last package */

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
			int started;				/* 1 if we started comm, 0 if not */
		} udp_info;

	} shared_info;
};

// Function prototypes
void DV_Reset();
void DV_addPacket(in_addr_t own_ip, const struct ether_header *ethernet,const struct ip *ip,const struct icmp *icmp_header,
				  const struct tcphdr *tcp_header,const struct udphdr *udp_header,const struct igmp *igmp_header, unsigned n_bytes, unsigned priority);
void DV_ShowInfo();
void DV_Purge();

#endif