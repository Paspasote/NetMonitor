#ifndef __CONNECTION_H
#define __CONNECTION_H

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
#include <SharedSortedList.h>
#include <WhoIs.h>

struct connection_bandwidth {
	time_t time;
	unsigned n_bytes;
};

struct connection_info {
	unsigned priority;			/* Priority for the view */

	time_t time;				/* Time stamp of last packet */

	unsigned long hits;					/* Number of packets */
	unsigned long total_bytes;			/* Total bytes of all packets (of this kind) */

	double_list last_connections;		/* Connections in the last INTERVAL_BANDWITH seconds */
	float bandwidth;					/* Current connection bandwith */

	int incoming;		/* 1 if it is an incoming connection, 0 in another case */
   	int starting;		/* 1 if this connection started comm, 0 if not */
	int stablished;		/* 1 if connection is a stablished one, 0 in another case */
	int NAT;			/* 1 if this is a NAT incoming connection */
	
   	uint8_t ip_protocol;	/* protocol */

	struct in_addr ip_src;	/* source IP address */
	struct in_addr ip_dst;	/* destination IP address */
	struct in_addr ip_NAT_dst;  /* Local IP destination (with NAT) */

	union {
		struct {
  			uint8_t type;	/* message type */
  			uint8_t code;	/* type sub-code */
		} icmp_info;

		struct {
        	uint16_t sport;	/* source port */
        	uint16_t dport;	/* destination port */
			uint16_t NAT_dport;  /* NAT destination port */
        	tcp_seq seq;	/* sequence number */
        	tcp_seq ack;	/* acknowledgement number */
			uint8_t flags;	/* TCP Flags */
		} tcp_info;

		struct {
        	uint16_t sport;	/* source port */
        	uint16_t dport;	/* destination port */
			uint16_t NAT_dport; /* NAT destination port */
		} udp_info;

	} shared_info;
};

// Function prototypes
void *connection_tracker(void *ptr_paramt);

#endif
