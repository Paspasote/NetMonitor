#ifndef __IP_GROUPED_VIEW_H
#define __IP_GROUPED_VIEW_H

#include <SharedSortedList.h>
#include <DoubleList.h>
#include <WhoIs.h>

// Constants
#define MAX_SERVICES	5

struct IPG_info_bandwidth {
	time_t time;
	unsigned n_bytes;
};

struct IPG_service_info {
	unsigned priority;

	time_t time;						/* Time stamp of last package */
	time_t first_time;					/* Time stamp of first hit (or first hit after timeout */

	unsigned long hits;					/* Number of Inconming packages */
	unsigned long total_bytes;			/* Total bytes of all connections (of this service) */

	float bandwidth;					/* Current connection bandwith (of this service) */
	double_list last_connections;		/* Connections in the last INTERVAL_BANDWITH seconds */

	int response;						/* 1 if incoming connection is a respond of a previous outcoming 
										   0 in another case */

   	uint8_t ip_protocol;				/* protocol */

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

struct IPG_info_outbound {
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


struct IPG_info {
	unsigned priority;

	time_t time;						/* Time stamp of last package */
	time_t first_time;					/* Time stamp of first hit (or first hit after timeout */

	unsigned long hits;					/* Number of Inconming packages of all services */
	unsigned long total_bytes;			/* Totaal bytes of all connections of all services */

	float bandwidth;					/* Current connection bandwith (of all services) */
	double_list last_connections;		/* Connections in the last INTERVAL_BANDWITH seconds */

	char country[MAX_LEN_COUNTRY+1];	/* Country code where this packet is coming from */
	char netname[MAX_LEN_NETNAME+1];	/* Net name this packet is coming from */  

	struct in_addr ip_src;				/* source IP address */
	struct in_addr ip_dst;				/* destination IP address */

	sem_t mutex_services;
	shared_sorted_list l_services;				// List of services hit by source IP
};

struct count_services {
	unsigned cont;
	time_t now;
};

// Function prototypes
void IPG_Init();
void IPG_Reset();
void IPG_addPacket(in_addr_t own_ip, const struct ether_header *ethernet,const struct ip *ip,const struct icmp *icmp_header,
				   const struct tcphdr *tcp_header,const struct udphdr *udp_header,const struct igmp *igmp_header, unsigned n_bytes, unsigned priority);
void IPG_ShowInfo();
void IPG_Purge();


#endif