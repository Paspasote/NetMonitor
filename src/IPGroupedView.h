#ifndef __IP_GROUPED_VIEW_H
#define __IP_GROUPED_VIEW_H

#include <SortedList.h>

struct IPG_service_info {
	unsigned priority;

	time_t time;						/* Time stamp of last package */
	time_t time_inbound;				/* Time stamp of last Inbound */
	time_t first_time;					/* Time stamp of first hit (or first hit after timeout */

	unsigned long hits;					/* Number of Inconming packages */
//	unsigned long n_bytes;				/* Total bytes of connection (it resets if timeout) */
//	unsigned long total_bytes;			/* Totaal bytes of all connections (of this kind) */

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

struct IPG_info {
	unsigned priority;

	time_t time;						/* Time stamp of last package */
	time_t time_inbound;				/* Time stamp of last Inbound */
	time_t first_time;					/* Time stamp of first hit (or first hit after timeout */

	unsigned long hits;					/* Number of Inconming packages */
//	unsigned long n_bytes;				/* Total bytes of connection (it resets if timeout) */
//	unsigned long total_bytes;			/* Totaal bytes of all connections (of this kind) */
	struct in_addr ip_src;				/* source IP address */
	struct in_addr ip_dst;				/* destination IP address */

	sorted_list l_services;				// List of services hit by source IP
};

// Function prototypes
void IPG_Init();
void IPG_Reset();
void IPG_addPacket(const struct ether_header *ethernet,const struct ip *ip,const struct icmp *icmp_header,
				   const struct tcphdr *tcp_header,const struct udphdr *udp_header,const struct igmp *igmp_header, unsigned n_bytes, unsigned priority);
void IPG_ShowInfo();
void IPG_Purge();


#endif