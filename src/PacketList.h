#ifndef __PACKET_LIST_H
#define __PACKET_LIST_H

#include <time.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/igmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Global vars

struct info_packet 
{
	time_t	time;

	uint8_t  ether_dhost[ETH_ALEN];		/* destination eth addr */
  	uint8_t  ether_shost[ETH_ALEN];		/* source ether addr    */

    uint8_t ip_protocol;				/* protocol */

	struct in_addr ip_src, ip_dst;		/* source and destination IP address */

	union {
		struct {
  			uint8_t type;				/* message type */
  			uint8_t code;				/* type sub-code */
		} icmp_header;

		struct {
  			uint8_t type;				/* IGMP type */
  			uint8_t code;				/* routing code */
  			struct in_addr group;		/* group address */
		} igmp_header;

		struct {
        	uint16_t sport;				/* source port */
        	uint16_t dport;				/* destination port */
        	tcp_seq seq;				/* sequence number */
        	tcp_seq ack;				/* acknowledgement number */
			uint8_t flags;
		} tcp_header;

		struct {
        	uint16_t sport;				/* source port */
        	uint16_t dport;				/* destination port */
		} udp_header;

	} shared_header;
};

struct node 
{
	struct info_packet info;
	struct node *next;
	struct node *prev;
};

typedef struct info_list {
	struct node *header;
	struct node *tail;
	unsigned n_elements;
} *list;

// Function prototypes
void addPacket(const struct ether_header *ethernet,const struct ip *ip,const struct icmp *icmp_header,
			   const struct tcphdr *tcp_header,const struct udphdr *udp_header,const struct igmp *igmp_header);
void show_info();


#endif