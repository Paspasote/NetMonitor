#ifndef __IP_GROUPED_VIEW_H
#define __IP_GROUPED_VIEW_H

#include <time.h>
#include <arpa/inet.h>

#include <SortedList.h>
#include <SharedSortedList.h>

// Constants
#define MAX_SERVICES	5

struct IPG_service_info {
	char flags[6];						/* Extra service info */
	time_t iptable_rule;				/* Last time the iptable rule has been updated */

	int stablished;						/* 1 if incoming connection is stablished one, 0 in another case */

	struct node_shared_sorted_list *conn_node;	// Connection node of this node view
	shared_sorted_list conn_list;				// Connection's list
};

struct IPG_info {
	unsigned priority;

	time_t time;						/* Time stamp of last package */
//	time_t first_time;					/* Time stamp of first hit (or first hit after timeout */

	unsigned long hits;					/* Number of Inconming packages of all services */
	unsigned long total_bytes;			/* Totaal bytes of all connections of all services */

	float bandwidth;					/* Current connection bandwith (of all services) */

	char country[MAX_LEN_COUNTRY+1];	/* Country code where this packet is coming from */
	char netname[MAX_VISIBLE_NETNAME+1];	/* Net name this packet is coming from */  

	struct in_addr ip_src;				/* source IP address */

	sorted_list l_services;				// List of services hit by source IP
};

// Function prototypes
void IPG_ShowInfo();


#endif