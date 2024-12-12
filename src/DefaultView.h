#ifndef __DEFAULT_VIEW_H
#define __DEFAULT_VIEW_H

#include <time.h>

#include <SharedSortedList.h>
#include <Connection.h>

struct DV_info {
	char country[MAX_LEN_COUNTRY+1];	/* Country code where this packet is coming from */
	char netname[MAX_VISIBLE_NETNAME+1];	/* Net name this packet is coming from */

	char flags[6];						/* Extra source address info */
	time_t xtable_rule;				/* Last time the nftables or iptables policy has been updated */

	int stablished;		/* 1 if connection is a stablished one, 0 in another case */

	struct node_shared_sorted_list *conn_node;	// Connection node of this node view
	shared_sorted_list conn_list;				// Connection's list
};

// Function prototypes
void DV_ShowInfo();

#endif