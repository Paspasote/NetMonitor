#ifndef __OUTNAT_VIEW_H
#define __OUTNAT_VIEW_H

#include <time.h>

#include <SharedSortedList.h>
#include <Connection.h>

// Constants
#define BANDWIDTH_PRECISION 0.001

struct ONATV_info {
	char country[MAX_LEN_COUNTRY+1];	/* Country code where this packet is coming from */
	char netname[MAX_VISIBLE_NETNAME+1];	/* Net name this packet is coming from */  

	char flags[6];						/* Extra source address info */

	int stablished;		/* 1 if connection is a stablished one, 0 in another case */

	struct node_shared_sorted_list *conn_node;	// Connection node of this node view
	shared_sorted_list conn_list;				// Connection's list
};

// Function prototypes
void ONATV_ShowInfo();

#endif