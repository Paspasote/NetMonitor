#ifndef __PURGECONNECTION_H
#define __PURGECONNECTION_H

#include <SharedSortedList.h>

// Constants
#define PURGE_INTERVAL  10

// Function prototypes
void *purge_connections(void *ptr_paramt);
void purge_connection(shared_sorted_list list, struct node_shared_sorted_list *node);

#endif
