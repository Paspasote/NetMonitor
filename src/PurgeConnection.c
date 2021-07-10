#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <GlobalVars.h>
#include <PacketList.h>
#include <Configuration.h>
#include <Connection.h>
#ifdef DEBUG
#include <debug.h>
#endif

#include <PurgeConnection.h>

// EXTERNAL Global vars
extern struct const_global_vars c_globvars;
extern struct write_global_vars w_globvars;

// Function prototypes
void purgeConnections(int internet, int incoming);
int Purge_isValidList(shared_sorted_list list, sem_t mutex);
void Purge_freeLastConnections(void *val, void *param);
void Purge_updateBandwidth(struct connection_info *info, time_t now);
void Purge_accumulateBytes(void *val, void *total);

void *purge_connections(void *ptr_paramt) 
{
	while (1)
	{
		// Purge incoming internet connections
        purgeConnections(1, 1);
		// Purge outgoing internet connections
        purgeConnections(1, 0);

		if (c_globvars.intranet_dev != NULL)
		{
			// Purge incoming intranet connections
			purgeConnections(0, 1);
			// Purge outgoing intranet connections
			purgeConnections(0, 0);
		}

        sleep(PURGE_INTERVAL);
	}

    fprintf(stderr, "PURGE CONNECTIONS THREAD HAS FINISHED!!!!!!!!\n");
	exit(1);
}

void purgeConnections(int internet, int incoming) 
{
    shared_sorted_list *hash_table;
    sem_t *mutex;
    int i;
	struct node_shared_sorted_list *node, *current_node;
	struct connection_info *info;
	time_t now;
	unsigned timeout;

	// Internet or intranet packet ?
	if (internet)
	{
		// Incoming or Outgoing ?
		if (incoming)
		{

#if DEBUG > 1
            /***************************  DEBUG ****************************/
            {
                char m[255];

                sprintf(m, "Connection Purge: Purging incoming internet connections...           ");
                debugMessageXY(PURGE_THREAD_ROW, PURGE_THREAD_COL, m, NULL, 1);
            }
#endif

			// Incoming connection
			// Get hash table
			hash_table = w_globvars.conn_internet_in;
            mutex = &w_globvars.mutex_conn_internet_in;
		}
		else
		{
#if DEBUG > 1
            /***************************  DEBUG ****************************/
            {
                char m[255];

                sprintf(m, "Connection Purge: Purging outgoing internet connections...           ");
                debugMessageXY(PURGE_THREAD_ROW, PURGE_THREAD_COL, m, NULL, 1);
            }
#endif

			// Outgoing connection
			// Get hash table
			hash_table = w_globvars.conn_internet_out;
            mutex = &w_globvars.mutex_conn_internet_out;
		}
	}
	else
	{
		// Incoming or Outgoing ?
		if (incoming)
		{
#if DEBUG > 1
            /***************************  DEBUG ****************************/
            {
                char m[255];

                sprintf(m, "Connection Purge: Purging incoming intranet connections...           ");
                debugMessageXY(PURGE_THREAD_ROW, PURGE_THREAD_COL, m, NULL, 1);
            }
#endif

			// Incoming connection
			// Get hash table
			hash_table = w_globvars.conn_intranet_in;
            mutex = &w_globvars.mutex_conn_intranet_in;
		}
		else
		{
#if DEBUG > 1
            /***************************  DEBUG ****************************/
            {
                char m[255];

                sprintf(m, "Connection Purge: Purging outgoing intranet connections...           ");
                debugMessageXY(PURGE_THREAD_ROW, PURGE_THREAD_COL, m, NULL, 1);
            }
#endif

			// Outgoing connection
			// Get hash table
			hash_table = w_globvars.conn_intranet_out;
            mutex = &w_globvars.mutex_conn_intranet_out;
		}
	}

    // Get current time
    now = time(NULL);

    // Iterate buckets of hash table
    for (i=0; i<65536; i++)
    {
        // Is list valid?
        if (Purge_isValidList(hash_table[i], *mutex))
        {
            // Iterate the bucket's list and remove old connections
            node = firstNode_shared_sorted_list(hash_table[i]);
            while (node != NULL) {
                // Get info node
                info = (struct connection_info *)node->info;

#if DEBUG > 1
                        /***************************  DEBUG ****************************/
                        {
                            char m[255];

                            sprintf(m, "Connection Purge: Before request Read Access...     ");
                            debugMessageXY(PURGE_THREAD_ROW, PURGE_THREAD_COL, m, NULL, 1);
                        }
#endif
                if (requestReadNode_shared_sorted_list(node))
                {
                    switch (info->ip_protocol) {
                        case IPPROTO_TCP:
                            timeout = TCP_TIMEOUT;
                            break;
                        case IPPROTO_UDP:
                            timeout = UDP_TIMEOUT;
                            break;
                        default:
                            timeout = ANY_TIMEOUT;
                    }

                    // Timeout?
                    if (now - info->time > timeout) 
                    {
                        // Leave read access
                        leaveReadNode_shared_sorted_list(node);
                        // have to delete current node
                        current_node = node;
                        // Before remove current node get the next one
                        node = nextNode_shared_sorted_list(hash_table[i], node, 0);
                        // Removing current node
#if DEBUG > 1
                        /***************************  DEBUG ****************************/
                        {
                            char m[255];

                            sprintf(m, "Connection Purge: Before purge connection...     ");
                            debugMessageXY(PURGE_THREAD_ROW, PURGE_THREAD_COL, m, NULL, 1);
                        }
#endif
                        purge_connection(hash_table[i], current_node);
#if DEBUG > 1
                        /***************************  DEBUG ****************************/
                        {
                            char m[255];

                            sprintf(m, "Connection Purge: After purge connection...      ");
                            debugMessageXY(PURGE_THREAD_ROW, PURGE_THREAD_COL, m, NULL, 1);
                        }
#endif
                    }
                    else 
                    {
                        // Leave read access
                        leaveReadNode_shared_sorted_list(node);

                        if (requestWriteNode_shared_sorted_list(node))
                        {
                            // Check if pointers to relative/NAT connections are still valid
                            if (info->relative_list != NULL && info->relative_node != NULL && isNodeRemoved_shared_sorted_list(info->relative_node))
                            {
                                // Pointer to relative connection not valid
                                leaveNode_shared_sorted_list(info->relative_list, info->relative_node);
                                info->relative_list = NULL;
                                info->relative_node = NULL;
                            }
                            if (info->nat_list != NULL && info->nat_node != NULL && isNodeRemoved_shared_sorted_list(info->nat_node))
                            {
                                // Pointer to NAT connection not valid
                                leaveNode_shared_sorted_list(info->nat_list, info->nat_node);
                                info->nat_list = NULL;
                                info->nat_node = NULL;
                            }

                            // Update bandwidth
                            Purge_updateBandwidth(info, now);

                            // Leave write access
                            leaveWriteNode_shared_sorted_list(node);
                        }

                        // Next node
                        node = nextNode_shared_sorted_list(hash_table[i], node, 1);
                    }
                }
                else
                {
                    // Next node
                    node = nextNode_shared_sorted_list(hash_table[i], node, 1);
                }
#if DEBUG > 1
                /***************************  DEBUG ****************************/
                {
                    char m[255];

                    sprintf(m, "Connection Purge: next node...                        ");
                    debugMessageXY(PURGE_THREAD_ROW, PURGE_THREAD_COL, m, NULL, 1);
                }
#endif

            }
        }
    }
#if DEBUG > 1
    /***************************  DEBUG ****************************/
    {
        char m[255];

        sprintf(m, "Connection Purge: finished                                           ");
        debugMessageXY(PURGE_THREAD_ROW, PURGE_THREAD_COL, m, NULL, 1);
    }
#endif

}

void purge_connection(shared_sorted_list list, struct node_shared_sorted_list *node)
{
    struct connection_info *info, *info_relative, *info_nat;
    struct node_shared_sorted_list *relative_node, *nat_node;
    shared_sorted_list relative_list, nat_list;

#if DEBUG > 1
    /***************************  DEBUG ****************************/
    {
        char m[255];

        sprintf(m, "Connection tracker: Purging conn, Before request write acces to node... ");
        debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
    }
#endif

    if (!requestReadNode_shared_sorted_list(node))
    {
        // Node already removed
        leaveNode_shared_sorted_list(list, node);
        return;
    }

    info = (struct connection_info *)node->info;

    // Get relative connection info
    relative_node = info->relative_node;
    relative_list = info->relative_list;

    // Get relative NAT connection info
    nat_node = info->nat_node;
    nat_list = info->nat_list;

   // Purge bandwidth information
    Purge_freeLastConnections(info, NULL);

    // Remove this node connection and free the info
    if (removeNode_shared_sorted_list(list, node, 1) != 1)
    {
        leaveReadNode_shared_sorted_list(node);
        leaveNode_shared_sorted_list(list, node);
    }

    // Was this node pointing to a relative connection
    if (relative_node != NULL && relative_list != NULL)
    {
        // Yes. We have to leave access to relative node
#if DEBUG > 1
        /***************************  DEBUG ****************************/
        {
            char m[255];

            sprintf(m, "Connection tracker: Purging conn, Before request write access to relative... ");
            debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
        }
#endif
        if (requestWriteNode_shared_sorted_list(relative_node))
        {
#if DEBUG > 1
            /***************************  DEBUG ****************************/
            {
                char m[255];

                sprintf(m, "Connection tracker: Purging conn, After request write access to relative...     ");
                debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
            }
#endif
            // Is relative node pointing to this node?
            info_relative = (struct connection_info *)relative_node->info;
            if (info_relative->relative_list != NULL || info_relative->relative_node != NULL)
            {
                // Yes. Removing references to this node
                info_relative->relative_list = NULL;
                info_relative->relative_node = NULL;
                // One less pointer to this node
                leaveNode_shared_sorted_list(list, node);
            }

            // This node not pointing to relative node any more
            info_relative->pointed_by_relative--;

            leaveWriteNode_shared_sorted_list(relative_node);
        }

        // One less pointer to relative node
        leaveNode_shared_sorted_list(relative_list, relative_node);
    }

#if DEBUG > 1
    /***************************  DEBUG ****************************/
    {
        char m[255];

        sprintf(m, "Connection tracker: Purging conn, Before check for relative NAT...           ");
        debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
    }
#endif

    // Was this node pointing to a NAT connection
    if (nat_node != NULL && nat_list != NULL)
    {
        // Yes. We have to leave access to NAT node
#if DEBUG > 1
        /***************************  DEBUG ****************************/
        {
            char m[255];

            sprintf(m, "Connection tracker: Purging conn, Before request write access to NAT... ");
            debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
        }
#endif
        if (requestWriteNode_shared_sorted_list(nat_node))
        {
#if DEBUG > 1
            /***************************  DEBUG ****************************/
            {
                char m[255];

                sprintf(m, "Connection tracker: Purging conn, After request write access to NAT...     ");
                debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
            }
#endif
            // Is NAT node pointing to this node?
            info_nat = (struct connection_info *)nat_node->info;
            if (info_nat->nat_list != NULL || info_nat->nat_node != NULL)
            {
                // Yes. Removing references to this node
                info_nat->nat_list = NULL;
                info_nat->nat_node = NULL;
                // One less pointer to this node
                leaveNode_shared_sorted_list(list, node);
            }

            // This node not pointing to NAT node any more
            info_nat->pointed_by_nat--;

            leaveWriteNode_shared_sorted_list(nat_node);
        }

        // One less pointer to NAT node
        leaveNode_shared_sorted_list(nat_list, nat_node);
    }

#if DEBUG > 1
    /***************************  DEBUG ****************************/
    {
        char m[255];

        sprintf(m, "Connection tracker: Purging conn, finished                      ");
        debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
    }
#endif
}

int Purge_isValidList(shared_sorted_list list, sem_t mutex) {
	int ret;

	if (sem_wait(&mutex)) 
	{
		perror("Purge_isValidList: sem_wait with mutex list");
		exit(1);
	}
	ret = list != NULL;
	if (sem_post(&mutex))
	{
		perror("Purge_isValidList: sem_post with mutex list");
		exit(1);		
	}

	return ret;
}

void Purge_freeLastConnections(void *val, void *param) {
	struct connection_info *info;

	info = (struct connection_info *)val;

	// Clear Bandwidth info
	clear_all_double_list(info->last_connections, 1, NULL, NULL);
	// Free memory
	free(info->last_connections);
}

void Purge_updateBandwidth(struct connection_info *info, time_t now) {
	unsigned long total_bytes = 0;
	struct connection_bandwidth *info_bandwidth;	
	time_t t;
	int stop;

	// First, we remove all connections older than MAX_INTERVAL_BANDWIDTH seconds
	stop = 0;
	while (!stop && !isEmpty_double_list(info->last_connections)) {
		info_bandwidth = (struct connection_bandwidth *) front_double_list(info->last_connections);
		stop = now - info_bandwidth->time <= MAX_INTERVAL_BANDWIDTH;
		if (!stop) {
			// We have to remove this last connection
			remove_front_double_list(info->last_connections, 1);
		}
	}

	// Get time of older connection
	t = now;
	if (!isEmpty_double_list(info->last_connections)) {
		info_bandwidth = (struct connection_bandwidth *)front_double_list(info->last_connections);
		t = info_bandwidth->time;
	}

	if (now - t >= MIN_INTERVAL_BANDWIDTH) {
		// Calculate total bytes 	
		for_each_double_list(info->last_connections, Purge_accumulateBytes, (void *)&total_bytes);

		info->bandwidth = (float)total_bytes / (1024.0 * (now - t + 1));
	}
	else {
		info->bandwidth = 0.0;
	}
}

void Purge_accumulateBytes(void *val, void *total) {
	*(unsigned long *)total += ((struct connection_bandwidth *)val)->n_bytes;
}
