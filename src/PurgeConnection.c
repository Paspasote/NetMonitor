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
unsigned purgeConnections(int internet, int incoming);
int Purge_isValidList(shared_sorted_list list, pthread_mutex_t mutex);
void Purge_freeLastConnections(void *val, void *param);
void Purge_updateBandwidth(struct connection_info *info, time_t now);
void Purge_accumulateBytes(void *val, void *total);

void *purge_connections(void *ptr_paramt) 
{
    unsigned intranet_count = 0, internet_count = 0;

	while (1)
	{
		// Purge incoming internet connections
        internet_count = purgeConnections(1, 1);
		// Purge outgoing internet connections
        internet_count += purgeConnections(1, 0);

		if (c_globvars.intranet_dev != NULL)
		{
			// Purge incoming intranet connections
			intranet_count = purgeConnections(0, 1);
			// Purge outgoing intranet connections
			intranet_count += purgeConnections(0, 0);
		}
#ifdef DEBUG
		if (pthread_mutex_lock(&w_globvars.mutex_debug_stats)) 
        {
            perror("connection_tracker: pthread_mutex_lock with mutex_debug_stats");
            exit(1);
        }        
		w_globvars.internet_packets_purged += internet_count;
		w_globvars.intranet_packets_purged += intranet_count;
		if (pthread_mutex_unlock(&w_globvars.mutex_debug_stats))
		{
			perror("connection_tracker: pthread_mutex_unlock with mutex_debug_stats");
			exit(1);		
		}
#endif

        sleep(PURGE_INTERVAL);
	}

    fprintf(stderr, "PURGE CONNECTIONS THREAD HAS FINISHED!!!!!!!!\n");
	exit(1);
}

unsigned purgeConnections(int internet, int incoming) 
{
    shared_sorted_list *hash_table;
    pthread_mutex_t *mutex;
    int i;
	struct node_shared_sorted_list *node, *current_node;
	struct connection_info *info;
	time_t now;
	unsigned timeout;
    unsigned count = 0;

	// Internet or intranet packet ?
	if (internet)
	{
		// Incoming or Outgoing ?
		if (incoming)
		{

#ifdef DEBUG
            /***************************  DEBUG ****************************/
            {
                char m[150];

                sprintf(m, "Connection Purger: Purging incoming internet connections...");
		        debugMessageModule(CONNECTIONS_PURGER, m, NULL, 1);
            }
#endif

			// Incoming connection
			// Get hash table
			hash_table = w_globvars.conn_internet_in;
            mutex = &w_globvars.mutex_conn_internet_in;
		}
		else
		{
#ifdef DEBUG
            /***************************  DEBUG ****************************/
            {
                char m[150];

                sprintf(m, "Connection Purger: Purging outgoing internet connections...");
		        debugMessageModule(CONNECTIONS_PURGER, m, NULL, 1);
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
#ifdef DEBUG
            /***************************  DEBUG ****************************/
            {
                char m[150];

                sprintf(m, "Connection Purger: Purging incoming intranet connections...");
		        debugMessageModule(CONNECTIONS_PURGER, m, NULL, 1);
            }
#endif

			// Incoming connection
			// Get hash table
			hash_table = w_globvars.conn_intranet_in;
            mutex = &w_globvars.mutex_conn_intranet_in;
		}
		else
		{
#ifdef DEBUG
            /***************************  DEBUG ****************************/
            {
                char m[150];

                sprintf(m, "Connection Purger: Purging outgoing intranet connections...");
		        debugMessageModule(CONNECTIONS_PURGER, m, NULL, 1);
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

#ifdef DEBUG
                /***************************  DEBUG ****************************/
                {
                    char m[150];

                    sprintf(m, "Connection Purger: Before request Read Access...");
                    debugMessageModule(CONNECTIONS_PURGER, m, NULL, 1);
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
#ifdef DEBUG
                        /***************************  DEBUG ****************************/
                        {
                            char m[150];

                            sprintf(m, "Connection Purger: Before purge connection...");
		                    debugMessageModule(CONNECTIONS_PURGER, m, NULL, 1);
                        }
#endif
                        purge_connection(hash_table[i], current_node);
                        count++;
#ifdef DEBUG
                        /***************************  DEBUG ****************************/
                        {
                            char m[150];

                            sprintf(m, "Connection Purger: After purge connection...");
		                    debugMessageModule(CONNECTIONS_PURGER, m, NULL, 1);
                        }
#endif
                    }
                    else 
                    {
                        // Leave read access
                        leaveReadNode_shared_sorted_list(node);

                        if (requestWriteNode_shared_sorted_list(node))
                        {
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
#ifdef DEBUG
                /***************************  DEBUG ****************************/
                {
                    char m[150];

                    sprintf(m, "Connection Purger: next node...");
		            debugMessageModule(CONNECTIONS_PURGER, m, NULL, 1);
                }
#endif

            }
        }
    }
#ifdef DEBUG
    /***************************  DEBUG ****************************/
    {
        char m[150];

        sprintf(m, "Connection Purger: finished");
		debugMessageModule(CONNECTIONS_PURGER, m, NULL, 1);
    }
#endif

    return count;
}

void purge_connection(shared_sorted_list list, struct node_shared_sorted_list *node)
{
    struct connection_info *info;

#ifdef DEBUG
    /***************************  DEBUG ****************************/
    {
        char m[150];

        sprintf(m, "Connection purger: Purging conn, Before request write acces to node... ");
		debugMessageModule(CONNECTIONS_PURGER, m, NULL, 1);
    }
#endif

    if (!requestReadNode_shared_sorted_list(node))
    {
        // Node already removed
        leaveNode_shared_sorted_list(list, node);
        return;
    }

    info = (struct connection_info *)node->info;

   // Purge bandwidth information
    Purge_freeLastConnections(info, NULL);

    // Remove this node connection and free the info
    if (removeNode_shared_sorted_list(list, node, 1) != 1)
    {
        leaveReadNode_shared_sorted_list(node);
        leaveNode_shared_sorted_list(list, node);
    }
#ifdef DEBUG
    /***************************  DEBUG ****************************/
    {
        char m[150];

        sprintf(m, "Connection purger: Purging conn, finished");
		debugMessageModule(CONNECTIONS_PURGER, m, NULL, 1);
    }
#endif
}

int Purge_isValidList(shared_sorted_list list, pthread_mutex_t mutex) {
	int ret;

	if (pthread_mutex_lock(&mutex)) 
	{
		perror("Purge_isValidList: pthread_mutex_lock with mutex list");
		exit(1);
	}
	ret = list != NULL;
	if (pthread_mutex_unlock(&mutex))
	{
		perror("Purge_isValidList: pthread_mutex_unlock with mutex list");
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
