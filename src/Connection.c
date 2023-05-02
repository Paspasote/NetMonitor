#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <GlobalVars.h>
#include <PacketList.h>
#include <Configuration.h>
#include <PurgeConnection.h>
#ifdef DEBUG
#include <debug.h>
#endif

#include <Connection.h>

// EXTERNAL Global vars
extern struct const_global_vars c_globvars;
extern struct write_global_vars w_globvars;

// Function prototypes
unsigned internetConnections();
unsigned intranetConnections();
void incomingConnection(int internet, struct info_packet *packet);
void outgoingConnection(int internet, struct info_packet *packet);
void addConnection(int internet, int incoming, struct info_packet *packet, unsigned priority);
void checkForRelativeOutgoingConnection(int internet, shared_sorted_list list, struct node_shared_sorted_list *node, 
										struct connection_info *info, struct connection_info *info_rev, 
										int syn, uint16_t src_port, uint16_t dst_port);
void checkForRelativeIncomingConnection(int internet, shared_sorted_list list, struct node_shared_sorted_list *node,
										struct connection_info *info, struct connection_info *info_rev, 
										int syn, uint16_t src_port, uint16_t dst_port);
void checkForRelativeNATConnection(int internet, shared_sorted_list list, struct node_shared_sorted_list *node,
								   struct connection_info *info);
void Conn_updateBandwidth(struct connection_info *info, time_t now);
void Conn_accumulateBytes(void *val, void *total);
int Conn_isValidList(shared_sorted_list list, sem_t mutex);
void Conn_createList(shared_sorted_list *list, sem_t mutex, int (*compare)(void *, void*) );
int compareConnections(void *data1, void *data2);
int compareNAT(void *data1, void *data2);

void *connection_tracker(void *ptr_paramt) {
	unsigned count = 0;
	int is_internet;

	is_internet = *((int *)ptr_paramt);

	while (1)
	{
		if (is_internet)
		{
			// Get internet connections
			count = internetConnections();
#ifdef DEBUG
			if (sem_wait(&w_globvars.mutex_debug_stats)) 
			{
				perror("connection_tracker: sem_wait with mutex_debug_stats");
				exit(1);
			}        
			w_globvars.internet_packets_processed += count;
			if (sem_post(&w_globvars.mutex_debug_stats))
			{
				perror("connection_tracker: sem_post with mutex_debug_stats");
				exit(1);		
			}
#endif
		}
		else
		{
			// Get intranet connections
			count = intranetConnections(); 
#ifdef DEBUG
			if (sem_wait(&w_globvars.mutex_debug_stats)) 
			{
				perror("connection_tracker: sem_wait with mutex_debug_stats");
				exit(1);
			}        
			w_globvars.intranet_packets_processed += count;
			if (sem_post(&w_globvars.mutex_debug_stats))
			{
				perror("connection_tracker: sem_post with mutex_debug_stats");
				exit(1);		
			}
#endif
		}
		// Any packet got?
		if (!count)
		{
			// No. Buffers were empty. Wait a moment
			sleep(1);
		}
	}

	// Terminate all threads and process
	if (is_internet) 
	{
    	fprintf(stderr, "INTERNET CONNECTION TRACKER THREAD HAS FINISHED!!!!!!!!\n");
	}
	else
	{
    	fprintf(stderr, "INTRANET CONNECTION TRACKER THREAD HAS FINISHED!!!!!!!!\n");
	}
	exit(1);
}

unsigned internetConnections()
{
    struct info_packet *packet;

#ifdef DEBUG
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "Internet Connection tracker: internetConnections start...");
		debugMessageModule(INTERNET_CONNECTIONS_TRACKER, m, NULL, 1);
	}
#endif

    // Get one internet packet
    packet = PL_getPacket(1);

    // Got any?
    if (packet == NULL) 
	{
#ifdef DEBUG 
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "Internet Connection tracker: internetConnections finished (no packets)");
		debugMessageModule(INTERNET_CONNECTIONS_TRACKER, m, NULL, 1);
	}
#endif
		return 0;
	}

    // Incoming or outgoing
	if (packet->ip_src.s_addr == c_globvars.own_ip_internet) 
    {
		// Outgoing
		outgoingConnection(1, packet);
	}
    else
    {
        // Incoming
        incomingConnection(1, packet);
    }

#ifdef DEBUG
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "Internet Connection tracker: internetConnections finished");
		debugMessageModule(INTERNET_CONNECTIONS_TRACKER, m, NULL, 1);
	}
#endif
	return 1;
}

unsigned intranetConnections()
{
    struct info_packet *packet;

#ifdef DEBUG
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "Intranet Connection tracker: intranetConnections start...");
		debugMessageModule(INTRANET_CONNECTIONS_TRACKER, m, NULL, 1);
	}
#endif

    // Get one intranet packet
    packet = PL_getPacket(0);

    // Got any?
    if (packet == NULL)
	{
#ifdef DEBUG
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "Intranet Connection tracker: intranetConnections finished (no packets)");
		debugMessageModule(INTRANET_CONNECTIONS_TRACKER, m, NULL, 1);
	}
#endif
		return 0;
	}

    // Incoming or outgoing
	if ((packet->ip_src.s_addr & c_globvars.own_mask_intranet) == c_globvars.network_intranet)
    {
		// Outgoing
		outgoingConnection(0, packet);
	}
    else
    {
        // Incoming
        incomingConnection(0, packet);
    }

#ifdef DEBUG
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "Intranet Connection tracker: intranetConnections finished");
		debugMessageModule(INTRANET_CONNECTIONS_TRACKER, m, NULL, 1);
	}
#endif
	return 1;
}


void incomingConnection(int internet, struct info_packet *packet)
{
    int priority;
   	unsigned single_port;

#ifdef DEBUG
	int module, module_info;
	char s[9];

	if (internet) 
	{
		module = INTERNET_CONNECTIONS_TRACKER;
		module_info = INTERNET_CONNECTIONS_TRACKER_INFO;
		strcpy(s, "Internet");
	}
	else
	{
		module = INTRANET_CONNECTIONS_TRACKER;
		module_info = INTRANET_CONNECTIONS_TRACKER_INFO;
		strcpy(s, "Intranet");
	}
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "%s Connection tracker: incomingConnection start...", s);
		debugMessageModule(module, m, NULL, 1);
	}
#endif

	// Protocol and destination port?
	switch (packet->ip_protocol) {
		case IPPROTO_ICMP:
			single_port = packet->shared_header.icmp_header.type;
			break;
		case IPPROTO_TCP:
			single_port = packet->shared_header.tcp_header.dport;
			break;
		case IPPROTO_UDP:
			single_port = packet->shared_header.udp_header.dport;
			break;
		case IPPROTO_IGMP:
			single_port = packet->shared_header.igmp_header.type;
			break;
		default:
			single_port = 0;
	} 

	// Protocol wanted??
	if (packet->ip_protocol != IPPROTO_ICMP && packet->ip_protocol != IPPROTO_TCP && packet->ip_protocol != IPPROTO_UDP) {
        // Not wanted
        free(packet);
#ifdef DEBUG
		/***************************  DEBUG ****************************/
		{
			char m[150];

			sprintf(m, "%s Connection tracker: incomingConnection finished", s);
			debugMessageModule(module, m, NULL, 1);
		}
#endif
		return;
	}

	// Package filtered?
	priority = 1;
	if (internet)
	{
		if (packet->ip_protocol == IPPROTO_TCP || packet->ip_protocol == IPPROTO_UDP) 
		{
				priority = incoming_packetAllowed(packet->ip_protocol, single_port);
		}
	}

	if (!priority) {
		// Not wanted
        free(packet);
#ifdef DEBUG
		/***************************  DEBUG ****************************/
		{
			char m[150];

			sprintf(m, "%s Connection tracker: incomingConnection finished", s);
			debugMessageModule(module, m, NULL, 1);
		}
#endif
		return;
	}

    addConnection(internet, 1, packet, priority);

#ifdef DEBUG
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "%s Connection tracker: incomingConnection finished", s);
		debugMessageModule(module, m, NULL, 1);
	}
#endif
}

void outgoingConnection(int internet, struct info_packet *packet)
{
    int priority;
   	unsigned single_port;

#ifdef DEBUG
	int module, module_info;
	char s[9];

	if (internet) 
	{
		module = INTERNET_CONNECTIONS_TRACKER;
		module_info = INTERNET_CONNECTIONS_TRACKER_INFO;
		strcpy(s, "Internet");
	}
	else
	{
		module = INTRANET_CONNECTIONS_TRACKER;
		module_info = INTRANET_CONNECTIONS_TRACKER_INFO;
		strcpy(s, "Intranet");
	}
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "%s Connection tracker: outgoingConnection start...", s);
		debugMessageModule(module, m, NULL, 1);
	}
#endif

	// Protocol and destination port?
	switch (packet->ip_protocol) {
		case IPPROTO_ICMP:
			single_port = packet->shared_header.icmp_header.type;
			break;
		case IPPROTO_TCP:
			single_port = packet->shared_header.tcp_header.dport;
			break;
		case IPPROTO_UDP:
			single_port = packet->shared_header.udp_header.dport;
			break;
		case IPPROTO_IGMP:
			single_port = packet->shared_header.igmp_header.type;
			break;
		default:
			single_port = 0;
	} 

	// Protocol wanted??
	if (packet->ip_protocol != IPPROTO_ICMP && packet->ip_protocol != IPPROTO_TCP && packet->ip_protocol != IPPROTO_UDP) {
        // Not wanted
        free(packet);
#ifdef DEBUG
		/***************************  DEBUG ****************************/
		{
			char m[150];

			sprintf(m, "%s Connection tracker: outgoingConnection finished", s);
			debugMessageModule(module, m, NULL, 1);
		}
#endif
		return;
	}

	// Package filtered?
	priority = 1;
	if (!internet)
	{
		if (packet->ip_protocol == IPPROTO_TCP || packet->ip_protocol == IPPROTO_UDP) 
		{
			priority = outgoing_packetAllowed(packet->ip_src, packet->ip_protocol, single_port, 0);
		}
		else
		{
			priority = outgoing_packetAllowed(packet->ip_src, packet->ip_protocol, single_port, 1);
		}
	}

	if (!priority) {
		// Not wanted
        free(packet);
#ifdef DEBUG
		/***************************  DEBUG ****************************/
		{
			char m[150];

			sprintf(m, "%s Connection tracker: outgoingConnection finished", s);
			debugMessageModule(module, m, NULL, 1);
		}
#endif
		return;
	}

    addConnection(internet, 0, packet, priority);
#ifdef DEBUG
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "%s Connection tracker: outgoingConnection finished", s);
		debugMessageModule(module, m, NULL, 1);
	}
#endif
}

void addConnection(int internet, int incoming, struct info_packet *packet, unsigned priority) {
    u_int16_t hash;
    shared_sorted_list list;
	time_t now;
	struct connection_info *info, *new_info;
	struct connection_info info_rev;
	struct node_shared_sorted_list *node;
	struct connection_bandwidth *info_bandwidth;
	uint16_t src_port=0, dst_port=0;
	int syn;


#ifdef DEBUG
	int module, module_info;
	char s[9];

	if (internet) 
	{
		module = INTERNET_CONNECTIONS_TRACKER;
		module_info = INTERNET_CONNECTIONS_TRACKER_INFO;
		strcpy(s, "Internet");
	}
	else
	{
		module = INTRANET_CONNECTIONS_TRACKER;
		module_info = INTRANET_CONNECTIONS_TRACKER_INFO;
		strcpy(s, "Intranet");
	}
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "%s Connection tracker: addConnection start...", s);
		debugMessageModule(module, m, NULL, 1);
	}
#endif

    // Get current time
	now = time(NULL);

	// Internet or intranet packet ?
	if (internet)
	{
		// It is an internet packet. Incoming or Outgoing ?
		if (incoming)
		{
			// Incoming connection
			// Get hash value and list
			hash = packet->ip_src.s_addr / 65536;
			list = w_globvars.conn_internet_in[hash];
			// Check if list has been created
			if (!Conn_isValidList(list, w_globvars.mutex_conn_internet_in)) {
				Conn_createList(&list, w_globvars.mutex_conn_internet_in, compareConnections);
				w_globvars.conn_internet_in[hash] = list;
			}
			// List is valid?
			if (!Conn_isValidList(list, w_globvars.mutex_conn_internet_in)) {
				fprintf(stderr,"addConnection: Internet incoming list is not valid!!\n");
				exit(1);
			}
		}
		else
		{
			// Outgoing connection
			// Get hash value and list
			hash = packet->ip_dst.s_addr / 65536;
			list = w_globvars.conn_internet_out[hash];
			// Check if list has been created
			if (!Conn_isValidList(list, w_globvars.mutex_conn_internet_out)) {
				Conn_createList(&list, w_globvars.mutex_conn_internet_out, compareConnections);
				w_globvars.conn_internet_out[hash] = list;
			}
			// List is valid?
			if (!Conn_isValidList(list, w_globvars.mutex_conn_internet_out)) {
				fprintf(stderr,"addConnection: Internet outgoing list is not valid!!\n");
				exit(1);
			}
		}
	}
	else
	{
		// It is an intranet packet. Incoming or Outgoing ?
		if (incoming)
		{
			// Incoming connection
			// Get hash value and list
			hash = packet->ip_src.s_addr / 65536;
			list = w_globvars.conn_intranet_in[hash];
			// Check if list has been created
			if (!Conn_isValidList(list, w_globvars.mutex_conn_intranet_in)) {
				Conn_createList(&list, w_globvars.mutex_conn_intranet_in, compareConnections);
				w_globvars.conn_intranet_in[hash] = list;
			}
			// List is valid?
			if (!Conn_isValidList(list, w_globvars.mutex_conn_intranet_in)) {
				fprintf(stderr,"addConnection: Intranet incoming list is not valid!!\n");
				exit(1);
			}
		}
		else
		{
			// Outgoing connection
			// Get hash value and list
			hash = packet->ip_dst.s_addr / 65536;
			list = w_globvars.conn_intranet_out[hash];
			// Check if list has been created
			if (!Conn_isValidList(list, w_globvars.mutex_conn_intranet_out)) {
				Conn_createList(&list, w_globvars.mutex_conn_intranet_out, compareConnections);
				w_globvars.conn_intranet_out[hash] = list;
			}
			// List is valid?
			if (!Conn_isValidList(list, w_globvars.mutex_conn_intranet_out)) {
				fprintf(stderr,"addConnection: Intranet outgoing list is not valid!!\n");
				exit(1);
			}
		}
	}

	// SYN Flag ?
	syn = packet->ip_protocol == IPPROTO_TCP && (packet->shared_header.tcp_header.flags & TH_SYN) && !(packet->shared_header.tcp_header.flags & TH_ACK);

	new_info = (struct connection_info *) malloc(sizeof(struct connection_info));
	if (new_info == NULL) {
		fprintf(stderr,"addConnection: Could not allocate memory for connection info!!\n");
		exit(1);				
	}

	// Store IP Protocol
	new_info->ip_protocol = packet->ip_protocol;
	info_rev.ip_protocol = new_info->ip_protocol;

	// Store Source and Destination IP address and direction
	new_info->ip_src = packet->ip_src;
	new_info->ip_dst = packet->ip_dst;
	new_info->incoming = incoming;
	info_rev.ip_src = new_info->ip_dst;
	info_rev.ip_dst = new_info->ip_src;
	info_rev.incoming = !incoming;

	// Protocol?
	switch (packet->ip_protocol) {
		case IPPROTO_ICMP:
			// Store ICMP type and code
			new_info->shared_info.icmp_info.type = packet->shared_header.icmp_header.type;
			new_info->shared_info.icmp_info.code = packet->shared_header.icmp_header.code;
			break;
		case IPPROTO_TCP:
			// Store source and destination port, and TCP flags
			new_info->shared_info.tcp_info.sport = packet->shared_header.tcp_header.sport;
			new_info->shared_info.tcp_info.dport = packet->shared_header.tcp_header.dport;
			new_info->shared_info.tcp_info.flags = packet->shared_header.tcp_header.flags;
            new_info->shared_info.tcp_info.seq = packet->shared_header.tcp_header.seq;
            new_info->shared_info.tcp_info.ack = packet->shared_header.tcp_header.ack;
			info_rev.shared_info.tcp_info.sport = new_info->shared_info.tcp_info.dport;
			info_rev.shared_info.tcp_info.dport = new_info->shared_info.tcp_info.sport;
			src_port = new_info->shared_info.tcp_info.sport;
			dst_port = new_info->shared_info.tcp_info.dport;
			break;
		case IPPROTO_UDP:
			// Store source and destination port
			new_info->shared_info.udp_info.sport = packet->shared_header.udp_header.sport;
			new_info->shared_info.udp_info.dport = packet->shared_header.udp_header.dport;
			info_rev.shared_info.udp_info.sport = new_info->shared_info.udp_info.dport;
			info_rev.shared_info.udp_info.dport = new_info->shared_info.udp_info.sport;
			src_port = new_info->shared_info.udp_info.sport;
			dst_port = new_info->shared_info.udp_info.dport;
			break;	
	}

	// Connection (node list) exist?
	node = exclusiveFind_shared_sorted_list(list, new_info, NULL);

#ifdef DEBUG
	{
		char s_ip_src[INET_ADDRSTRLEN], s_ip_dst[INET_ADDRSTRLEN];
		u_int16_t sport, dport;
		char m[150];

		inet_ntop(AF_INET, &(new_info->ip_src), s_ip_src, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(new_info->ip_dst), s_ip_dst, INET_ADDRSTRLEN);
		switch (new_info->ip_protocol)
		{
			case IPPROTO_ICMP:
				sprintf(m, "%s Connection info: ICMP %u %s TO %s", s, new_info->shared_info.icmp_info.type, s_ip_src, s_ip_dst);
				break;
			case IPPROTO_TCP:
				sport = new_info->shared_info.tcp_info.sport;
				dport = new_info->shared_info.tcp_info.dport;
				sprintf(m, "%s Connection info: TCP  %s:%u TO %s:%u", s, s_ip_src, sport, s_ip_dst, dport);
				break;
			case IPPROTO_UDP:
				sport = new_info->shared_info.udp_info.sport;
				dport = new_info->shared_info.udp_info.dport;
				sprintf(m, "%s Connection info: UDP  %s:%u TO %s:%u", s, s_ip_src, sport, s_ip_dst, dport);
				break;
			default:
				sprintf(m, "%s Connection info: UNKNOWN PROTOCOL!!!!!", s);
				debugMessageModule(module_info, m, NULL, 1);
				exit(EXIT_FAILURE);
		}
		debugMessageModule(module_info, m, NULL, 1);
	}
#endif

	// New connection?
	if (node == NULL) 
	{

#ifdef DEBUG
		/***************************  DEBUG ****************************/
		{
			char m[150];

			sprintf(m, "%s Connection tracker: start new connection treatment...", s);
			debugMessageModule(module, m, NULL, 1);
		}
#endif
		// The connection is new.
// 		if (!incoming && packet->ip_protocol == IPPROTO_UDP && !(src_port >= 1024 && dst_port < 1024))
// 		{
// 			// This UDP connection is a candidate to be a client connection
// 			// This is a starting connection if there is not a relative
// 			// incoming connections (we are not responding to a previous incoming connection)
// 			// If we have recently start the monitor then we wait a while for
// 			// incoming connections until take a decision
// 			if (time(NULL) - c_globvars.monitor_started <= THRESHOLD_ESTABLISHED_CONNECTIONS) 
// 			{
// 				// Waiting por posible incoming connections. Discard UDP connection
// #ifdef DEBUG
// 				/***************************  DEBUG ****************************/
// 				{
// 					char m[150];

// 					sprintf(m, "%s Connection tracker: addConnection finished", s);
// 					debugMessageModule(module, m, NULL, 1);
// 				}
// #endif
// 				free(packet);
// 				free(new_info);
// 				return;				
// 			}
// 		}

 		// Initialize stats of new connection
		info = new_info;
		info->last_connections = NULL;
		init_double_list(&info->last_connections);
		info->hits = 0;
		info->total_bytes = 0;
		info->starting = 0;
		info->stablished = 0;
		info->relative_list = NULL;
		info->relative_node = NULL;
		info->nat_list = NULL;
		info->nat_node = NULL;
		info->pointed_by_relative = 0;
		info->pointed_by_nat = 0;
	}  // end of new connection
	else 
	{
#ifdef DEBUG
		/***************************  DEBUG ****************************/
		{
			char m[150];

			sprintf(m, "%s Connection tracker: Start existing connection treatment", s);
			debugMessageModule(module, m, NULL, 1);
		}
#endif

		// Connection already exists. Get its information
		info = (struct connection_info *) node->info;
		// Free new info
		free(new_info);

#if DEBUG > 4
		if (node->nprocs -1 != info->pointed_by_relative+info->pointed_by_nat)
		{
			fprintf(stderr, "\nNodo exist 1   nproc: %u  nat: %u  rel: %u\n", node->nprocs-1, info->pointed_by_nat, info->pointed_by_relative);
			exit(EXIT_FAILURE);
		}
#endif

		// Request write access
		if (!requestWriteNode_shared_sorted_list(node))
		{
			// Someone remove this node
			free(packet);
			// Leaving current node
			leaveNode_shared_sorted_list(list, node);
#ifdef DEBUG
			/***************************  DEBUG ****************************/
			{
				char m[150];

				sprintf(m, "%s Connection tracker: addConnection finished", s);
				debugMessageModule(module, m, NULL, 1);
			}
#endif
			return;
		}


		// Restarting a TCP connection ?
		if (syn) 
		{
			// TCP connection restarted. Remove all last connections			
			clear_all_double_list(info->last_connections, 1, NULL, NULL);
			info->total_bytes = 0;
			info->stablished = 0;
			info->starting = 1;
			leaveWriteNode_shared_sorted_list(node);

			if (!requestReadNode_shared_sorted_list(node))
			{
				// Someone remove this node
				free(packet);
				// Leaving current node
				leaveNode_shared_sorted_list(list, node);
				return;
			}
			
            // Remove relative connection if any
            if (info->relative_node != NULL && info->relative_list != NULL)
            {
#ifdef DEBUG
				/***************************  DEBUG ****************************/
				{
					char m[150];

					sprintf(m, "%s Connection tracker: Before request acces to relative connection...", s);
					debugMessageModule(module, m, NULL, 1);
				}
#endif
				if (requestAccessNode_shared_sorted_list(info->relative_list, info->relative_node))
				{
					leaveReadNode_shared_sorted_list(node);
					purge_connection(info->relative_list, info->relative_node);
#ifdef DEBUG
					/***************************  DEBUG ****************************/
					{
						char m[150];

						sprintf(m, "%s Connection tracker: After purge connection, requesting read access...", s);
						debugMessageModule(module, m, NULL, 1);
					}
#endif
					if (!requestReadNode_shared_sorted_list(node))
					{
						// Someone remove this node
						free(packet);
						// Leaving current node
						leaveNode_shared_sorted_list(list, node);
						return;
					}
				}
            }
			leaveReadNode_shared_sorted_list(node);
			if (!requestWriteNode_shared_sorted_list(node))
			{
				// Someone remove this node
				free(packet);
				// Leaving current node
				leaveNode_shared_sorted_list(list, node);
				return;
			}
		}


#if DEBUG > 4
		if (node->nprocs -1 != info->pointed_by_relative+info->pointed_by_nat)
		{
			fprintf(stderr, "\nNodo exist 2   nproc: %u  nat: %u  rel: %u\n", node->nprocs-1, info->pointed_by_nat, info->pointed_by_relative);
			exit(EXIT_FAILURE);
		}
#endif
	} // end of existing connection

#ifdef DEBUG
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "%s Connection tracker: Updating stats...", s);
		debugMessageModule(module, m, NULL, 1);
	}
#endif


	// One hit more
	info->hits++;

	// Store current time
	info->time = now;

	// Store priority
	info->priority = priority;

	// Add current size to totals
	info->total_bytes = info->total_bytes + packet->n_bytes;

	// Add current connection to last connections (to calculate bandwith)
	info_bandwidth = (struct connection_bandwidth *) malloc(sizeof(struct connection_bandwidth));
	if (info_bandwidth == NULL) {
		fprintf(stderr,"addConnection: Could not allocate memory for bandwidth info!!\n");
		exit(1);				
	}
	info_bandwidth->time = info->time;
	info_bandwidth->n_bytes = packet->n_bytes;
 	insert_tail_double_list(info->last_connections, (void *)info_bandwidth);

    // Free packet info
    free(packet);

	// Calculate bandwidth
	Conn_updateBandwidth(info, now);

	// Refresh the list of connections
	if (node == NULL) {
		// Insert the new connection in the list and request access to it
		node = insert_access_shared_sorted_list(list, info);
		if (!requestReadNode_shared_sorted_list(node))
		{
			// Someone remove this node
			// Leaving current node
			leaveNode_shared_sorted_list(list, node);
			return;
		}
	}
	else
	{
		// No more write access needed
		leaveWriteNode_shared_sorted_list(node);
		// Request read access
		if (!requestReadNode_shared_sorted_list(node))
		{
			// Someone remove this node
			// Leaving current node
			leaveNode_shared_sorted_list(list, node);
			return;
		}
	}


#if DEBUG > 4
	if (node->nprocs -1 != info->pointed_by_relative+info->pointed_by_nat)
	{
		fprintf(stderr, "\nNodo fusionado 1   nproc: %u  nat: %u  rel: %u\n", node->nprocs-1, info->pointed_by_nat, info->pointed_by_relative);
		exit(EXIT_FAILURE);
	}
#endif
	// UPDATING TRACKING INFORMATION
#ifdef DEBUG
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "%s Connection tracker: Before updating relative connections...", s);
		debugMessageModule(module, m, NULL, 1);
	}
#endif
	if (info->relative_node == NULL) 
	{
		leaveReadNode_shared_sorted_list(node);
		// We recheck if it is a a related connection
		if (incoming)
		{
			// Check if it is a respond of a previous outgoing connection
			checkForRelativeOutgoingConnection(internet, list, node, info, &info_rev, syn, src_port, dst_port);
		}
		else
		{
			// Check if it is a client connection
			checkForRelativeIncomingConnection(internet, list, node, info, &info_rev, syn, src_port, dst_port);
		}
		if (!requestReadNode_shared_sorted_list(node))
		{
			// Someone remove this node
			// Leaving current node
			leaveNode_shared_sorted_list(list, node);
			return;
		}
	}


#if DEBUG > 4
	if (node->nprocs -1 != info->pointed_by_relative+info->pointed_by_nat)
	{
		fprintf(stderr, "\nNodo fusionado 2   nproc: %u  nat: %u  rel: %u\n", node->nprocs-1, info->pointed_by_nat, info->pointed_by_relative);
		exit(EXIT_FAILURE);
	}
#endif
	if (info->nat_node == NULL)
	{
		leaveReadNode_shared_sorted_list(node);
		// Recheck if there is a relative NAT connection
		checkForRelativeNATConnection(internet, list, node, info);
		if (!requestReadNode_shared_sorted_list(node))
		{
			// Someone remove this node
			// Leaving current node
			leaveNode_shared_sorted_list(list, node);
			return;
		}
	}


#if DEBUG > 4
		if (node->nprocs -1 != info->pointed_by_relative+info->pointed_by_nat)
		{
			fprintf(stderr, "\nNodo fusionado 3   nproc: %u  nat: %u  rel: %u\n", node->nprocs-1, info->pointed_by_nat, info->pointed_by_relative);
			exit(EXIT_FAILURE);
		}
#endif
	// No more read access needed
	leaveReadNode_shared_sorted_list(node);

	// Leaving current node
	leaveNode_shared_sorted_list(list, node);


#if DEBUG > 4
		if (node->nprocs  != info->pointed_by_relative+info->pointed_by_nat)
		{
			fprintf(stderr, "\nNodo fusionado 4   nproc: %u  nat: %u  rel: %u\n", node->nprocs, info->pointed_by_nat, info->pointed_by_relative);
			exit(EXIT_FAILURE);
		}
#endif

#ifdef DEBUG
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "%s Connection tracker: addConnection finished", s);
		debugMessageModule(module, m, NULL, 1);
	}
#endif
}

void checkForRelativeOutgoingConnection(int internet, shared_sorted_list list, struct node_shared_sorted_list *node,
										struct connection_info *info, struct connection_info *info_rev,
										int syn, uint16_t src_port, uint16_t dst_port)
{
    u_int16_t hash2;
    shared_sorted_list list2;
	sem_t *mutex;
	struct connection_info *info_reverse;
	struct node_shared_sorted_list *node_reverse;
	int start;

#ifdef DEBUG
	int module, module_info;
	char s[9];

	if (internet) 
	{
		module = INTERNET_CONNECTIONS_TRACKER;
		module_info = INTERNET_CONNECTIONS_TRACKER_INFO;
		strcpy(s, "Internet");
	}
	else
	{
		module = INTRANET_CONNECTIONS_TRACKER;
		module_info = INTRANET_CONNECTIONS_TRACKER_INFO;
		strcpy(s, "Intranet");
	}
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "%s Connection tracker: checkForRelativeOutgoingConnection start...", s);
		debugMessageModule(module, m, NULL, 1);
	}
#endif

	if (!requestReadNode_shared_sorted_list(node))
	{
#ifdef DEBUG
		fprintf(stderr, "\ncheckForRelativeOutgoingConnection: ERROR 1\n");
		exit(EXIT_FAILURE);
#endif
		// Someone remove this node!!!!
		return;
	}

	if (info->ip_protocol == IPPROTO_ICMP) 
	{
		// TRACKING ICMP CONNECTIONS NOT YET IMPLEMENTED
		leaveReadNode_shared_sorted_list(node);
		return;
	}
	else 
	{
		// Recheck if there is a relative connection or not
		if (info->relative_node != NULL) 
		{
			// Someone else already fills the relative node
			leaveReadNode_shared_sorted_list(node);
			return;
		}

		// All incoming connections with src port >= 1024 and
		// dst port < 1024 are considered as client (starting)
		// connections
		start = syn || (src_port >= 1024 && dst_port < 1024);

		// Get the relative list
		node_reverse = NULL;
		info_reverse = NULL;
		//info_rev->incoming = 0;
		// Get hash value and list
		if (internet)
		{
			hash2 = info_rev->ip_dst.s_addr / 65536;
			list2 = w_globvars.conn_internet_out[hash2];
			mutex = &w_globvars.mutex_conn_internet_out;
		}
		else
		{
			hash2 = info_rev->ip_dst.s_addr / 65536;
			list2 = w_globvars.conn_intranet_out[hash2];
			mutex = &w_globvars.mutex_conn_intranet_out;
		}

		// Search for relative outgoing connection
		if (Conn_isValidList(list2, *mutex)) 
		{
			node_reverse = exclusiveFind_shared_sorted_list(list2, info_rev, NULL);
		}

		// Leave node read acess and request write access
		leaveReadNode_shared_sorted_list(node);
		if (!requestWriteNode_shared_sorted_list(node))
		{
			// Someone remove this node!!!!
			if (node_reverse != NULL)
			{
				leaveNode_shared_sorted_list(list2, node_reverse);
			}
#ifdef DEBUG
			fprintf(stderr, "\ncheckForRelativeOutgoingConnection: ERROR 2\n");
			exit(EXIT_FAILURE);
#endif
			return;
		}

		// Found it ?
		if (node_reverse != NULL)
		{
			// Yes. Updating its tracking information
			// Recheck if there is a relative connection or not
			if (info->relative_node != NULL) 
			{
				// Someone else already fills the relative node
				leaveNode_shared_sorted_list(list2, node_reverse);
				leaveWriteNode_shared_sorted_list(node);
				return;
			}

			// Get relative node info
			info_reverse = (struct connection_info *)node_reverse->info;

			// We also need write access to relative node
			// (to increment info->pointed_by_relative)
			if (requestWriteNode_shared_sorted_list(node_reverse))
			{ 
				// Relative node exists and can write to it
				// We can set relative info to node
				info_reverse->pointed_by_relative++;
				info_reverse->stablished = 1;
				if (start)
				{
					info_reverse->starting =  0;
				}
				info->relative_node = node_reverse;
				info->relative_list = list2;
				info->starting = start;
				info->stablished = 1; 
#ifdef DEBUG
				if (info_reverse->pointed_by_relative > 1)
				{
					char s_ip_src[INET_ADDRSTRLEN], s_ip_dst[INET_ADDRSTRLEN];
					char s_ip_src_reverse[INET_ADDRSTRLEN], s_ip_dst_reverse[INET_ADDRSTRLEN];
					u_int16_t sport, dport, sport_reverse, dport_reverse;

					inet_ntop(AF_INET, &(info->ip_src), s_ip_src, INET_ADDRSTRLEN);
					inet_ntop(AF_INET, &(info->ip_dst), s_ip_dst, INET_ADDRSTRLEN);
					inet_ntop(AF_INET, &(info_reverse->ip_src), s_ip_src_reverse, INET_ADDRSTRLEN);
					inet_ntop(AF_INET, &(info_reverse->ip_dst), s_ip_dst_reverse, INET_ADDRSTRLEN);
					switch (info->ip_protocol)
					{
						case IPPROTO_ICMP:
							fprintf(stderr, "\ncheckForRelativeOutgoingConnection: ERROR 3 - NODE ICMP %u %s TO %s ----> REV ICMP %u  %s TO %s\n", info->shared_info.icmp_info.type, s_ip_src, s_ip_dst, info_reverse->shared_info.icmp_info.type, s_ip_src_reverse, s_ip_dst_reverse);
							break;
						case IPPROTO_TCP:
							sport = info->shared_info.tcp_info.sport;
							dport = info->shared_info.tcp_info.dport;
							sport_reverse = info_reverse->shared_info.tcp_info.sport;
							dport_reverse = info_reverse->shared_info.tcp_info.dport;
							fprintf(stderr, "\ncheckForRelativeOutgoingConnection: ERROR 3 - NODE TCP  %s:%u TO %s:%u ----> REV TCP  %s:%u TO %s:%u\n", s_ip_src, sport, s_ip_dst, dport, s_ip_src_reverse, sport_reverse, s_ip_dst_reverse, dport_reverse);
							break;
						case IPPROTO_UDP:
							sport = info->shared_info.udp_info.sport;
							dport = info->shared_info.udp_info.dport;
							sport_reverse = info_reverse->shared_info.udp_info.sport;
							dport_reverse = info_reverse->shared_info.udp_info.dport;
							fprintf(stderr, "\ncheckForRelativeOutgoingConnection: ERROR 3 - NODE UDP  %s:%u TO %s:%u ----> REV UDP  %s:%u TO %s:%u\n", s_ip_src, sport, s_ip_dst, dport, s_ip_src_reverse, sport_reverse, s_ip_dst_reverse, dport_reverse);
							break;
					}
					exit(EXIT_FAILURE);
				}
#endif
				// Relative node has its relative info pointing to node?
				if (info_reverse->relative_node == NULL)
				{
					// No. We try to set relative info of relative node
					// We need one more access to this node
					if (requestAccessNode_shared_sorted_list(list, node))
					{
						// Relative info of relative node
						// must point to this node
						info_reverse->relative_node = node;
						info_reverse->relative_list = list;
						info->pointed_by_relative++;
#ifdef DEBUG
						if (info->pointed_by_relative > 1)
						{
							char s_ip_src[INET_ADDRSTRLEN], s_ip_dst[INET_ADDRSTRLEN];
							char s_ip_src_reverse[INET_ADDRSTRLEN], s_ip_dst_reverse[INET_ADDRSTRLEN];
							u_int16_t sport, dport, sport_reverse, dport_reverse;

							inet_ntop(AF_INET, &(info->ip_src), s_ip_src, INET_ADDRSTRLEN);
							inet_ntop(AF_INET, &(info->ip_dst), s_ip_dst, INET_ADDRSTRLEN);
							inet_ntop(AF_INET, &(info_reverse->ip_src), s_ip_src_reverse, INET_ADDRSTRLEN);
							inet_ntop(AF_INET, &(info_reverse->ip_dst), s_ip_dst_reverse, INET_ADDRSTRLEN);
							switch (info->ip_protocol)
							{
								case IPPROTO_ICMP:
									fprintf(stderr, "\ncheckForRelativeOutgoingConnection: ERROR 4 - REV ICMP %u %s TO %s ----> NODE ICMP %u  %s TO %s\n", info_reverse->shared_info.icmp_info.type, s_ip_src_reverse, s_ip_dst_reverse, info->shared_info.icmp_info.type, s_ip_src, s_ip_dst);
									break;
								case IPPROTO_TCP:
									sport = info->shared_info.tcp_info.sport;
									dport = info->shared_info.tcp_info.dport;
									sport_reverse = info_reverse->shared_info.tcp_info.sport;
									dport_reverse = info_reverse->shared_info.tcp_info.dport;
									fprintf(stderr, "\ncheckForRelativeOutgoingConnection: ERROR 4 - REV TCP  %s:%u TO %s:%u ----> NODE TCP  %s:%u TO %s:%u\n", s_ip_src_reverse, sport_reverse, s_ip_dst_reverse, dport_reverse, s_ip_src, sport, s_ip_dst, dport);
									break;
								case IPPROTO_UDP:
									sport = info->shared_info.udp_info.sport;
									dport = info->shared_info.udp_info.dport;
									sport_reverse = info_reverse->shared_info.udp_info.sport;
									dport_reverse = info_reverse->shared_info.udp_info.dport;
									fprintf(stderr, "\ncheckForRelativeOutgoingConnection: ERROR 4 - REV UDP  %s:%u TO %s:%u ----> NODE UDP  %s:%u TO %s:%u\n", s_ip_src_reverse, sport_reverse, s_ip_dst_reverse, dport_reverse, s_ip_src, sport, s_ip_dst, dport);
									break;
							}
							exit(EXIT_FAILURE);
						}
#endif
					}
				}
#if DEBUG > 4
				if (node_reverse->nprocs-1 != info_reverse->pointed_by_nat + info_reverse->pointed_by_relative)
				{
					fprintf(stderr, "\ncheckForRelativeOutgoingConnection: ERROR 5\n");
					exit(EXIT_FAILURE);
				}
#endif
				// Leave relative node write access 
				leaveWriteNode_shared_sorted_list(node_reverse);
			}
			else
			{
				// Relative node exists but can't access to relative node for writing.
				// Someone else want's to delete it
#ifdef DEBUG
				fprintf(stderr, "\ncheckForRelativeOutgoingConnection: ERROR 6\n");
				exit(EXIT_FAILURE);
#endif
				leaveNode_shared_sorted_list(list2, node_reverse);
				info->relative_node = NULL;
				info->relative_list = NULL;
				info->stablished = 0;
			}
		}
		else
		{
			// Relative node doesn't exist
#ifdef DEBUG
			if (info->pointed_by_relative)
			{
				// Error. Node is pointing to a non-existing relative node
				fprintf(stderr, "\ncheckForRelativeOutgoingConnection: ERROR 7\n");
				exit(EXIT_FAILURE);
			}
#endif
			// Reset relative NAT node info for node
			info->relative_node = NULL;
			info->relative_list = NULL;
			info->pointed_by_relative = 0;
			info->stablished = 0; 
			info->starting = 1;
		} 
#if DEBUG > 4
		if (node->nprocs-1 != info->pointed_by_nat + info->pointed_by_relative)
		{
			fprintf(stderr, "\ncheckForRelativeOutgoingConnection: ERROR 8\n");
			exit(EXIT_FAILURE);
		}
#endif
		// All done. Leave write access node
		leaveWriteNode_shared_sorted_list(node);
	}


#ifdef DEBUG
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "%s Connection tracker: checkForRelativeOutgoingConnection finished", s);
		debugMessageModule(module, m, NULL, 1);
	}
#endif

}

void checkForRelativeIncomingConnection(int internet, shared_sorted_list list, struct node_shared_sorted_list *node,
										struct connection_info *info, struct connection_info *info_rev, 
										int syn, uint16_t src_port, uint16_t dst_port)
{
    u_int16_t hash2;
    shared_sorted_list list2;
	sem_t *mutex;
	struct connection_info *info_reverse;
	struct node_shared_sorted_list *node_reverse;
	int start;

#ifdef DEBUG
	int module, module_info;
	char s[9];

	if (internet) 
	{
		module = INTERNET_CONNECTIONS_TRACKER;
		module_info = INTERNET_CONNECTIONS_TRACKER_INFO;
		strcpy(s, "Internet");
	}
	else
	{
		module = INTRANET_CONNECTIONS_TRACKER;
		module_info = INTRANET_CONNECTIONS_TRACKER_INFO;
		strcpy(s, "Intranet");
	}
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "%s Connection tracker: checkForRelativeIncomingConnection start...", s);
		debugMessageModule(module, m, NULL, 1);
	}
#endif

	if (!requestReadNode_shared_sorted_list(node))
	{
#ifdef DEBUG
		fprintf(stderr, "\ncheckForRelativeIncomingConnection: ERROR 1\n");
		exit(EXIT_FAILURE);
#endif
		// Someone remove this node!!!!
		return;
	}

	if (info->ip_protocol == IPPROTO_ICMP) 
	{
		// TRACKING ICMP CONNECTIONS NOT YET IMPLEMENTED
		leaveReadNode_shared_sorted_list(node);
		return;
	}
	else 
	{
		// Recheck if there is a relative connection or not
		if (info->relative_node != NULL) 
		{
			// Someone else already fills the relative node
			leaveReadNode_shared_sorted_list(node);
			return;
		}

		// All outgoing connections with src port >= 1024 and
		// dst port < 1024 are considered as client (starting)
		// connections
		start = syn || (src_port >= 1024 && dst_port < 1024);

		// Search for relative incoming connection
		node_reverse = NULL;
		info_reverse = NULL;
		//info_rev->incoming = 1;
		// Get hash value and list
		if (internet)
		{
			hash2 = info_rev->ip_src.s_addr / 65536;
			list2 = w_globvars.conn_internet_in[hash2];
			mutex = &w_globvars.mutex_conn_internet_in;
		}
		else
		{
			hash2 = info_rev->ip_src.s_addr / 65536;
			list2 = w_globvars.conn_intranet_in[hash2];
			mutex = &w_globvars.mutex_conn_intranet_in;
		}

		// Search for relative outgoing connection
		if (Conn_isValidList(list2, *mutex)) 
		{
			node_reverse = exclusiveFind_shared_sorted_list(list2, info_rev, NULL);
		}

		// Leave node read acess and request write access
		leaveReadNode_shared_sorted_list(node);
		if (!requestWriteNode_shared_sorted_list(node))
		{
			// Someone remove this node!!!!
			if (node_reverse != NULL)
			{
				leaveNode_shared_sorted_list(list2, node_reverse);
			}
#ifdef DEBUG
			fprintf(stderr, "\ncheckForRelativeIncomingConnection: ERROR 2\n");
			exit(EXIT_FAILURE);
#endif
			return;
		}

		// Found it ?
		if (node_reverse != NULL)
		{
			// Yes. Updating its tracking information
			// Recheck if there is a relative connection or not
			if (info->relative_node != NULL) 
			{
				// Someone else already fills the relative node
				leaveNode_shared_sorted_list(list2, node_reverse);
				leaveWriteNode_shared_sorted_list(node);
				return;
			}

			// Get relative node info
			info_reverse = (struct connection_info *)node_reverse->info;

			// We also need write access to relative node
			// (to increment info->pointed_by_relative)
			if (requestWriteNode_shared_sorted_list(node_reverse))
			{
				// Relative node exists and can write to it
				// We can set relative info to node
				info_reverse->pointed_by_relative++;
				info_reverse->stablished = 1;
				if (start)
				{
					info_reverse->starting =  0;
				}
				info->relative_node = node_reverse;
				info->relative_list = list2;
				info->starting = start;
				info->stablished = 1; 
#ifdef DEBUG
				if (info_reverse->pointed_by_relative > 1)
				{
					char s_ip_src[INET_ADDRSTRLEN], s_ip_dst[INET_ADDRSTRLEN];
					char s_ip_src_reverse[INET_ADDRSTRLEN], s_ip_dst_reverse[INET_ADDRSTRLEN];
					u_int16_t sport, dport, sport_reverse, dport_reverse;

					inet_ntop(AF_INET, &(info->ip_src), s_ip_src, INET_ADDRSTRLEN);
					inet_ntop(AF_INET, &(info->ip_dst), s_ip_dst, INET_ADDRSTRLEN);
					inet_ntop(AF_INET, &(info_reverse->ip_src), s_ip_src_reverse, INET_ADDRSTRLEN);
					inet_ntop(AF_INET, &(info_reverse->ip_dst), s_ip_dst_reverse, INET_ADDRSTRLEN);
					switch (info->ip_protocol)
					{
						case IPPROTO_ICMP:
							fprintf(stderr, "\ncheckForRelativeIncomingConnection: ERROR 3 - NODE ICMP %u %s TO %s ----> REV ICMP %u  %s TO %s\n", info->shared_info.icmp_info.type, s_ip_src, s_ip_dst, info_reverse->shared_info.icmp_info.type, s_ip_src_reverse, s_ip_dst_reverse);
							break;
						case IPPROTO_TCP:
							sport = info->shared_info.tcp_info.sport;
							dport = info->shared_info.tcp_info.dport;
							sport_reverse = info_reverse->shared_info.tcp_info.sport;
							dport_reverse = info_reverse->shared_info.tcp_info.dport;
							fprintf(stderr, "\ncheckForRelativeIncomingConnection: ERROR 3 - NODE TCP  %s:%u TO %s:%u ----> REV TCP  %s:%u TO %s:%u\n", s_ip_src, sport, s_ip_dst, dport, s_ip_src_reverse, sport_reverse, s_ip_dst_reverse, dport_reverse);
							break;
						case IPPROTO_UDP:
							sport = info->shared_info.udp_info.sport;
							dport = info->shared_info.udp_info.dport;
							sport_reverse = info_reverse->shared_info.udp_info.sport;
							dport_reverse = info_reverse->shared_info.udp_info.dport;
							fprintf(stderr, "\ncheckForRelativeIncomingConnection: ERROR 3 - NODE UDP  %s:%u TO %s:%u ----> REV UDP  %s:%u TO %s:%u\n", s_ip_src, sport, s_ip_dst, dport, s_ip_src_reverse, sport_reverse, s_ip_dst_reverse, dport_reverse);
							break;
					}
					exit(EXIT_FAILURE);
				}
#endif
				// Relative node has its relative info pointing to node?				
				if (info_reverse->relative_node == NULL)
				{
					// No. We try to set relative info of relative node
					// We need one more access to this node
					if (requestAccessNode_shared_sorted_list(list, node))
					{
						// Relative info of relative node
						// must point to this node
						info_reverse->relative_node = node;
						info_reverse->relative_list = list;
						info->pointed_by_relative++;
#ifdef DEBUG
						if (info->pointed_by_relative > 1)
						{
							char s_ip_src[INET_ADDRSTRLEN], s_ip_dst[INET_ADDRSTRLEN];
							char s_ip_src_reverse[INET_ADDRSTRLEN], s_ip_dst_reverse[INET_ADDRSTRLEN];
							u_int16_t sport, dport, sport_reverse, dport_reverse;

							inet_ntop(AF_INET, &(info->ip_src), s_ip_src, INET_ADDRSTRLEN);
							inet_ntop(AF_INET, &(info->ip_dst), s_ip_dst, INET_ADDRSTRLEN);
							inet_ntop(AF_INET, &(info_reverse->ip_src), s_ip_src_reverse, INET_ADDRSTRLEN);
							inet_ntop(AF_INET, &(info_reverse->ip_dst), s_ip_dst_reverse, INET_ADDRSTRLEN);
							switch (info->ip_protocol)
							{
								case IPPROTO_ICMP:
									fprintf(stderr, "\ncheckForRelativeIncomingConnection: ERROR 4 - REV ICMP %u %s TO %s ----> NODE ICMP %u  %s TO %s\n", info_reverse->shared_info.icmp_info.type, s_ip_src_reverse, s_ip_dst_reverse, info->shared_info.icmp_info.type, s_ip_src, s_ip_dst);
									break;
								case IPPROTO_TCP:
									sport = info->shared_info.tcp_info.sport;
									dport = info->shared_info.tcp_info.dport;
									sport_reverse = info_reverse->shared_info.tcp_info.sport;
									dport_reverse = info_reverse->shared_info.tcp_info.dport;
									fprintf(stderr, "\ncheckForRelativeIncomingConnection: ERROR 4 - REV TCP  %s:%u TO %s:%u ----> NODE TCP  %s:%u TO %s:%u\n", s_ip_src_reverse, sport_reverse, s_ip_dst_reverse, dport_reverse, s_ip_src, sport, s_ip_dst, dport);
									break;
								case IPPROTO_UDP:
									sport = info->shared_info.udp_info.sport;
									dport = info->shared_info.udp_info.dport;
									sport_reverse = info_reverse->shared_info.udp_info.sport;
									dport_reverse = info_reverse->shared_info.udp_info.dport;
									fprintf(stderr, "\ncheckForRelativeIncomingConnection: ERROR 4 - REV UDP  %s:%u TO %s:%u ----> NODE UDP  %s:%u TO %s:%u\n", s_ip_src_reverse, sport_reverse, s_ip_dst_reverse, dport_reverse, s_ip_src, sport, s_ip_dst, dport);
									break;
							}
							exit(EXIT_FAILURE);
						}
#endif
					}
				}
#if DEBUG > 4
				if (node_reverse->nprocs-1 != info_reverse->pointed_by_nat + info_reverse->pointed_by_relative)
				{
					fprintf(stderr, "\ncheckForRelativeIncomingConnection: ERROR 5\n");
					exit(EXIT_FAILURE);
				}
#endif
				// Leave relative node write access 
				leaveWriteNode_shared_sorted_list(node_reverse);
			}
			else
			{
				// Relative node exists but can't access to relative node for writing.
				// Someone else want's to delete it
#ifdef DEBUG
				fprintf(stderr, "\ncheckForRelativeIncomingConnection: ERROR 6\n");
				exit(EXIT_FAILURE);
#endif
				leaveNode_shared_sorted_list(list2, node_reverse);
				info->relative_node = NULL;
				info->relative_list = NULL;
				info->stablished = 0;
			}
		}
		else
		{
			// Relative node doesn't exist
#ifdef DEBUG
			if (info->pointed_by_relative)
			{
				// Error. Node is pointing to a non-existing relative node
				fprintf(stderr, "\ncheckForRelativeIncomingConnection: ERROR 7\n");
				exit(EXIT_FAILURE);
			}
#endif
			// Reset relative NAT node info for node
			info->relative_node = NULL;
			info->relative_list = NULL;
			info->pointed_by_relative = 0;
			info->stablished = 0; 
			info->starting = 1;
		}
#if DEBUG > 4
	if (node->nprocs-1 != info->pointed_by_nat + info->pointed_by_relative)
	{
		fprintf(stderr, "\ncheckForRelativeIncomingConnection: ERROR 8\n");
		exit(EXIT_FAILURE);
	}
#endif
		// All done. Leave write access node
		leaveWriteNode_shared_sorted_list(node);
	}

#ifdef DEBUG
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "%s Connection tracker: checkForRelativeIncomingConnection finished", s);
		debugMessageModule(module, m, NULL, 1);
	}
#endif
}

void checkForRelativeNATConnection(int internet, shared_sorted_list list, struct node_shared_sorted_list *node,
								   struct connection_info *info)
{
    u_int16_t hash2;
    shared_sorted_list list2;
	sem_t *mutex;
	struct connection_info *info_NAT;
	struct node_shared_sorted_list *node_NAT;

#ifdef DEBUG
	int module, module_info;
	char s[9];

	if (internet) 
	{
		module = INTERNET_CONNECTIONS_TRACKER;
		module_info = INTERNET_CONNECTIONS_TRACKER_INFO;
		strcpy(s, "Internet");
	}
	else
	{
		module = INTRANET_CONNECTIONS_TRACKER;
		module_info = INTRANET_CONNECTIONS_TRACKER_INFO;
		strcpy(s, "Intranet");
	}
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "%s Connection tracker: checkForRelativeNATConnection start...", s);
		debugMessageModule(module, m, NULL, 1);
	}
#endif

	if (internet && c_globvars.intranet_dev == NULL)
	{
#ifdef DEBUG
		/***************************  DEBUG ****************************/
		{
			char m[150];

			sprintf(m, "%s Connection tracker: checkForRelativeNATConnection finished", s);
			debugMessageModule(module, m, NULL, 1);
		}
#endif

		return;
	}

	if (!requestReadNode_shared_sorted_list(node))
	{
#ifdef DEBUG
		fprintf(stderr, "\ncheckForRelativeNATConnection: ERROR 1\n");
		exit(EXIT_FAILURE);
#endif
		// Someone remove this node!!!!
		return;
	}

	if (info->ip_protocol == IPPROTO_ICMP) 
	{
		// NAT ICMP CONNECTIONS NOT YET IMPLEMENTED
#ifdef DEBUG
		/***************************  DEBUG ****************************/
		{
			char m[150];

			sprintf(m, "%s Connection tracker: checkForRelativeNATConnection finished", s);
			debugMessageModule(module, m, NULL, 1);
		}
#endif
		leaveReadNode_shared_sorted_list(node);
		return;
	}

	// Recheck if there is a relative NAT connection or not
	if (info->nat_node != NULL) 
	{
		// Someone else already fills the relative NAT node
		leaveReadNode_shared_sorted_list(node);
		return;
	}

	// Get the relative list
	node_NAT = NULL;
	info_NAT = NULL;
	if (internet)
	{
		if (info->incoming)
		{
			// Incoming packet
			hash2 = info->ip_src.s_addr / 65536;
			list2 = w_globvars.conn_intranet_in[hash2];
			mutex = &w_globvars.mutex_conn_intranet_in;
		}
		else 
		{
			// Outgoing packet
			hash2 = info->ip_dst.s_addr / 65536;
			list2 = w_globvars.conn_intranet_out[hash2];
			mutex = &w_globvars.mutex_conn_intranet_out;
		}
	}
	else
	{
		if (info->incoming)
		{
			// Incoming packet
			hash2 = info->ip_src.s_addr / 65536;
			list2 = w_globvars.conn_internet_in[hash2];
			mutex = &w_globvars.mutex_conn_internet_in;
		}
		else 
		{
			// Outgoing packet
			hash2 = info->ip_dst.s_addr / 65536;
			list2 = w_globvars.conn_internet_out[hash2];
			mutex = &w_globvars.mutex_conn_internet_out;
		}
	}

	// Search relative NAT connection
	if (Conn_isValidList(list2, *mutex)) 
	{
		node_NAT = exclusiveFind_shared_sorted_list(list2, info, compareNAT);
	}

	// Leave node read acess and request write access
	leaveReadNode_shared_sorted_list(node);
	if (!requestWriteNode_shared_sorted_list(node))
	{
		// Someone remove this node!!!!
		if (node_NAT != NULL)
		{
			leaveNode_shared_sorted_list(list2, node_NAT);
		}
#ifdef DEBUG
		fprintf(stderr, "\ncheckForRelativeNATConnection: ERROR 2\n");
		exit(EXIT_FAILURE);
#endif
		return;
	}

	// Found it?
	if (node_NAT != NULL)
	{
		// Yes. Updating its tracking information
		// Recheck if there is a relative NAT connection or not
		if (info->nat_node != NULL) 
		{
			// Someone else already fills the relative NAT node
			leaveNode_shared_sorted_list(list2, node_NAT);
			leaveWriteNode_shared_sorted_list(node);
			return;
		}

		// Get relative NAT node info
		info_NAT = (struct connection_info *)node_NAT->info;

		// We also need write access to relative NAT node
		// (to increment info_NAT->pointed_by_nat)
		if (requestWriteNode_shared_sorted_list(node_NAT))
		{
			// Relative NAT node exists and can write to it
			// We can set relative info to node
			info_NAT->pointed_by_nat++;
			info->nat_node = node_NAT;
			info->nat_list = list2;
#ifdef DEBUG
			if (info_NAT->pointed_by_nat > 1)
			{
				char s_ip_src[INET_ADDRSTRLEN], s_ip_dst[INET_ADDRSTRLEN];
				char s_ip_src_NAT[INET_ADDRSTRLEN], s_ip_dst_NAT[INET_ADDRSTRLEN];
				u_int16_t sport, dport, sport_NAT, dport_NAT;

				inet_ntop(AF_INET, &(info->ip_src), s_ip_src, INET_ADDRSTRLEN);
				inet_ntop(AF_INET, &(info->ip_dst), s_ip_dst, INET_ADDRSTRLEN);
				inet_ntop(AF_INET, &(info_NAT->ip_src), s_ip_src_NAT, INET_ADDRSTRLEN);
				inet_ntop(AF_INET, &(info_NAT->ip_dst), s_ip_dst_NAT, INET_ADDRSTRLEN);
				switch (info->ip_protocol)
				{
					case IPPROTO_ICMP:
						fprintf(stderr, "\ncheckForRelativeNATConnection: ERROR 3 - NODE ICMP %u %s TO %s ----> NAT ICMP %u  %s TO %s\n", info->shared_info.icmp_info.type, s_ip_src, s_ip_dst, info_NAT->shared_info.icmp_info.type, s_ip_src_NAT, s_ip_dst_NAT);
						break;
					case IPPROTO_TCP:
						sport = info->shared_info.tcp_info.sport;
						dport = info->shared_info.tcp_info.dport;
						sport_NAT = info_NAT->shared_info.tcp_info.sport;
						dport_NAT = info_NAT->shared_info.tcp_info.dport;
						fprintf(stderr, "\ncheckForRelativeNATConnection: ERROR 3 - NODE TCP  %s:%u TO %s:%u ----> NAT TCP  %s:%u TO %s:%u\n", s_ip_src, sport, s_ip_dst, dport, s_ip_src_NAT, sport_NAT, s_ip_dst_NAT, dport_NAT);
						break;
					case IPPROTO_UDP:
						sport = info->shared_info.udp_info.sport;
						dport = info->shared_info.udp_info.dport;
						sport_NAT = info_NAT->shared_info.udp_info.sport;
						dport_NAT = info_NAT->shared_info.udp_info.dport;
						fprintf(stderr, "\ncheckForRelativeNATConnection: ERROR 3 - NODE UDP  %s:%u TO %s:%u ----> NAT UDP  %s:%u TO %s:%u\n", s_ip_src, sport, s_ip_dst, dport, s_ip_src_NAT, sport_NAT, s_ip_dst_NAT, dport_NAT);
						break;
				}
				exit(EXIT_FAILURE);
			}
#endif
			
			// Relative NAT node has its relative info pointing to node?
			if (info_NAT->nat_node == NULL)			
			{
				// No. We try to set relative info of relative NAT node
				// We need one more access to this node
				if (requestAccessNode_shared_sorted_list(list, node))
				{
					// Relative NAT info of relative NAT node
					// must point to this node
					info_NAT->nat_node = node;
					info_NAT->nat_list = list;
					info->pointed_by_nat++;
#ifdef DEBUG
					if (info->pointed_by_nat > 1)
					{
						char s_ip_src[INET_ADDRSTRLEN], s_ip_dst[INET_ADDRSTRLEN];
						char s_ip_src_NAT[INET_ADDRSTRLEN], s_ip_dst_NAT[INET_ADDRSTRLEN];
						u_int16_t sport, dport, sport_NAT, dport_NAT;

						inet_ntop(AF_INET, &(info->ip_src), s_ip_src, INET_ADDRSTRLEN);
						inet_ntop(AF_INET, &(info->ip_dst), s_ip_dst, INET_ADDRSTRLEN);
						inet_ntop(AF_INET, &(info_NAT->ip_src), s_ip_src_NAT, INET_ADDRSTRLEN);
						inet_ntop(AF_INET, &(info_NAT->ip_dst), s_ip_dst_NAT, INET_ADDRSTRLEN);
						switch (info->ip_protocol)
						{
							case IPPROTO_ICMP:
								fprintf(stderr, "\ncheckForRelativeNATConnection: ERROR 4 - NAT ICMP %u %s TO %s ----> NODE ICMP %u  %s TO %s\n", info_NAT->shared_info.icmp_info.type, s_ip_src_NAT, s_ip_dst_NAT, info->shared_info.icmp_info.type, s_ip_src, s_ip_dst);
								break;
							case IPPROTO_TCP:
								sport = info->shared_info.tcp_info.sport;
								dport = info->shared_info.tcp_info.dport;
								sport_NAT = info_NAT->shared_info.tcp_info.sport;
								dport_NAT = info_NAT->shared_info.tcp_info.dport;
								fprintf(stderr, "\ncheckForRelativeNATConnection: ERROR 4 - NAT TCP  %s:%u TO %s:%u ----> NODE TCP  %s:%u TO %s:%u\n", s_ip_src_NAT, sport_NAT, s_ip_dst_NAT, dport_NAT, s_ip_src, sport, s_ip_dst, dport);
								break;
							case IPPROTO_UDP:
								sport = info->shared_info.udp_info.sport;
								dport = info->shared_info.udp_info.dport;
								sport_NAT = info_NAT->shared_info.udp_info.sport;
								dport_NAT = info_NAT->shared_info.udp_info.dport;
								fprintf(stderr, "\ncheckForRelativeNATConnection: ERROR 4 - NAT UDP  %s:%u TO %s:%u ----> NODE UDP  %s:%u TO %s:%u\n", s_ip_src_NAT, sport_NAT, s_ip_dst_NAT, dport_NAT, s_ip_src, sport, s_ip_dst, dport);
								break;
						}
						exit(EXIT_FAILURE);
					}
#endif
				}
			}
#if DEBUG > 4
			if (node_NAT->nprocs != info_NAT->pointed_by_nat + info_NAT->pointed_by_relative)
			{
				fprintf(stderr, "\ncheckForRelativeNATConnection: ERROR 5\n");
				exit(EXIT_FAILURE);
			}
#endif
			// Leave NAT node write access 
			leaveWriteNode_shared_sorted_list(node_NAT);
		}
		else
		{
			// Relative NAT node exists but can't access to relative NAT node for writing.
			// Someone else want's to delete it
#ifdef DEBUG
			fprintf(stderr, "\ncheckForRelativeNATConnection: ERROR 6\n");
			exit(EXIT_FAILURE);
#endif
			leaveNode_shared_sorted_list(list2, node_NAT);
			info->nat_node = NULL;
			info->nat_list = NULL;
		}
	}
	else
	{
		// Relative NAT node doesn't exist
#ifdef DEBUG
		if (info->pointed_by_nat)
		{
			// Error. Node is pointing to a non-existing relative NAT node
			fprintf(stderr, "\ncheckForRelativeNATConnection: ERROR 7\n");
			exit(EXIT_FAILURE);
		}
#endif
		// Reset relative NAT node info for node
		info->nat_node = NULL;
		info->nat_list = NULL;
		info->pointed_by_nat = 0;
	}

#if DEBUG > 4
	if (node->nprocs-1 != info->pointed_by_nat + info->pointed_by_relative)
	{
		fprintf(stderr, "\ncheckForRelativeNATConnection: ERROR 8  nproc: %u  nat: %u  rel: %u\n", node->nprocs-1, info->pointed_by_nat, info->pointed_by_relative);
		exit(EXIT_FAILURE);
	}
#endif

	// All done. Leave write access node
	leaveWriteNode_shared_sorted_list(node);

#ifdef DEBUG
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "%s Connection tracker: checkForRelativeNATConnection finished", s);
		debugMessageModule(module, m, NULL, 1);
	}
#endif
}

void Conn_updateBandwidth(struct connection_info *info, time_t now) {
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
		for_each_double_list(info->last_connections, Conn_accumulateBytes, (void *)&total_bytes);

		info->bandwidth = (float)total_bytes / (1024.0 * (now - t + 1));
	}
	else {
		info->bandwidth = 0.0;
	}
}

void Conn_accumulateBytes(void *val, void *total) {
	*(unsigned long *)total += ((struct connection_bandwidth *)val)->n_bytes;
}

int Conn_isValidList(shared_sorted_list list, sem_t mutex) {
	int ret;

	if (sem_wait(&mutex)) 
	{
		perror("CONN_isValidList: sem_wait with mutex list");
		exit(1);
	}
	ret = list != NULL;
	if (sem_post(&mutex))
	{
		perror("CONN_isValidList: sem_post with mutex list");
		exit(1);		
	}

	return ret;
}

void Conn_createList(shared_sorted_list *list, sem_t mutex, int (*compare)(void *, void*) ) {
	if (sem_wait(&mutex)) 
	{
		perror("CONN_createList: sem_wait with mutex list");
		exit(1);
	}
	init_shared_sorted_list(list, compare);
	if (sem_post(&mutex))
	{
		perror("CONN_createList: sem_post with mutex list");
		exit(1);		
	}
}

int compareConnections(void *data1, void *data2)
{
    struct connection_info *conn1, *conn2;
    uint32_t address1, address2;
    uint32_t another_address1, another_address2;

    // Get both connections info
    conn1 = (struct connection_info *)data1;
    conn2 = (struct connection_info *)data2;

    // Is an incoming or outgoing connection?
    if (conn1->incoming)
    {
        // Incoming. Compare source address in host order
        address1 = ntohl(conn1->ip_src.s_addr);
        address2 = ntohl(conn2->ip_src.s_addr);
        another_address1 = ntohl(conn1->ip_dst.s_addr);
        another_address2 = ntohl(conn2->ip_dst.s_addr);        
   }
    else
    {
        // Outgoing. Compare destination address in host order
        address1 = ntohl(conn1->ip_dst.s_addr);
        address2 = ntohl(conn2->ip_dst.s_addr);
        another_address1 = ntohl(conn1->ip_src.s_addr);
        another_address2 = ntohl(conn2->ip_src.s_addr);
    }

    if (address1 < address2)
    {
        return -1;
    }

    if (address1 == address2)
    {
        if (conn1->ip_protocol < conn2->ip_protocol)
            return -1;
        if (conn1->ip_protocol > conn2->ip_protocol)
            return 1;

        // Protocol?
        switch (conn1->ip_protocol) {
            case IPPROTO_ICMP:
                if (conn1->shared_info.icmp_info.type < conn2->shared_info.icmp_info.type)
                    return -1;
                if (conn1->shared_info.icmp_info.type > conn2->shared_info.icmp_info.type)
                    return 1;
                break;
            case IPPROTO_TCP:            
                if (conn1->shared_info.tcp_info.dport < conn2->shared_info.tcp_info.dport)
                    return -1;
                if (conn1->shared_info.tcp_info.dport > conn2->shared_info.tcp_info.dport)
                    return 1;

                if (conn1->shared_info.tcp_info.sport < conn2->shared_info.tcp_info.sport)
                    return -1;
                if (conn1->shared_info.tcp_info.sport > conn2->shared_info.tcp_info.sport)
                    return 1;
                break;
            case IPPROTO_UDP:
                if (conn1->shared_info.udp_info.dport < conn2->shared_info.udp_info.dport)
                    return -1;
                if (conn1->shared_info.udp_info.dport > conn2->shared_info.udp_info.dport)
                    return 1;

                if (conn1->shared_info.udp_info.sport < conn2->shared_info.udp_info.sport)
                    return -1;
                if (conn1->shared_info.udp_info.sport > conn2->shared_info.udp_info.sport)
                    return 1;
                break;	
        }

        if (another_address1 < another_address2)
        {
            return -1;
        }

        if (another_address1 == another_address2)
        {
            return 0;
        }
    }

    return 1;
}

int compareNAT(void *data1, void *data2)
{
    struct connection_info *conn1, *conn2;
    uint32_t address1, address2;

    // Get both connections info
    conn1 = (struct connection_info *)data1;
    conn2 = (struct connection_info *)data2;

    // Is an incoming or outgoing connection?
    if (conn1->incoming)
    {
        // Incoming. Compare source address in host order
        address1 = ntohl(conn1->ip_src.s_addr);
        address2 = ntohl(conn2->ip_src.s_addr);
   }
    else
    {
        // Outgoing. Compare destination address in host order
        address1 = ntohl(conn1->ip_dst.s_addr);
        address2 = ntohl(conn2->ip_dst.s_addr);
    }

    if (address1 < address2)
    {
        return -1;
    }

    if (address1 == address2)
    {
        if (conn1->ip_protocol < conn2->ip_protocol)
            return -1;
        if (conn1->ip_protocol > conn2->ip_protocol)
            return 1;

        // Protocol?
        switch (conn1->ip_protocol) {
            case IPPROTO_ICMP:
                if (conn1->shared_info.icmp_info.type < conn2->shared_info.icmp_info.type)
                    return -1;
                if (conn1->shared_info.icmp_info.type > conn2->shared_info.icmp_info.type)
                    return 1;
                break;
            case IPPROTO_TCP:            
                if (conn1->shared_info.tcp_info.dport < conn2->shared_info.tcp_info.dport)
                    return -1;
                if (conn1->shared_info.tcp_info.dport > conn2->shared_info.tcp_info.dport)
                    return 1;

                if (conn1->shared_info.tcp_info.sport < conn2->shared_info.tcp_info.sport)
                    return -1;
                if (conn1->shared_info.tcp_info.sport > conn2->shared_info.tcp_info.sport)
                    return 1;
                break;
            case IPPROTO_UDP:
                if (conn1->shared_info.udp_info.dport < conn2->shared_info.udp_info.dport)
                    return -1;
                if (conn1->shared_info.udp_info.dport > conn2->shared_info.udp_info.dport)
                    return 1;

                if (conn1->shared_info.udp_info.sport < conn2->shared_info.udp_info.sport)
                    return -1;
                if (conn1->shared_info.udp_info.sport > conn2->shared_info.udp_info.sport)
                    return 1;
                break;	
        }

        return 0;
    }

    return 1;
}
