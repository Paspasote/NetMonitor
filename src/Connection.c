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
int internetConnections();
int intranetConnections();
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
	int count;

	while (1)
	{
		// Get internet connections
        count = internetConnections();

		if (c_globvars.intranet_dev != NULL)
		{
			// Get intranet connections
			count = count + intranetConnections();
		}
		// Any packet got?
		if (!count)
		{
			// No. Buffers were empty. Wait a moment
			sleep(1);
		}
	}

    fprintf(stderr, "CONNECTION TRACKER THREAD HAS FINISHED!!!!!!!!\n");
	exit(1);
}

int internetConnections()
{
    struct info_packet *packet;

#if DEBUG > 1
	/***************************  DEBUG ****************************/
	{
		char m[255];

		sprintf(m, "Connection tracker: internetConnections start...           ");
		debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
	}
#endif

    // Get one internet packet
    packet = PL_getPacket(1);
    // Got any?
    if (packet == NULL) return 0;

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

#if DEBUG > 1
	/***************************  DEBUG ****************************/
	{
		char m[255];

		sprintf(m, "Connection tracker: internetConnections finished           ");
		debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
	}
#endif
	return 1;
}

int intranetConnections()
{
    struct info_packet *packet;

#if DEBUG > 1
	/***************************  DEBUG ****************************/
	{
		char m[255];

		sprintf(m, "Connection tracker: intranetConnections start...           ");
		debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
	}
#endif

    // Get one intranet packet
    packet = PL_getPacket(0);
    // Got any?
    if (packet == NULL) return 0;

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

#if DEBUG > 1
	/***************************  DEBUG ****************************/
	{
		char m[255];

		sprintf(m, "Connection tracker: intranetConnections finished                                         ");
		debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
	}
#endif
	return 1;
}


void incomingConnection(int internet, struct info_packet *packet)
{
    int priority;
   	unsigned single_port;

#if DEBUG > 1
	/***************************  DEBUG ****************************/
	{
		char m[255];

		sprintf(m, "Connection tracker: incomingConnection start...            ");
		debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
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
#if DEBUG > 1
		/***************************  DEBUG ****************************/
		{
			char m[255];

			sprintf(m, "Connection tracker: incomingConnection finished        ");
			debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
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
#if DEBUG > 1
		/***************************  DEBUG ****************************/
		{
			char m[255];

			sprintf(m, "Connection tracker: incomingConnection finished        ");
			debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
		}
#endif
		return;
	}

    addConnection(internet, 1, packet, priority);

#if DEBUG > 1
	/***************************  DEBUG ****************************/
	{
		char m[255];

		sprintf(m, "Connection tracker: incomingConnection finished            ");
		debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
	}
#endif
}

void outgoingConnection(int internet, struct info_packet *packet)
{
    int priority;
   	unsigned single_port;

#if DEBUG > 1
	/***************************  DEBUG ****************************/
	{
		char m[255];

		sprintf(m, "Connection tracker: outgoingConnection start...            ");
		debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
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
#if DEBUG > 1
		/***************************  DEBUG ****************************/
		{
			char m[255];

			sprintf(m, "Connection tracker: outgoingConnection finished        ");
			debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
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
#if DEBUG > 1
		/***************************  DEBUG ****************************/
		{
			char m[255];

			sprintf(m, "Connection tracker: outgoingConnection finished        ");
			debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
		}
#endif
		return;
	}

    addConnection(internet, 0, packet, priority);
#if DEBUG > 1
	/***************************  DEBUG ****************************/
	{
		char m[255];

		sprintf(m, "Connection tracker: outgoingConnection finished            ");
		debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
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


#if DEBUG > 1
		/***************************  DEBUG ****************************/
		{
			char m[255];

			sprintf(m, "Connection tracker: addConnection start...             ");
			debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
		}
#endif

    // Get current time
	now = time(NULL);

	// Internet or intranet packet ?
	if (internet)
	{
		// Incoming or Outgoing ?
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
		// Incoming or Outgoing ?
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

#if DEBUG > 1
	{
		char s_ip_src[INET_ADDRSTRLEN], s_ip_dst[INET_ADDRSTRLEN];
		u_int16_t sport, dport;
		char m[255];

		inet_ntop(AF_INET, &(new_info->ip_src), s_ip_src, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(new_info->ip_dst), s_ip_dst, INET_ADDRSTRLEN);
		switch (new_info->ip_protocol)
		{
			case IPPROTO_ICMP:
				sprintf(m, "ICMP %u %s TO %s          ", new_info->shared_info.icmp_info.type, s_ip_src, s_ip_dst);
				break;
			case IPPROTO_TCP:
				sport = new_info->shared_info.tcp_info.sport;
				dport = new_info->shared_info.tcp_info.dport;
				sprintf(m, "TCP  %s:%u TO %s:%u        ", s_ip_src, sport, s_ip_dst, dport);
				break;
			case IPPROTO_UDP:
				sport = new_info->shared_info.udp_info.sport;
				dport = new_info->shared_info.udp_info.dport;
				sprintf(m, "UDP  %s:%u TO %s:%u        ", s_ip_src, sport, s_ip_dst, dport);
				break;
			default:
				sprintf(m, "UNKNOWN PROTOCOL!!!!!");
				debugMessageXY(TRACKER_INFO_CONN_ROW, TRACKER_INFO_CONN_COL, m, NULL, 1);
				exit(EXIT_FAILURE);
		}
		debugMessageXY(TRACKER_INFO_CONN_ROW, TRACKER_INFO_CONN_COL, m, NULL, 1);
	}
#endif

	// New connection?
	if (node == NULL) 
	{

#if DEBUG > 1
		/***************************  DEBUG ****************************/
		{
			char m[255];

			sprintf(m, "Connection tracker: start new connection treatment...  ");
			debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
		}
#endif
		// The connection is new.
		if (!incoming && packet->ip_protocol == IPPROTO_UDP && !(src_port >= 1024 && dst_port < 1024))
		{
			// This UDP connection is a candidate to be a client connection
			// This is a starting connection if there is not a relative
			// incoming connections (we are not responding to a previous incoming connection)
			// If we have recently start the monitor then we wait a while for
			// incoming connections until take a decision
			if (time(NULL) - c_globvars.monitor_started <= THRESHOLD_ESTABLISHED_CONNECTIONS) {
				// Waiting por posible incoming connections. Discard UDP connection
#if DEBUG > 1
				/***************************  DEBUG ****************************/
				{
					char m[255];

					sprintf(m, "Connection tracker: addConnection finished             ");
					debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
				}
#endif
				free(packet);
				free(new_info);
				return;				
			}
		}

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
	}
	else 
	{
#if DEBUG > 1
		/***************************  DEBUG ****************************/
		{
			char m[255];

			sprintf(m, "Connection tracker: Start existing connection treatment");
			debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
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
#if DEBUG > 1
			/***************************  DEBUG ****************************/
			{
				char m[255];

				sprintf(m, "Connection tracker: addConnection finished              ");
				debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
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
#if DEBUG > 1
				/***************************  DEBUG ****************************/
				{
					char m[255];

					sprintf(m, "Connection tracker: Before request acces to relative connection... ");
					debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
				}
#endif
				if (requestAccessNode_shared_sorted_list(info->relative_list, info->relative_node))
				{
					leaveReadNode_shared_sorted_list(node);
					purge_connection(info->relative_list, info->relative_node);
#if DEBUG > 1
					/***************************  DEBUG ****************************/
					{
						char m[255];

						sprintf(m, "Connection tracker: After purge connection, requesting read access...");
						debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
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
	}

#if DEBUG > 1
	/***************************  DEBUG ****************************/
	{
		char m[255];

		sprintf(m, "Connection tracker: Updating stats...                      ");
		debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
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
#if DEBUG > 1
	/***************************  DEBUG ****************************/
	{
		char m[255];

		sprintf(m, "Connection tracker: Before updating relative connections...          ");
		debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
	}
#endif
	if (info->relative_node == NULL) {
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

#if DEBUG > 1
	/***************************  DEBUG ****************************/
	{
		char m[255];

		sprintf(m, "Connection tracker: addConnection finished             ");
		debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
	}
#endif
}

void checkForRelativeOutgoingConnection(int internet, shared_sorted_list list, struct node_shared_sorted_list *node,
										struct connection_info *info, struct connection_info *info_rev,
										int syn, uint16_t src_port, uint16_t dst_port)
{
    u_int16_t hash2;
    shared_sorted_list list2;
	struct connection_info *info_reverse;
	struct node_shared_sorted_list *node_reverse;
	int start;

#if DEBUG > 1
	/***************************  DEBUG ****************************/
	{
		char m[255];

		sprintf(m, "Connection tracker: checkForRelativeOutgoingConnection start...  ");
		debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
	}
#endif

	if (info->ip_protocol == IPPROTO_ICMP) 
	{
		// TRACKING ICMP CONNECTIONS NOT YET IMPLEMENTED
		return;
	}
	else 
	{
		// All incoming connections with src port >= 1024 and
		// dst port < 1024 are considered as client (starting)
		// connections
		start = syn || (src_port >= 1024 && dst_port < 1024);

		// Search for relative outgoing connection
		node_reverse = NULL;
		info_reverse = NULL;
		info_rev->incoming = 0;
		// Get hash value and list
		if (internet)
		{
			hash2 = info_rev->ip_dst.s_addr / 65536;
			list2 = w_globvars.conn_internet_out[hash2];
			if (Conn_isValidList(list2, w_globvars.mutex_conn_internet_out)) 
			{
				node_reverse = exclusiveFind_shared_sorted_list(list2, info_rev, NULL);
			}
		}
		else
		{
			hash2 = info_rev->ip_dst.s_addr / 65536;
			list2 = w_globvars.conn_intranet_out[hash2];
			if (Conn_isValidList(list2, w_globvars.mutex_conn_intranet_out)) 
			{
				node_reverse = exclusiveFind_shared_sorted_list(list2, info_rev, NULL);
			}
		}

		if (!requestWriteNode_shared_sorted_list(node))
		{
#ifdef DEBUG
			fprintf(stderr, "\ncheckForRelativeOutgoingConnection: ERROR 1\n");
			exit(EXIT_FAILURE);
#endif
			// Someone remove this node!!!!
			if (node_reverse != NULL)
			{
				leaveNode_shared_sorted_list(list2, node_reverse);
			}
			return;
		}

#if DEBUG > 4
		if (node->nprocs-1 != info->pointed_by_nat + info->pointed_by_relative)
		{
			fprintf(stderr, "\ncheckForRelativeOutgoingConnection: ERROR 2  nproc: %u  nat: %u  rel: %u\n", node->nprocs-1, info->pointed_by_nat, info->pointed_by_relative);
			exit(EXIT_FAILURE);
		}
#endif

		// Found it ?
		if (node_reverse != NULL)
		{
			// Yes. Updating its tracking information
			info_reverse = (struct connection_info *)node_reverse->info; 
#if DEBUG > 4
			if (node_reverse->nprocs-1 != info_reverse->pointed_by_nat + info_reverse->pointed_by_relative)
			{
				fprintf(stderr, "\ncheckForRelativeOutgoingConnection: ERROR 3\n");
				exit(EXIT_FAILURE);
			}
			if (node->nprocs-1 != info->pointed_by_nat + info->pointed_by_relative)
			{
				fprintf(stderr, "\ncheckForRelativeOutgoingConnection: ERROR 4\n");
				exit(EXIT_FAILURE);
			}
#endif
			if (requestWriteNode_shared_sorted_list(node_reverse))
			{ 
				info_reverse->stablished = 1;

				if (info_reverse->relative_node == NULL)
				{
					if (requestAccessNode_shared_sorted_list(list, node))
					{
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
									fprintf(stderr, "checkForRelativeOutgoingConnection: REV ICMP %u %s TO %s ----> NODE ICMP %u  %s TO %s\n", info_reverse->shared_info.icmp_info.type, s_ip_src_reverse, s_ip_dst_reverse, info->shared_info.icmp_info.type, s_ip_src, s_ip_dst);
									break;
								case IPPROTO_TCP:
									sport = info->shared_info.tcp_info.sport;
									dport = info->shared_info.tcp_info.dport;
									sport_reverse = info_reverse->shared_info.tcp_info.sport;
									dport_reverse = info_reverse->shared_info.tcp_info.dport;
									fprintf(stderr, "checkForRelativeOutgoingConnection: REV TCP  %s:%u TO %s:%u ----> NODE TCP  %s:%u TO %s:%u\n", s_ip_src_reverse, sport_reverse, s_ip_dst_reverse, dport_reverse, s_ip_src, sport, s_ip_dst, dport);
									break;
								case IPPROTO_UDP:
									sport = info->shared_info.udp_info.sport;
									dport = info->shared_info.udp_info.dport;
									sport_reverse = info_reverse->shared_info.udp_info.sport;
									dport_reverse = info_reverse->shared_info.udp_info.dport;
									fprintf(stderr, "checkForRelativeOutgoingConnection: REV UDP  %s:%u TO %s:%u ----> NODE UDP  %s:%u TO %s:%u\n", s_ip_src_reverse, sport_reverse, s_ip_dst_reverse, dport_reverse, s_ip_src, sport, s_ip_dst, dport);
									break;
							}
							exit(EXIT_FAILURE);
						}
#endif
					}
				}  
				if (start)
				{
					info_reverse->starting =  0;
				}
				info->relative_node = node_reverse;
				info->relative_list = list2;
				info_reverse->pointed_by_relative++; 
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
							fprintf(stderr, "checkForRelativeOutgoingConnection: NODE ICMP %u %s TO %s ----> REV ICMP %u  %s TO %s\n", info->shared_info.icmp_info.type, s_ip_src, s_ip_dst, info_reverse->shared_info.icmp_info.type, s_ip_src_reverse, s_ip_dst_reverse);
							break;
						case IPPROTO_TCP:
							sport = info->shared_info.tcp_info.sport;
							dport = info->shared_info.tcp_info.dport;
							sport_reverse = info_reverse->shared_info.tcp_info.sport;
							dport_reverse = info_reverse->shared_info.tcp_info.dport;
							fprintf(stderr, "checkForRelativeOutgoingConnection: NODE TCP  %s:%u TO %s:%u ----> REV TCP  %s:%u TO %s:%u\n", s_ip_src, sport, s_ip_dst, dport, s_ip_src_reverse, sport_reverse, s_ip_dst_reverse, dport_reverse);
							break;
						case IPPROTO_UDP:
							sport = info->shared_info.udp_info.sport;
							dport = info->shared_info.udp_info.dport;
							sport_reverse = info_reverse->shared_info.udp_info.sport;
							dport_reverse = info_reverse->shared_info.udp_info.dport;
							fprintf(stderr, "checkForRelativeOutgoingConnection: NODE UDP  %s:%u TO %s:%u ----> REV UDP  %s:%u TO %s:%u\n", s_ip_src, sport, s_ip_dst, dport, s_ip_src_reverse, sport_reverse, s_ip_dst_reverse, dport_reverse);
							break;
					}
					exit(EXIT_FAILURE);
				}
#endif
			}
			else
			{
				leaveNode_shared_sorted_list(list2, node_reverse);
				info->relative_node = NULL;
				info->relative_list = NULL;
				node_reverse = NULL;
			}
		}
		else
		{
#ifdef DEBUG
			if (info->pointed_by_relative)
			{
				fprintf(stderr, "\ncheckForRelativeOutgoingConnection: ERROR 5\n");
				exit(EXIT_FAILURE);
			}
#endif
			info->relative_node = NULL;
			info->relative_list = NULL;
		} 
#if DEBUG > 4
		if (node_reverse != NULL && node_reverse->nprocs != info_reverse->pointed_by_nat + info_reverse->pointed_by_relative)
		{
			fprintf(stderr, "\ncheckForRelativeOutgoingConnection: ERROR 6\n");
			exit(EXIT_FAILURE);
		}
		if (node->nprocs-1 != info->pointed_by_nat + info->pointed_by_relative)
		{
			fprintf(stderr, "\ncheckForRelativeOutgoingConnection: ERROR 7\n");
			exit(EXIT_FAILURE);
		}
#endif

		// Updating tracking information
		info->starting = start || node_reverse == NULL || (node_reverse != NULL && !info_reverse->starting);
		info->stablished = node_reverse != NULL; 
		if (node_reverse != NULL) {
			leaveWriteNode_shared_sorted_list(node_reverse);
			// Next line is commented because we are pointing to that node until someone remove it
			//leaveNode_shared_sorted_list(list2, node_reverse);
		} 
	}

	leaveWriteNode_shared_sorted_list(node);

#if DEBUG > 4
		if (node_reverse != NULL && node_reverse->nprocs != info_reverse->pointed_by_nat + info_reverse->pointed_by_relative)
		{
			fprintf(stderr, "\ncheckForRelativeOutgoingConnection: ERROR 8\n");
			exit(EXIT_FAILURE);
		}
		if (node->nprocs-1 != info->pointed_by_nat + info->pointed_by_relative)
		{
			fprintf(stderr, "\ncheckForRelativeOutgoingConnection: ERROR 9\n");
			exit(EXIT_FAILURE);
		}
#endif

#if DEBUG > 1
		/***************************  DEBUG ****************************/
		{
			char m[255];

			sprintf(m, "Connection tracker: checkForRelativeOutgoingConnection finished     ");
			debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
		}
#endif

}

void checkForRelativeIncomingConnection(int internet, shared_sorted_list list, struct node_shared_sorted_list *node,
										struct connection_info *info, struct connection_info *info_rev, 
										int syn, uint16_t src_port, uint16_t dst_port)
{
    u_int16_t hash2;
    shared_sorted_list list2;
	struct connection_info *info_reverse;
	struct node_shared_sorted_list *node_reverse;
	int start;

#if DEBUG > 1
		/***************************  DEBUG ****************************/
		{
			char m[255];

			sprintf(m, "Connection tracker: checkForRelativeIncomingConnection start...");
			debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
		}
#endif

	if (info->ip_protocol == IPPROTO_ICMP) 
	{
		return;
	}
	else 
	{
		// All outgoing connections with src port >= 1024 and
		// dst port < 1024 are considered as client (starting)
		// connections
		start = syn || (src_port >= 1024 && dst_port < 1024);

		// Search for relative incoming connection
		node_reverse = NULL;
		info_reverse = NULL;
		info_rev->incoming = 1;
		// Get hash value and list
		if (internet)
		{
			hash2 = info_rev->ip_src.s_addr / 65536;
			list2 = w_globvars.conn_internet_in[hash2];
			if (Conn_isValidList(list2, w_globvars.mutex_conn_internet_in)) 
			{
				node_reverse = exclusiveFind_shared_sorted_list(list2, info_rev, NULL);
			}
		}
		else
		{
			hash2 = info_rev->ip_src.s_addr / 65536;
			list2 = w_globvars.conn_intranet_in[hash2];
			if (Conn_isValidList(list2, w_globvars.mutex_conn_intranet_in)) 
			{
				node_reverse = exclusiveFind_shared_sorted_list(list2, info_rev, NULL);
			}
		}

		if (!requestWriteNode_shared_sorted_list(node))
		{
#ifdef DEBUG
			fprintf(stderr, "\ncheckForRelativeIncomingConnection: ERROR 1\n");
			exit(EXIT_FAILURE);
#endif
			// Someone remove this node!!!!
			if (node_reverse != NULL)
			{
				leaveNode_shared_sorted_list(list2, node_reverse);
			}
			return;
		}

#if DEBUG > 4
			if (node->nprocs-1 != info->pointed_by_nat + info->pointed_by_relative)
			{
				fprintf(stderr, "\ncheckForRelativeIncomingConnection: ERROR 2  nproc: %u  nat: %u  rel: %u\n", node->nprocs-1, info->pointed_by_nat, info->pointed_by_relative);
				exit(EXIT_FAILURE);
			}
#endif

		// Found it ?
		if (node_reverse != NULL)
		{
			// Yes. Updating its tracking information
			info_reverse = (struct connection_info *)node_reverse->info;
#if DEBUG > 4
			if (node_reverse->nprocs-1 != info_reverse->pointed_by_nat + info_reverse->pointed_by_relative)
			{
				fprintf(stderr, "\ncheckForRelativeIncomingConnection: ERROR 3\n");
				exit(EXIT_FAILURE);
			}
			if (node->nprocs-1 != info->pointed_by_nat + info->pointed_by_relative)
			{
				fprintf(stderr, "\ncheckForRelativeIncomingConnection: ERROR 4\n");
				exit(EXIT_FAILURE);
			}
#endif

			if (requestWriteNode_shared_sorted_list(node_reverse))
			{
				info_reverse->stablished = 1;
				
				if (info_reverse->relative_node == NULL)
				{
					if (requestAccessNode_shared_sorted_list(list, node))
					{
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
									fprintf(stderr, "REV ICMP %u %s TO %s ----> NODE ICMP %u  %s TO %s\n", info_reverse->shared_info.icmp_info.type, s_ip_src_reverse, s_ip_dst_reverse, info->shared_info.icmp_info.type, s_ip_src, s_ip_dst);
									break;
								case IPPROTO_TCP:
									sport = info->shared_info.tcp_info.sport;
									dport = info->shared_info.tcp_info.dport;
									sport_reverse = info_reverse->shared_info.tcp_info.sport;
									dport_reverse = info_reverse->shared_info.tcp_info.dport;
									fprintf(stderr, "REV TCP  %s:%u TO %s:%u ----> NODE TCP  %s:%u TO %s:%u\n", s_ip_src_reverse, sport_reverse, s_ip_dst_reverse, dport_reverse, s_ip_src, sport, s_ip_dst, dport);
									break;
								case IPPROTO_UDP:
									sport = info->shared_info.udp_info.sport;
									dport = info->shared_info.udp_info.dport;
									sport_reverse = info_reverse->shared_info.udp_info.sport;
									dport_reverse = info_reverse->shared_info.udp_info.dport;
									fprintf(stderr, "REV UDP  %s:%u TO %s:%u ----> NODE UDP  %s:%u TO %s:%u\n", s_ip_src_reverse, sport_reverse, s_ip_dst_reverse, dport_reverse, s_ip_src, sport, s_ip_dst, dport);
									break;
							}
							exit(EXIT_FAILURE);
						}
#endif
					}
				}
				if (start)
				{
					info_reverse->starting =  0;
				}
				info->relative_node = node_reverse;
				info->relative_list = list2;
				info_reverse->pointed_by_relative++;
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
							fprintf(stderr, "NODE ICMP %u %s TO %s ----> REV ICMP %u  %s TO %s\n", info->shared_info.icmp_info.type, s_ip_src, s_ip_dst, info_reverse->shared_info.icmp_info.type, s_ip_src_reverse, s_ip_dst_reverse);
							break;
						case IPPROTO_TCP:
							sport = info->shared_info.tcp_info.sport;
							dport = info->shared_info.tcp_info.dport;
							sport_reverse = info_reverse->shared_info.tcp_info.sport;
							dport_reverse = info_reverse->shared_info.tcp_info.dport;
							fprintf(stderr, "NODE TCP  %s:%u TO %s:%u ----> REV TCP  %s:%u TO %s:%u\n", s_ip_src, sport, s_ip_dst, dport, s_ip_src_reverse, sport_reverse, s_ip_dst_reverse, dport_reverse);
							break;
						case IPPROTO_UDP:
							sport = info->shared_info.udp_info.sport;
							dport = info->shared_info.udp_info.dport;
							sport_reverse = info_reverse->shared_info.udp_info.sport;
							dport_reverse = info_reverse->shared_info.udp_info.dport;
							fprintf(stderr, "NODE UDP  %s:%u TO %s:%u ----> REV UDP  %s:%u TO %s:%u\n", s_ip_src, sport, s_ip_dst, dport, s_ip_src_reverse, sport_reverse, s_ip_dst_reverse, dport_reverse);
							break;
					}
					exit(EXIT_FAILURE);
				}
#endif
			}
			else
			{
				leaveNode_shared_sorted_list(list2, node_reverse);
				info->relative_node = NULL;
				info->relative_list = NULL;
				node_reverse = NULL;
			}
		}
		else
		{
#ifdef DEBUG
			if (info->pointed_by_relative)
			{
				fprintf(stderr, "\ncheckForRelativeIncomingConnection: ERROR 5\n");
				exit(EXIT_FAILURE);
			}
#endif
			info->relative_node = NULL;
			info->relative_list = NULL;
		}
#if DEBUG > 4
		if (node_reverse != NULL && node_reverse->nprocs != info_reverse->pointed_by_nat + info_reverse->pointed_by_relative)
		{
			fprintf(stderr, "\ncheckForRelativeIncomingConnection: ERROR 6\n");
			exit(EXIT_FAILURE);
		}
		if (node->nprocs-1 != info->pointed_by_nat + info->pointed_by_relative)
		{
			fprintf(stderr, "\ncheckForRelativeIncomingConnection: ERROR 7\n");
			exit(EXIT_FAILURE);
		}
#endif

		// Updating tracking information
		info->starting = start || (node_reverse != NULL && !info_reverse->starting);
		info->stablished = node_reverse != NULL;
		if (node_reverse != NULL) {
			leaveWriteNode_shared_sorted_list(node_reverse);
			// Next line is commented because we are pointing to that node until someone remove it
			//leaveNode_shared_sorted_list(*list2, node_reverse);
		}
	}

	leaveWriteNode_shared_sorted_list(node);

#if DEBUG > 4
		if (node_reverse != NULL && node_reverse->nprocs != info_reverse->pointed_by_nat + info_reverse->pointed_by_relative)
		{
			fprintf(stderr, "\ncheckForRelativeIncomingConnection: ERROR 8\n");
			exit(EXIT_FAILURE);
		}
		if (node->nprocs-1 != info->pointed_by_nat + info->pointed_by_relative)
		{
			fprintf(stderr, "\ncheckForRelativeIncomingConnection: ERROR 9\n");
			exit(EXIT_FAILURE);
		}
#endif


#if DEBUG > 1
		/***************************  DEBUG ****************************/
		{
			char m[255];

			sprintf(m, "Connection tracker: checkForRelativeIncomingConnection finished  ");
			debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
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

#if DEBUG > 1
	/***************************  DEBUG ****************************/
	{
		char m[255];

		sprintf(m, "Connection tracker: checkForRelativeNATConnection start...     ");
		debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
	}
#endif

	if (internet && c_globvars.intranet_dev == NULL)
	{
#if DEBUG > 1
		/***************************  DEBUG ****************************/
		{
			char m[255];

			sprintf(m, "Connection tracker: checkForRelativeNATConnection finished    ");
			debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
		}
#endif

		return;
	}

	if (info->ip_protocol == IPPROTO_ICMP) 
	{
		// NAT ICMP CONNECTIONS NOT YET IMPLEMENTED
#if DEBUG > 1
		/***************************  DEBUG ****************************/
		{
			char m[255];

			sprintf(m, "Connection tracker: checkForRelativeNATConnection finished    ");
			debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
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

	// Search relative NAT connection
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

#if DEBUG > 4
			if (node->nprocs-1 != info->pointed_by_nat + info->pointed_by_relative)
			{
				fprintf(stderr, "\ncheckForRelativeNATConnection: ERROR 3  nproc: %u  nat: %u  rel: %u\n", node->nprocs-1, info->pointed_by_nat, info->pointed_by_relative);
				exit(EXIT_FAILURE);
			}
#endif

	// Found it?
	if (node_NAT != NULL)
	{
		info_NAT = (struct connection_info *)node_NAT->info;
#if DEBUG > 4
			if (node_NAT->nprocs-1 != info_NAT->pointed_by_nat + info_NAT->pointed_by_relative)
			{
				fprintf(stderr, "\ncheckForRelativeNATConnection: ERROR 4\n");
				exit(EXIT_FAILURE);
			}
			if (node->nprocs-1 != info->pointed_by_nat + info->pointed_by_relative)
			{
				fprintf(stderr, "\ncheckForRelativeNATConnection: ERROR 5\n");
				exit(EXIT_FAILURE);
			}
#endif

		if (requestWriteNode_shared_sorted_list(node_NAT))
		{
			if (info_NAT->nat_node == NULL)			
			{
				if (requestAccessNode_shared_sorted_list(list, node))
				{
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
								fprintf(stderr, "NAT ICMP %u %s TO %s ----> NODE ICMP %u  %s TO %s\n", info_NAT->shared_info.icmp_info.type, s_ip_src_NAT, s_ip_dst_NAT, info->shared_info.icmp_info.type, s_ip_src, s_ip_dst);
								break;
							case IPPROTO_TCP:
								sport = info->shared_info.tcp_info.sport;
								dport = info->shared_info.tcp_info.dport;
								sport_NAT = info_NAT->shared_info.tcp_info.sport;
								dport_NAT = info_NAT->shared_info.tcp_info.dport;
								fprintf(stderr, "NAT TCP  %s:%u TO %s:%u ----> NODE TCP  %s:%u TO %s:%u\n", s_ip_src_NAT, sport_NAT, s_ip_dst_NAT, dport_NAT, s_ip_src, sport, s_ip_dst, dport);
								break;
							case IPPROTO_UDP:
								sport = info->shared_info.udp_info.sport;
								dport = info->shared_info.udp_info.dport;
								sport_NAT = info_NAT->shared_info.udp_info.sport;
								dport_NAT = info_NAT->shared_info.udp_info.dport;
								fprintf(stderr, "NAT UDP  %s:%u TO %s:%u ----> NODE UDP  %s:%u TO %s:%u\n", s_ip_src_NAT, sport_NAT, s_ip_dst_NAT, dport_NAT, s_ip_src, sport, s_ip_dst, dport);
								break;
						}
						exit(EXIT_FAILURE);
					}
#endif
				}
			}
			info_NAT->pointed_by_nat++;
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
						fprintf(stderr, "NODE ICMP %u %s TO %s ----> NAT ICMP %u  %s TO %s\n", info->shared_info.icmp_info.type, s_ip_src, s_ip_dst, info_NAT->shared_info.icmp_info.type, s_ip_src_NAT, s_ip_dst_NAT);
						break;
					case IPPROTO_TCP:
						sport = info->shared_info.tcp_info.sport;
						dport = info->shared_info.tcp_info.dport;
						sport_NAT = info_NAT->shared_info.tcp_info.sport;
						dport_NAT = info_NAT->shared_info.tcp_info.dport;
						fprintf(stderr, "NODE TCP  %s:%u TO %s:%u ----> NAT TCP  %s:%u TO %s:%u\n", s_ip_src, sport, s_ip_dst, dport, s_ip_src_NAT, sport_NAT, s_ip_dst_NAT, dport_NAT);
						break;
					case IPPROTO_UDP:
						sport = info->shared_info.udp_info.sport;
						dport = info->shared_info.udp_info.dport;
						sport_NAT = info_NAT->shared_info.udp_info.sport;
						dport_NAT = info_NAT->shared_info.udp_info.dport;
						fprintf(stderr, "NODE UDP  %s:%u TO %s:%u ----> NAT UDP  %s:%u TO %s:%u\n", s_ip_src, sport, s_ip_dst, dport, s_ip_src_NAT, sport_NAT, s_ip_dst_NAT, dport_NAT);
						break;
				}
				exit(EXIT_FAILURE);
			}
#endif
			leaveWriteNode_shared_sorted_list(node_NAT);
			info->nat_node = node_NAT;
			info->nat_list = list2;
			// Next line is commented because we are pointing to that node until someone remove it
			//leaveNode_shared_sorted_list(list2, node_NAT);
		}
		else
		{
			leaveNode_shared_sorted_list(list2, node_NAT);
			info->nat_node = NULL;
			info->nat_list = NULL;
		}
	}
	else
	{
#ifdef DEBUG
		if (info->pointed_by_nat)
		{
			fprintf(stderr, "\ncheckForRelativeNATConnection: ERROR 6\n");
			exit(EXIT_FAILURE);
		}
#endif
		info->nat_node = NULL;
		info->nat_list = NULL;
	}

#if DEBUG > 4
		if (node_NAT != NULL && node_NAT->nprocs != info_NAT->pointed_by_nat + info_NAT->pointed_by_relative)
		{
			fprintf(stderr, "\ncheckForRelativeNATConnection: ERROR 7\n");
			exit(EXIT_FAILURE);
		}
		if (node->nprocs-1 != info->pointed_by_nat + info->pointed_by_relative)
		{
			fprintf(stderr, "\ncheckForRelativeNATConnection: ERROR 8\n");
			exit(EXIT_FAILURE);
		}
#endif

	leaveWriteNode_shared_sorted_list(node);

#if DEBUG > 4
		if (node_NAT != NULL && node_NAT->nprocs != info_NAT->pointed_by_nat + info_NAT->pointed_by_relative)
		{
			fprintf(stderr, "\ncheckForRelativeNATConnection: ERROR 9\n");
			exit(EXIT_FAILURE);
		}
		if (node->nprocs-1 != info->pointed_by_nat + info->pointed_by_relative)
		{
			fprintf(stderr, "\ncheckForRelativeNATConnection: ERROR 10\n");
			exit(EXIT_FAILURE);
		}
#endif

#if DEBUG > 1
		/***************************  DEBUG ****************************/
		{
			char m[255];

			sprintf(m, "Connection tracker: checkForRelativeNATConnection finished      ");
			debugMessageXY(TRACKER_THREAD_ROW, TRACKER_THREAD_COL, m, NULL, 1);
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
