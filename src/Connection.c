#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <GlobalVars.h>
#include <PacketList.h>
#include <Configuration.h>
#include <conntrack.h>
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
uint32_t checkForRelativeNATConnection(struct connection_info *info);
void Conn_updateBandwidth(struct connection_info *info, time_t now);
void Conn_accumulateBytes(void *val, void *total);
int Conn_isValidList(shared_sorted_list list, pthread_mutex_t mutex);
void Conn_createList(shared_sorted_list *list, pthread_mutex_t mutex, int (*compare)(void *, void*) );
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
			if (pthread_mutex_lock(&w_globvars.mutex_debug_stats)) 
			{
				perror("connection_tracker: pthread_mutex_lock with mutex_debug_stats");
				exit(1);
			}        
			w_globvars.internet_packets_processed += count;
			if (pthread_mutex_unlock(&w_globvars.mutex_debug_stats))
			{
				perror("connection_tracker: pthread_mutex_unlock with mutex_debug_stats");
				exit(1);		
			}
#endif
		}
		else
		{
			// Get intranet connections
			count = intranetConnections(); 
#ifdef DEBUG
			if (pthread_mutex_lock(&w_globvars.mutex_debug_stats)) 
			{
				perror("connection_tracker: pthread_mutex_lock with mutex_debug_stats");
				exit(1);
			}        
			w_globvars.intranet_packets_processed += count;
			if (pthread_mutex_unlock(&w_globvars.mutex_debug_stats))
			{
				perror("connection_tracker: pthread_mutex_unlock with mutex_debug_stats");
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
	int module;
	char s[9];

	if (internet) 
	{
		module = INTERNET_CONNECTIONS_TRACKER;
		strcpy(s, "Internet");
	}
	else
	{
		module = INTRANET_CONNECTIONS_TRACKER;
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
				priority = incoming_packetAllowed(packet->ip_src, packet->ip_protocol, single_port);
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
	int module;
	char s[9];

	if (internet) 
	{
		module = INTERNET_CONNECTIONS_TRACKER;
		strcpy(s, "Internet");
	}
	else
	{
		module = INTRANET_CONNECTIONS_TRACKER;
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
	struct node_shared_sorted_list *node;
	struct connection_bandwidth *info_bandwidth;
	int syn;
	int info_conntrack;


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

	// Store Source and Destination IP address and direction
	new_info->ip_src = packet->ip_src;
	new_info->ip_dst = packet->ip_dst;
	new_info->incoming = incoming;

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
			break;
		case IPPROTO_UDP:
			// Store source and destination port
			new_info->shared_info.udp_info.sport = packet->shared_header.udp_header.sport;
			new_info->shared_info.udp_info.dport = packet->shared_header.udp_header.dport;
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
 		// Initialize stats of new connection
		info = new_info;
		info->last_connections = NULL;
		init_double_list(&info->last_connections);
		info->hits = 0;
		info->total_bytes = 0;
		info->starting = 0;
		info->stablished = 0;
		info->NAT = 0;
		info->ip_NAT_dst.s_addr = 0;

	}
	else 
	{
		// Existing connection  
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
		}
	} // end of existing connection

#ifdef DEBUG
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "%s Connection tracker: Updating stats...", s);
		debugMessageModule(module, m, NULL, 1);
	}
#endif

	// Check if this is a stablished connection
	if (!info->stablished) {
		// Get kernel conntrack info for this connection
		switch (info->ip_protocol)
		{
			case IPPROTO_ICMP:
				info_conntrack = get_conntrack_ICMP(info->ip_src.s_addr, info->ip_dst.s_addr, info->shared_info.icmp_info.type, info->shared_info.icmp_info.code, &info->ip_NAT_dst.s_addr);
				if (info_conntrack != -1) {
 					info->starting = (info_conntrack & CONNTRACK_CLIENT) != 0;
					info->stablished = (info_conntrack & CONNTRACK_STABLISHED) != 0;
 					info->NAT = (info_conntrack & CONNTRACK_NAT) != 0;
				}
 				else {
					info->starting  = info->shared_info.icmp_info.type == ICMP_ECHO ||
					                  info->shared_info.icmp_info.type == ICMP_TIMESTAMP ||
					                  info->shared_info.icmp_info.type == ICMP_INFO_REQUEST ||
					                  info->shared_info.icmp_info.type == ICMP_REDIRECT ||
					                  info->shared_info.icmp_info.type == ICMP_ADDRESS;
					//info->starting = 1;
				}
				break;
			case IPPROTO_TCP:
				info_conntrack = get_conntrack_TCP_UDP(info->ip_protocol, info->ip_src.s_addr, info->shared_info.tcp_info.sport, info->ip_dst.s_addr, info->shared_info.tcp_info.dport, &info->ip_NAT_dst.s_addr, &info->shared_info.tcp_info.NAT_dport);
				if (info_conntrack != -1) {
 					info->starting = (info_conntrack & CONNTRACK_CLIENT) != 0;
					info->stablished = (info_conntrack & CONNTRACK_STABLISHED) != 0;
					info->NAT = (info_conntrack & CONNTRACK_NAT) != 0;
				}
 				else {
					info->starting = info->shared_info.tcp_info.sport >= 1024;
					//info->starting = 1;
				}
				break;
			case IPPROTO_UDP:
				info_conntrack = get_conntrack_TCP_UDP(info->ip_protocol, info->ip_src.s_addr, info->shared_info.udp_info.sport, info->ip_dst.s_addr, info->shared_info.udp_info.dport, &info->ip_NAT_dst.s_addr, &info->shared_info.udp_info.NAT_dport);
				if (info_conntrack != -1) {
 					info->starting = (info_conntrack & CONNTRACK_CLIENT) != 0;
					info->stablished = (info_conntrack & CONNTRACK_STABLISHED) != 0 || (info_conntrack & CONNTRACK_SEEN_REPLY) != 0 || (info_conntrack & CONNTRACK_ASURED) != 0;
					info->NAT = (info_conntrack & CONNTRACK_NAT) != 0;
				}
 				else {
					info->starting = info->shared_info.tcp_info.sport >= 1024;
					//info->starting = 1;
				}
				break;
		}
	}

	// One hit more
	info->hits++;

	// Store current time
	info->time = now;

	// Store priority
	info->priority = priority;

	// Add current size to totals
	info->total_bytes = info->total_bytes + packet->n_bytes;

	// Add current connection to last connections (to calculate bandwidth)
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
	}
	else
	{
		// No more write access needed
		leaveWriteNode_shared_sorted_list(node);
	}

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
}

uint32_t checkForRelativeNATConnection(struct connection_info *info)
{
    u_int16_t hash2;
    shared_sorted_list list2;
	pthread_mutex_t *mutex;
	struct connection_info *info_NAT;
	struct node_shared_sorted_list *node_NAT;
	uint32_t ret = 0;

#ifdef DEBUG
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "Internet checkForRelativeNATConnection start...");
		debugMessageModule(INTERNET_CONNECTIONS_TRACKER, m, NULL, 1);
	}
#endif

	if (c_globvars.intranet_dev == NULL)
	{
#ifdef DEBUG
		/***************************  DEBUG ****************************/
		{
			char m[150];

			sprintf(m, "Internet checkForRelativeNATConnection finished (no intranet dev)");
			debugMessageModule(INTERNET_CONNECTIONS_TRACKER, m, NULL, 1);
		}
#endif
		return 0;
	}

	// Get the relative list
	node_NAT = NULL;
	info_NAT = NULL;
	hash2 = info->ip_src.s_addr / 65536;
	list2 = w_globvars.conn_intranet_in[hash2];
	mutex = &w_globvars.mutex_conn_intranet_in;

	// Search relative NAT connection
	if (Conn_isValidList(list2, *mutex)) 
	{
#ifdef DEBUG
		/***************************  DEBUG ****************************/
		{
			char m[150];

			sprintf(m, "Internet checkForRelativeNATConnection before searching relative NAT node");
			debugMessageModule(INTERNET_CONNECTIONS_TRACKER, m, NULL, 1);
		}
#endif
		node_NAT = exclusiveFind_shared_sorted_list(list2, info, compareNAT);
#ifdef DEBUG
		/***************************  DEBUG ****************************/
		{
			char m[150];

			sprintf(m, "Internet checkForRelativeNATConnection after searching relative NAT node");
			debugMessageModule(INTERNET_CONNECTIONS_TRACKER, m, NULL, 1);
		}
#endif
		// Found it?
		if (node_NAT != NULL)
		{
#ifdef DEBUG
			/***************************  DEBUG ****************************/
			{
				char m[150];

				sprintf(m, "Internet checkForRelativeNATConnection relative NAT node found");
				debugMessageModule(INTERNET_CONNECTIONS_TRACKER, m, NULL, 1);
			}
#endif

			// Yes. Get the intranet IP destination

			// Get relative NAT node info		
			info_NAT = (struct connection_info *)node_NAT->info;

			// Request read access to NAT node
			if (requestReadNode_shared_sorted_list(node_NAT))
			{
				// Get the intranet IP destination
				ret = info_NAT->ip_dst.s_addr;

				// Leave NAT node read access 
				leaveReadNode_shared_sorted_list(node_NAT);
			}
			else
			{
				// Relative NAT node exists but can't access to relative NAT node for reading.
				// Someone else want's to delete it
#ifdef DEBUG
				fprintf(stderr, "\nInternet checkForRelativeNATConnection: ERROR 2\n");
				exit(EXIT_FAILURE);
#endif
			}
			leaveNode_shared_sorted_list(list2, node_NAT);
		}
	}

#ifdef DEBUG
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "Internet checkForRelativeNATConnection finished");
		debugMessageModule(INTERNET_CONNECTIONS_TRACKER, m, NULL, 1);
	}
#endif
	return ret;
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

int Conn_isValidList(shared_sorted_list list, pthread_mutex_t mutex) {
	int ret;

	if (pthread_mutex_lock(&mutex)) 
	{
		perror("CONN_isValidList: pthread_mutex_lock with mutex list");
		exit(1);
	}
	ret = list != NULL;
	if (pthread_mutex_unlock(&mutex))
	{
		perror("CONN_isValidList: pthread_mutex_unlock with mutex list");
		exit(1);		
	}

	return ret;
}

void Conn_createList(shared_sorted_list *list, pthread_mutex_t mutex, int (*compare)(void *, void*) ) {
	if (pthread_mutex_lock(&mutex)) 
	{
		perror("CONN_createList: pthread_mutex_lock with mutex list");
		exit(1);
	}
	init_shared_sorted_list(list, compare);
	if (pthread_mutex_unlock(&mutex))
	{
		perror("CONN_createList: pthread_mutex_unlock with mutex list");
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
				if (conn1->shared_info.icmp_info.code < conn2->shared_info.icmp_info.code)
					return -1;
				if (conn1->shared_info.icmp_info.code > conn2->shared_info.icmp_info.code)
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
				if (conn1->shared_info.icmp_info.code < conn2->shared_info.icmp_info.code)
					return -1;
				if (conn1->shared_info.icmp_info.code > conn2->shared_info.icmp_info.code)
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
