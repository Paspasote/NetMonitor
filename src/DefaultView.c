#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <curses.h>
#include <semaphore.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>


#include <debug.h>
#include <SharedSortedList.h>
#include <Configuration.h>
#include <WhoIs.h>
#include <interface.h>
#include <DefaultView.h>

// Global vars
shared_sorted_list DV_l = NULL;
shared_sorted_list DV_l_outbound = NULL;
extern sem_t mutex_packages_list;
extern sem_t mutex_outbound_list;
extern sem_t mutex_bd_whois;
extern time_t start;
extern int result_count_lines;

// Function prototypes
int DV_isValidList();
void DV_createList();
int DV_isValidList_outbound();
void DV_createList_outbound();

void DV_ShowElement(struct node_shared_sorted_list *node, void *param);
void DV_addPacket_outbound(const struct ip *ip, const struct tcphdr *tcp_header,const struct udphdr *udp_header);
void DV_updateBandwidth(struct DV_info *info, time_t now);
void DV_accumulateBytes(void *val, void *total);
void DV_freeLastConnections(void *val, void *param);
void DV_Purge_outbound();

int DV_Equals(void *val1, void *val2);
int DV_Reverse(void *val1, void *val2);
int DV_Compare(void *val1, void *val2);
int DV_Compare_outbound(void *val1, void *val2);

int DV_isValidList() {
	int ret;

	if (sem_wait(&mutex_packages_list)) 
	{
		perror("DV_isValidList: sem_wait with mutex_packages_list");
		exit(1);
	}
	ret = DV_l != NULL;
	if (sem_post(&mutex_packages_list))
	{
		perror("DV_isValidList: sem_post with mutex_packages_list");
		exit(1);		
	}

	return ret;
}

void DV_createList() {
	if (sem_wait(&mutex_packages_list)) 
	{
		perror("DV_createList: sem_wait with mutex_packages_list");
		exit(1);
	}
	init_shared_sorted_list(&DV_l, DV_Compare);
	if (sem_post(&mutex_packages_list))
	{
		perror("DV_createList: sem_post with mutex_packages_list");
		exit(1);		
	}
}

int DV_isValidList_outbound() {
	int ret;

	if (sem_wait(&mutex_outbound_list)) 
	{
		perror("DV_isValidList_outbound: sem_wait with mutex_outbound_list");
		exit(1);
	}
	ret = DV_l_outbound != NULL;
	if (sem_post(&mutex_outbound_list))
	{
		perror("DV_isValidList_outbound: sem_post with mutex_outbound_list");
		exit(1);		
	}

	return ret;
}

void DV_createList_outbound() {
	if (sem_wait(&mutex_outbound_list)) 
	{
		perror("DV_createList_outbound: sem_wait with mutex_outbound_list");
		exit(1);
	}
	init_shared_sorted_list(&DV_l_outbound, DV_Compare_outbound);
	if (sem_post(&mutex_outbound_list))
	{
		perror("DV_createList_outbound: sem_post with mutex_outbound_list");
		exit(1);		
	}
}

void DV_Reset() {
	if (DV_isValidList())
	{
		clear_all_shared_sorted_list(DV_l, 1, DV_freeLastConnections, NULL);
	}
	if (DV_isValidList_outbound()) {
		clear_all_shared_sorted_list(DV_l_outbound, 1, NULL, NULL);
	}
}

void DV_ShowElement(struct node_shared_sorted_list *node, void *param) {
	struct DV_info *info;
	struct tm *t;
	time_t now;
	char s_time[20];
	char line[250];
	char s_protocol[5];
	struct servent *servinfo;
	char s_ip_src[INET_ADDRSTRLEN], s_ip_dst[INET_ADDRSTRLEN];
	char s_vicmp[][50] = {"Echo Reply","","","Destination Unreachable","Source Quench","Redirect Message","","",
						  "Echo Request","Router Advertisement","Router Solicitation","Time Exceeded","Bad IP header",
						  "Timestamp Request","Timestamp Reply","Information Request","Information Reply","Address Mask Request",
						  "Adress Mask Reply"};
	char s_icmp[50];
	char total_bytes[20];
	char *service_alias;
	char s_port[9];

	info = (struct DV_info *)node->info;

	requestReadNode_shared_sorted_list(node);
	if (info->response) {
		// Do not show response connections
		leaveReadNode_shared_sorted_list(node);
		return;
	}

	now = time(NULL);

	t = localtime(&info->time);
	sprintf(s_time, "%02d/%02d/%4d %02d:%02d:%02d", t->tm_mday, t->tm_mon, 1900+t->tm_year, t->tm_hour, t->tm_min, t->tm_sec);

	inet_ntop(AF_INET, &(info->ip_src), s_ip_src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(info->ip_dst), s_ip_dst, INET_ADDRSTRLEN);

	if ((float)info->total_bytes / 1024.0 > 99999.99) {
		sprintf(total_bytes, "[%8.2f MB]", (float)info->total_bytes / (1024.0*1024.0));
	}
	else {
		sprintf(total_bytes, "[%8.2f KB]", (float)info->total_bytes / 1024.0);
	}

	// Protocol?
	switch (info->ip_protocol) {
		case IPPROTO_ICMP:
			if (now - info->time >= ANY_VISIBLE_TIMEOUT) {
				// Visibility timeout
				leaveReadNode_shared_sorted_list(node);
				return;
			}

			// Check if we have to update whois info
			if (!strcmp(info->country, ""))
			{
				updateWhoisInfo(node, info->ip_src.s_addr, info->country, info->netname);
			}

			// Generate line info
			strcpy(s_protocol, "icmp");
			if (info->shared_info.icmp_info.type < 19) {
				strcpy(s_icmp, s_vicmp[info->shared_info.icmp_info.type]);
			}
			else {
				strcpy(s_icmp, "");
			}
			if (!strcmp(s_icmp, "")) {
				sprintf(s_icmp, " [Unknown] Type: %u", info->shared_info.icmp_info.type);
			}
			sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s        %2s  %-16s  %-5s%s\n", s_time, info->hits, total_bytes, info->bandwidth, s_ip_src, info->country, info->netname, s_protocol, s_icmp);
			break;
		case IPPROTO_TCP:
			if (now - info->time >= TCP_VISIBLE_TIMEOUT) {
				// Visibility timeout
				leaveReadNode_shared_sorted_list(node);
				return;
			}

			// Check if we have to update whois info
			if (!strcmp(info->country, ""))
			{
				updateWhoisInfo(node, info->ip_src.s_addr, info->country, info->netname);
			}

			// Generate line info
			strcpy(s_protocol, "tcp");
			sprintf(s_port, "%0u", info->shared_info.tcp_info.sport);
			if (info->response) {
				strcat(s_port, "(R)");
			}
			service_alias = serviceAlias(info->ip_protocol, info->shared_info.tcp_info.dport);
			if (service_alias != NULL && strcmp(service_alias, "")) {
				sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s:%-5s  %2s  %-16s  %s\n", s_time, info->hits, total_bytes, info->bandwidth, s_ip_src, s_port, info->country, info->netname, service_alias);				
			}
			else {
				servinfo = getservbyport(htons(info->shared_info.tcp_info.dport), s_protocol);
				if (servinfo != NULL && servinfo->s_name != NULL && strcmp(servinfo->s_name, "")) {
					sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s:%-5s  %2s  %-16s  %s\n", s_time, info->hits, total_bytes, info->bandwidth, s_ip_src, s_port, info->country, info->netname, servinfo->s_name);
				}
				else {
					sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s:%-5s  %2s  %-16s  %-5s%5u\n", s_time, info->hits, total_bytes, info->bandwidth, s_ip_src, s_port, info->country, info->netname, s_protocol, info->shared_info.tcp_info.dport);				
				}
			}
			break;
		case IPPROTO_UDP:
			if (now - info->time >= UDP_VISIBLE_TIMEOUT) {
				// Visibility timeout
				leaveReadNode_shared_sorted_list(node);
				return;
			}

			// Check if we have to update whois info
			if (!strcmp(info->country, ""))
			{
				updateWhoisInfo(node, info->ip_src.s_addr, info->country, info->netname);
			}

			// Generate line info
			strcpy(s_protocol, "udp");
			sprintf(s_port, "%0u", info->shared_info.udp_info.sport);
			if (info->response) {
				strcat(s_port, "(R)");
			}
			service_alias = serviceAlias(info->ip_protocol, info->shared_info.udp_info.dport);
			if (service_alias != NULL && strcmp(service_alias, "")) {
				//sprintf(line, "%s   [%05lu] %s [%8.2f KB/s]  %22s  %s\n", s_time, info->hits, total_bytes, info->bandwidth, src_ip_port, service_alias);				
				sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s:%-5s  %2s  %-16s  %s\n", s_time, info->hits, total_bytes, info->bandwidth, s_ip_src, s_port, info->country, info->netname, service_alias);				
			}
			else {
				servinfo = getservbyport(htons(info->shared_info.udp_info.dport), s_protocol);
				if (servinfo != NULL && servinfo->s_name != NULL && strcmp(servinfo->s_name, "")) {
					sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s:%-5s  %2s  %-16s  %s\n", s_time, info->hits, total_bytes, info->bandwidth, s_ip_src, s_port, info->country, info->netname, servinfo->s_name);
				}
				else {
					sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s:%-5s  %2s  %-16s  %-5s%5u\n", s_time, info->hits, total_bytes, info->bandwidth, s_ip_src, s_port, info->country, info->netname, s_protocol, info->shared_info.udp_info.dport);				
				}
			}
			break;	
	}

	writeLineOnResult(line, COLOR_PAIR(info->priority), now - info->time <= RECENT_TIMEOUT);
	leaveReadNode_shared_sorted_list(node);
	result_count_lines++;
}

void DV_ShowInfo() {
	// Is list valid?
	if (!DV_isValidList())
	{
		return;
	}

	// Iterate the list and show info on screen
	result_count_lines = 0;
	for_eachNode_shared_sorted_list(DV_l, DV_ShowElement, NULL);
}

void DV_addPacket(in_addr_t own_ip, const struct ether_header *ethernet,const struct ip *ip,const struct icmp *icmp_header,
	const struct tcphdr *tcp_header,const struct udphdr *udp_header,const struct igmp *igmp_header, unsigned n_bytes, unsigned priority) {
	time_t now;
	struct DV_info *info, *new_info;
	struct DV_info_outbound info_outbound;
	struct node_shared_sorted_list *node, *node_reverse;
	struct DV_info_bandwidth *info_bandwidth;
	uint16_t src_port, dst_port;
	int syn;

	// Protocol wanted??
	if (ip->ip_p != IPPROTO_ICMP && ip->ip_p != IPPROTO_TCP && ip->ip_p != IPPROTO_UDP) {
		return;
	}

	// Inbound or Outbound??
	if (ip->ip_src.s_addr == own_ip) {
		// Outbound
		DV_addPacket_outbound(ip, tcp_header, udp_header);
		return;
	}

	now = time(NULL);

	// SYN Flag ?
	syn = ip->ip_p == IPPROTO_TCP && (tcp_header->th_flags & TH_SYN) && !(tcp_header->th_flags & TH_ACK);

	// Check if buffer list has been created
	if (!DV_isValidList()) {
		DV_createList();
	}

	// List is valid?
	if (!DV_isValidList()) {
		fprintf(stderr,"DV_addPacket: List is not valid!!\n");
		exit(1);
	}

	new_info = (struct DV_info *) malloc(sizeof(struct DV_info));
	if (new_info == NULL) {
		fprintf(stderr,"DV_addPacket: Could not allocate memory!!\n");
		exit(1);				
	}

	// Store IP Protocol
	new_info->ip_protocol = ip->ip_p;
	info_outbound.ip_protocol = new_info->ip_protocol;

	// Store Source and Destination IP address
	new_info->ip_src = ip->ip_src;
	new_info->ip_dst = ip->ip_dst;
	info_outbound.ip_src = new_info->ip_dst;
	info_outbound.ip_dst = new_info->ip_src;

	// Protocol?
	switch (ip->ip_p) {
		case IPPROTO_ICMP:
			// Store ICMP type and code
			new_info->shared_info.icmp_info.type = icmp_header->icmp_type;
			new_info->shared_info.icmp_info.code = icmp_header->icmp_code;
			break;
		case IPPROTO_TCP:
			// Store source and destination port, and TCP flags
			new_info->shared_info.tcp_info.sport = ntohs(tcp_header->th_sport);
			new_info->shared_info.tcp_info.dport = ntohs(tcp_header->th_dport);
			new_info->shared_info.tcp_info.flags = tcp_header->th_flags;
			info_outbound.shared_info.tcp_info.sport = new_info->shared_info.tcp_info.dport;
			info_outbound.shared_info.tcp_info.dport = new_info->shared_info.tcp_info.sport;
			src_port = new_info->shared_info.tcp_info.sport;
			dst_port = new_info->shared_info.tcp_info.dport;
			break;
		case IPPROTO_UDP:
			// Store source and destination port
			new_info->shared_info.udp_info.sport = ntohs(udp_header->uh_sport);
			new_info->shared_info.udp_info.dport = ntohs(udp_header->uh_dport);
			info_outbound.shared_info.udp_info.sport = new_info->shared_info.udp_info.dport;
			info_outbound.shared_info.udp_info.dport = new_info->shared_info.udp_info.sport;
			src_port = new_info->shared_info.udp_info.sport;
			dst_port = new_info->shared_info.udp_info.dport;
			break;	
	}

	// Connection (node list) exist?
	node = exclusiveFind_shared_sorted_list(DV_l, new_info, DV_Equals);

	// New connection?
	if (node == NULL) {
		// The connection is new.
		// Check if it is a respond of a previous outgoing connection
		if (ip->ip_p == IPPROTO_ICMP) {
			// Never can't be a respond
			new_info->response = 0;
		}
		else {
			// It is a respond if there is a relative outgoing connection
			node_reverse = NULL;
			if (DV_isValidList_outbound()) {
				node_reverse = exclusiveFind_shared_sorted_list(DV_l_outbound, &info_outbound, NULL);
			}
			//new_info->response = node_reverse != NULL && (ip->ip_p == IPPROTO_TCP || ((struct DV_info_outbound *)node_reverse->info)->shared_info.udp_info.started);
			new_info->response = node_reverse != NULL;
			if (node_reverse != NULL) {
				leaveNode_shared_sorted_list(DV_l_outbound, node_reverse);
			}
		}
 		// Initialize stats of new connection
		info = new_info;
		info->last_connections = NULL;
		init_double_list(&info->last_connections);
		info->hits = 0;
		info->total_bytes = 0;
		strcpy(info->country, "");
		strcpy(info->netname, "");
	}
	else {
		// Connection already exists. Get its information
		info = (struct DV_info *) node->info;
		// Request write access
		requestWriteNode_shared_sorted_list(node);
		if (syn) {
			// New connection. Remove all last connections
			clear_all_double_list(info->last_connections, 1, NULL, NULL);
			info->total_bytes = 0;
			info->response = 0;
		}
		else {
			if (!info->response && ip->ip_p != IPPROTO_ICMP && src_port < 1024 && dst_port >= 1024) {
				// Not a response connection
				// We recheck if it is a response connection if
				// src port < 1024 and dst port >= 1024
				// Is there NOW a relative outgoing connection ?
				node_reverse = NULL;
				if (DV_isValidList_outbound()) {
					node_reverse = exclusiveFind_shared_sorted_list(DV_l_outbound, &info_outbound, NULL);
				}
				//new_info->response = node_reverse != NULL && (ip->ip_p == IPPROTO_TCP || ((struct DV_info_outbound *)node_reverse->info)->shared_info.udp_info.started);
				info->response = node_reverse != NULL;
				if (node_reverse != NULL) {
					leaveNode_shared_sorted_list(DV_l_outbound, node_reverse);
				}
			}
		}
		// Free new info
		free(new_info);
	}

	// One hit more
	info->hits++;

	// Store current time
	info->time = now;

	// Store priority
	info->priority = priority;

	// Add current size to totals
	info->total_bytes = info->total_bytes + n_bytes;

	// Add current connection to last connections (to calculate bandwith)
	info_bandwidth = (struct DV_info_bandwidth *) malloc(sizeof(struct DV_info_bandwidth));
	if (info_bandwidth == NULL) {
		fprintf(stderr,"DV_addPacket: Could not allocate memory!!\n");
		exit(1);				
	}
	info_bandwidth->time = info->time;
	info_bandwidth->n_bytes = n_bytes;
 	insert_tail_double_list(info->last_connections, (void *)info_bandwidth);

	// Calculate bandwidth
	DV_updateBandwidth(info, now);

	// Refresh the list of connections
	if (node == NULL) {
		// Insert the new connection in the list
		insert_shared_sorted_list(DV_l, info);
	}
	else {
		// No more write access needed
		leaveWriteNode_shared_sorted_list(node);

		// Move existing node to its right position
		updateNode_shared_sorted_list(DV_l, node);

		// Leaving current node
		leaveNode_shared_sorted_list(DV_l, node);
	}
}

void DV_addPacket_outbound(const struct ip *ip, const struct tcphdr *tcp_header, const struct udphdr *udp_header) {
	time_t now;
	struct DV_info_outbound *info, *new_info;
	struct node_shared_sorted_list *node, *node_reverse;
	uint16_t src_port, dst_port;
	int syn, starting;

	// Protocol wanted??
	if (ip->ip_p == IPPROTO_ICMP) {
		return;
	}

	now = time(NULL);

	// SYN Flag ?
	syn = ip->ip_p == IPPROTO_TCP && (tcp_header->th_flags & TH_SYN) && !(tcp_header->th_flags & TH_ACK);

	// Check if buffer list has been created
	if (!DV_isValidList_outbound()) {
		DV_createList_outbound();
	}

	// List is valid?
	if (!DV_isValidList_outbound()) {
		fprintf(stderr,"DV_addPacket_outbound: List is not valid!!\n");
		exit(1);
	}

	new_info = (struct DV_info_outbound *) malloc(sizeof(struct DV_info_outbound));
	if (new_info == NULL) {
		fprintf(stderr,"DV_addPacket_outbound: Could not allocate memory!!\n");
		exit(1);				
	}

	// Store time
	new_info->time = now;

	// Store IP Protocol
	new_info->ip_protocol = ip->ip_p;

	// Store Source and Destination IP address
	new_info->ip_src = ip->ip_src;
	new_info->ip_dst = ip->ip_dst;

	// Protocol?
	switch (ip->ip_p) {
		case IPPROTO_TCP:
			// Store source and destination port, and TCP flags
			new_info->shared_info.tcp_info.sport = ntohs(tcp_header->th_sport);
			new_info->shared_info.tcp_info.dport = ntohs(tcp_header->th_dport);
			new_info->shared_info.tcp_info.flags = tcp_header->th_flags;
			src_port = new_info->shared_info.tcp_info.sport;
			dst_port = new_info->shared_info.tcp_info.dport;
			break;
		case IPPROTO_UDP:
			// Store source and destination port
			new_info->shared_info.udp_info.sport = ntohs(udp_header->uh_sport);
			new_info->shared_info.udp_info.dport = ntohs(udp_header->uh_dport);
			src_port = new_info->shared_info.udp_info.sport;
			dst_port = new_info->shared_info.udp_info.dport;
			break;	
	}

	// Connection (node list) exist?
	node = exclusiveFind_shared_sorted_list(DV_l_outbound, new_info, NULL);

	// New connection?
	if (node == NULL) {
		// The connection is new. Is it a starting one?
		// All TCP outgoing connections with src port >= 1024 and
		// dst port < 1024 are considered as client (starting)
		// connections
		starting = src_port >= 1024 && dst_port < 1024;
		starting = src_port >= 1024 && dst_port < 1024;
		// It is also a starting connection if TCP and SYN flag is active
		starting = starting || (ip->ip_p == IPPROTO_TCP &&syn);

		if (!starting) {
			if (ip->ip_p == IPPROTO_TCP) {
				// Can't be a starting connections. Discard TCP connection
				free(new_info);
				return;
			}
			else {
				// UDP connection.
				if (src_port < 1024) {
					// Can't be a starting connections. Discard UDP connection
					free(new_info);
					return;
				}
				// This is a starting connection (by us) if there is not a relative
				// incoming connections (we are not responding to a previous incoming connection)
				// If we have recently changed to a new view then we wait a while for
				// incoming connections until take a decision
				if (now - start <= THRESHOLD_ESTABLISHED_CONNECTIONS) {
					// Waiting por posible incoming connections. Discard UDP connection
					free(new_info);
					return;
				}
				// Checking if there is a relative incoming connection. 
				// If there is not one then we mark the packet as starting connection
				// (shared_info.udp_info.started to 1)
				// If there is one we mark the packet as NOT starting connection but
				// we ALSO ADD it to the list for optimization reasons (for not checking again)
				node_reverse = NULL;
				if (DV_isValidList()) {
					node_reverse = exclusiveFind_shared_sorted_list(DV_l, new_info, DV_Reverse);
				}
				new_info->shared_info.udp_info.started = node_reverse == NULL;
				if (node_reverse != NULL) {
					leaveNode_shared_sorted_list(DV_l, node_reverse);
				}				
			}
		}

		// Insert the new connection in the list
		insert_shared_sorted_list(DV_l_outbound, new_info);
	}
	else {
		// Connection already exists. Get its information
		info = (struct DV_info_outbound *) node->info;
		// Free new info
		free(new_info);
		// Request write access
		requestWriteNode_shared_sorted_list(node);
		// Update time to current time
		info->time = now;
		// No more write access needed
		leaveWriteNode_shared_sorted_list(node);
		// Leaving current node
		leaveNode_shared_sorted_list(DV_l_outbound, node);
	}
}

void DV_updateBandwidth(struct DV_info *info, time_t now) {
	unsigned long total_bytes = 0;
	struct DV_info_bandwidth *info_bandwidth;	
	time_t t;
	int stop;

	// First, we remove all connections older than MAX_INTERVAL_BANDWIDTH seconds
	stop = 0;
	while (!stop && !isEmpty_double_list(info->last_connections)) {
		info_bandwidth = (struct DV_info_bandwidth *) front_double_list(info->last_connections);
		stop = now - info_bandwidth->time <= MAX_INTERVAL_BANDWIDTH;
		if (!stop) {
			// We have to remove this last connection
			remove_front_double_list(info->last_connections, 1);
		}
	}

	// Get time of older connection
	t = now;
	if (!isEmpty_double_list(info->last_connections)) {
		info_bandwidth = (struct DV_info_bandwidth *)front_double_list(info->last_connections);
		t = info_bandwidth->time;
	}

	if (now - t >= MIN_INTERVAL_BANDWIDTH) {
		// Calculate total bytes 	
		for_each_double_list(info->last_connections, DV_accumulateBytes, (void *)&total_bytes);

		info->bandwidth = (float)total_bytes / (1024.0 * (now - t + 1));
	}
	else {
		info->bandwidth = 0.0;
	}
}

void DV_accumulateBytes(void *val, void *total) {
	*(unsigned long *)total += ((struct DV_info_bandwidth *)val)->n_bytes;
}

void DV_freeLastConnections(void *val, void *param) {
	struct DV_info *info;

	info = (struct DV_info *)val;

	// Clear Bandwidth info
	clear_all_double_list(info->last_connections, 1, NULL, NULL);
	// Free memory
	free(info->last_connections);
}

void DV_Purge() {
	struct node_shared_sorted_list *node, *current_node;
	struct DV_info *info;
	time_t now;
	unsigned timeout;

	// List is valid?
	if (!DV_isValidList())
	{
		return;
	}

	now = time(NULL);

	// Iterate the list and remove old connections
	node = firstNode_shared_sorted_list(DV_l);
	while (node != NULL) {
		// Get info node
		info = (struct DV_info *)node->info;

		requestWriteNode_shared_sorted_list(node);

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
		if (now - info->time > timeout) {
			// Leave write access
			leaveWriteNode_shared_sorted_list(node);
			// have to delete current node
			current_node = node;
			// Before remove current node get the next one
			node = nextNode_shared_sorted_list(DV_l, node, 0);
			// Removing current node
			DV_freeLastConnections(current_node->info, NULL);
			removeNode_shared_sorted_list(DV_l, current_node, 1);
		}
		else {
			// Update bandwidth
			DV_updateBandwidth(info, now);

			// Leave write access
			leaveWriteNode_shared_sorted_list(node);

			// Next node
			node = nextNode_shared_sorted_list(DV_l, node, 1);
		}
	}

	// Remove old outgoing connections
	DV_Purge_outbound();
}

void DV_Purge_outbound() {
	struct node_shared_sorted_list *node, *current_node;
	struct DV_info_outbound *info;
	time_t now;
	unsigned timeout;

	// List is valid?
	if (!DV_isValidList_outbound())
	{
		return;
	}

	now = time(NULL);

	// Iterate the list and remove old connections
	node = firstNode_shared_sorted_list(DV_l_outbound);
	while (node != NULL) {
		// Get info node
		info = (struct DV_info_outbound *)node->info;

		requestReadNode_shared_sorted_list(node);

		switch (info->ip_protocol) {
			case IPPROTO_TCP:
				timeout = TCP_TIMEOUT;
				break;
			case IPPROTO_UDP:
				timeout = UDP_TIMEOUT;
				break;
		}

		// Timeout?
		if (now - info->time > timeout) {
			// Leave read access
			leaveReadNode_shared_sorted_list(node);
			// have to delete current node
			current_node = node;
			// Before remove current node get the next one
			node = nextNode_shared_sorted_list(DV_l_outbound, node, 0);
			// Removing current node
			removeNode_shared_sorted_list(DV_l_outbound, current_node, 1);
		}
		else {
			// Leave read access
			leaveReadNode_shared_sorted_list(node);

			// Next node
			node = nextNode_shared_sorted_list(DV_l_outbound, node, 1);
		}
	}
}

int DV_Equals(void *val1, void *val2) {
	struct DV_info *info1, *info2;

	info1 = (struct DV_info *)val1;
	info2 = (struct DV_info *)val2;

	if (info1->ip_protocol != info2->ip_protocol)
		return(1);

	if (info1->ip_src.s_addr != info2->ip_src.s_addr)
		return 1;

	// Protocol?
	switch (info1->ip_protocol) {
		case IPPROTO_ICMP:
			if (info1->shared_info.icmp_info.type != info2->shared_info.icmp_info.type)
				return 1;
			break;
		case IPPROTO_TCP:
			if (info1->shared_info.tcp_info.dport != info2->shared_info.tcp_info.dport)
				return 1;
			break;
		case IPPROTO_UDP:
			if (info1->shared_info.udp_info.dport != info2->shared_info.udp_info.dport)
				return 1;
			break;	
	}

	return 0;
}

int DV_Reverse(void *val1, void *val2) {
	struct DV_info_outbound *info1;
	struct DV_info *info2;

	info1 = (struct DV_info_outbound *)val1;
	info2 = (struct DV_info *)val2;

	if (info1->ip_protocol != info2->ip_protocol)
		return 1;

	if (info1->ip_src.s_addr != info2->ip_dst.s_addr)
		return 1;

	// Protocol?
	switch (info1->ip_protocol) {
		case IPPROTO_TCP:
			if (info1->shared_info.tcp_info.dport != info2->shared_info.tcp_info.sport)
				return 1;
			break;
		case IPPROTO_UDP:
			if (info1->shared_info.udp_info.dport != info2->shared_info.udp_info.sport)
				return 1;
			break;	
	}

	return 0;
}

int DV_Compare(void *val1, void *val2) {
	struct DV_info *info1, *info2;
	unsigned long grade1, grade2;
	time_t now, diff_time1, diff_time2;

	now = time(NULL);

	info1 = (struct DV_info *)val1;
	info2 = (struct DV_info *)val2;

	diff_time1 = now - info1->time;
	diff_time2 = now - info2->time;

	grade1 = info1->hits;
	grade2 = info2->hits;

	if (diff_time1 == 0) {
		grade1 = grade1 * 1000;
	}
	else {
		if (diff_time1 <= 900) {
			grade1 = grade1 * (int) ( 900.0 / (float)diff_time1 );
		}
		else {
			grade1 = grade1 - (int) ( (float)diff_time1 / 900.0); 
		}

	}

	if (diff_time2 == 0) {
		grade2 = grade2 * 1000;
	}
	else {
		if (diff_time2 <= 900) {
			grade2 = grade2 * (int) ( 900.0 / (float)diff_time2 );
		}
		else {
			grade2 = grade2 - (int) ( (float)diff_time2 / 900.0); 
		}

	}

	if (grade1 < grade2) {
		return 1;
	}
	else {
		if (grade1 > grade2) {
			return -1;
		}
		else {
			return 0;
		}
	}
}

int DV_Compare_outbound(void *val1, void *val2) {
	struct DV_info_outbound *info1, *info2;

	info1 = (struct DV_info_outbound *)val1;
	info2 = (struct DV_info_outbound *)val2;

	// Firt sort by protocol
	if (info1->ip_protocol < info2->ip_protocol)
	{
		return -1;
	}
	else {
		if (info1->ip_protocol > info2->ip_protocol)
		{
			return 1;
		}
	}

	// They have the same protocol
	// Second sort by src port

	// Protocol?
	switch (info1->ip_protocol) {
		case IPPROTO_TCP:
			if (info1->shared_info.tcp_info.sport < info2->shared_info.tcp_info.sport) {
				return -1;
			}
			else {
				if (info1->shared_info.tcp_info.sport > info2->shared_info.tcp_info.sport) {
					return 1;
				}
			}
			break;
		case IPPROTO_UDP:
			if (info1->shared_info.udp_info.sport < info2->shared_info.udp_info.sport) {
				return -1;
			}
			else {
				if (info1->shared_info.udp_info.sport > info2->shared_info.udp_info.sport) {
					return 1;
				}
			}
			break;	
	}

	// They have same src port
	// Third (and last) sort by dst address
	if (info1->ip_dst.s_addr < info2->ip_dst.s_addr) {
		return -1;
	}
	else {
		if (info1->ip_dst.s_addr == info2->ip_dst.s_addr) {
			return 0;
		}
		else {
			return 1;
		}
	}
}

