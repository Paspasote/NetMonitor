#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <curses.h>
#include <semaphore.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <debug.h>
#include <GlobalVars.h>
#include <Configuration.h>
#include <SharedSortedList.h>
#include <Configuration.h>
#include <interface.h>
#include <OutboundView.h>

// EXTERNAL Global vars
extern struct const_global_vars c_globvars;
extern struct write_global_vars w_globvars;

// Global vars

// Function prototypes
int OV_isValidList();
void OV_createList();
void OV_removeNode(struct node_shared_sorted_list *node);

void OV_ShowElement(struct node_shared_sorted_list *node, void *param);
void OV_updateBandwidth(struct OV_info *info, time_t now);
void OV_accumulateBytes(void *val, void *total);
void OV_freeLastConnections(void *val, void *param);


int OV_Equals(void *val1, void *val2);
int OV_Compare(void *val1, void *val2);

int OV_isValidList() {
	int ret;

	if (sem_wait(&w_globvars.mutex_packages_list)) 
	{
		perror("OV_isValidList: sem_wait with mutex_packages_list");
		exit(1);
	}
	ret = w_globvars.OV_l != NULL;
	if (sem_post(&w_globvars.mutex_packages_list))
	{
		perror("OV_isValidList: sem_post with mutex_packages_list");
		exit(1);		
	}

	return ret;
}

void OV_createList() {
	if (sem_wait(&w_globvars.mutex_packages_list)) 
	{
		perror("OV_createList: sem_wait with mutex_packages_list");
		exit(1);
	}
	init_shared_sorted_list(&w_globvars.OV_l, OV_Compare);
	if (sem_post(&w_globvars.mutex_packages_list))
	{
		perror("OV_createList: sem_post with mutex_packages_list");
		exit(1);		
	}
}

void OV_removeNode(struct node_shared_sorted_list *node) {
	struct OV_info *info;

	// Save the info to free after node removed
	info = (struct OV_info *)node->info;

	// Remove node
	removeNode_shared_sorted_list(w_globvars.OV_l, node, 1);

	// Free memory
	// Clear Bandwidth info
	clear_all_double_list(info->last_connections, 1, NULL, NULL);
	free(info->last_connections);
	free(info);
}


void OV_Reset() {
	// List is valid?
	if (OV_isValidList())
	{
		clear_all_shared_sorted_list(w_globvars.OV_l, 1, NULL, NULL);
	}

}

void OV_ShowElement(struct node_shared_sorted_list *node, void *param) {
	struct OV_info *info;
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

	info = (struct OV_info *)node->info;

	now = time(NULL);

	requestReadNode_shared_sorted_list(node);

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
				updateWhoisInfo(node, info->ip_dst.s_addr, info->country, info->netname);
			}

			// Generate line info
			strcpy(s_protocol, "ICMP");
			if (info->shared_info.icmp_info.type < 19) {
				strcpy(s_icmp, s_vicmp[info->shared_info.icmp_info.type]);
			}
			else {
				strcpy(s_icmp, "");
			}
			if (!strcmp(s_icmp, "")) {
				sprintf(s_icmp, " [Unknown] Type: %u", info->shared_info.icmp_info.type);
			}
			sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s  %15s  %2s  %-16s  %-5s%s\n", s_time, info->hits, total_bytes, info->bandwidth, s_ip_src, s_ip_dst, info->country, info->netname, s_protocol, s_icmp);
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
				updateWhoisInfo(node, info->ip_dst.s_addr, info->country, info->netname);
			}

			// Generate line info
			strcpy(s_protocol, "tcp");
			service_alias = serviceAlias(info->ip_protocol, info->shared_info.tcp_info.dport);
			if (service_alias != NULL && strcmp(service_alias, "")) {
				sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s  %15s  %2s  %-16s  %s\n", s_time, info->hits, total_bytes, info->bandwidth, s_ip_src, s_ip_dst, info->country, info->netname, service_alias);				
			}
			else {
				servinfo = getservbyport(htons(info->shared_info.tcp_info.dport), s_protocol);
				if (servinfo != NULL && servinfo->s_name != NULL && strcmp(servinfo->s_name, "")) {
					sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s  %15s  %2s  %-16s  %s\n", s_time, info->hits, total_bytes, info->bandwidth, s_ip_src, s_ip_dst, info->country, info->netname, servinfo->s_name);
				}
				else {
					sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s  %15s  %2s  %-16s  %-5s%5u\n", s_time, info->hits, total_bytes, info->bandwidth, s_ip_src, s_ip_dst, info->country, info->netname, s_protocol, info->shared_info.tcp_info.dport);				
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
				updateWhoisInfo(node, info->ip_dst.s_addr, info->country, info->netname);
			}

			// Generate line info
			strcpy(s_protocol, "udp");
			service_alias = serviceAlias(info->ip_protocol, info->shared_info.udp_info.dport);
			if (service_alias != NULL && strcmp(service_alias, "")) {
				sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s  %15s  %2s  %-16s  %s\n", s_time, info->hits, total_bytes, info->bandwidth, s_ip_src, s_ip_dst, info->country, info->netname, service_alias);				
			}
			else {
				servinfo = getservbyport(htons(info->shared_info.udp_info.dport), s_protocol);
				if (servinfo != NULL && servinfo->s_name != NULL && strcmp(servinfo->s_name, "")) {
					sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s  %15s  %2s  %-16s  %s\n", s_time, info->hits, total_bytes, info->bandwidth, s_ip_src, s_ip_dst, info->country, info->netname, servinfo->s_name);
				}
				else {
					sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s  %15s  %2s  %-16s  %-5s%5u\n", s_time, info->hits, total_bytes, info->bandwidth, s_ip_src, s_ip_dst, info->country, info->netname, s_protocol, info->shared_info.udp_info.dport);				
				}
			}
			break;	
	}

	writeLineOnResult(line, COLOR_PAIR(info->priority), now - info->time <= RECENT_TIMEOUT);
	leaveReadNode_shared_sorted_list(node);
	w_globvars.result_count_lines++;
}

void OV_ShowInfo() {  
	// List is valid?
	if (!OV_isValidList())
	{
		return;
	}

	// Iterate the list and show info on screen
	w_globvars.result_count_lines = 0;
	for_eachNode_shared_sorted_list(w_globvars.OV_l, OV_ShowElement, NULL);
}

void OV_addPacket(const struct ether_header *ethernet,const struct ip *ip,const struct icmp *icmp_header,
				  const struct tcphdr *tcp_header,const struct udphdr *udp_header,const struct igmp *igmp_header, 
				  unsigned n_bytes, unsigned priority) {

	time_t now;
	struct OV_info *new_info, *info;
	struct node_shared_sorted_list *node;
	struct OV_info_bandwidth *info_bandwidth;
	uint16_t src_port, dst_port;

	// Protocol wanted??
	if (ip->ip_p != IPPROTO_ICMP && ip->ip_p != IPPROTO_TCP && ip->ip_p != IPPROTO_UDP) {
		return;
	}

	now = time(NULL);

	// Check if buffer list has been created
	if (!OV_isValidList()) {
		OV_createList();
	}

	// List is valid?
	if (!OV_isValidList())
	{
		fprintf(stderr,"OV_addPacket: List is not valid!!\n");
		exit(1);
	}

	new_info = (struct OV_info *) malloc(sizeof(struct OV_info));
	if (new_info == NULL) {
		fprintf(stderr,"OV_addPacket: Could not allocate memory!!\n");
		exit(1);				
	}

	// Store IP Protocol
	new_info->ip_protocol = ip->ip_p;

	// Store Source and Destination IP address
	new_info->ip_src = ip->ip_src;
	new_info->ip_dst = ip->ip_dst;

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
	node = exclusiveFind_shared_sorted_list(w_globvars.OV_l, new_info, OV_Equals);
    
    if (node == NULL) {
		// The connection is new.
		if (ip->ip_p != IPPROTO_ICMP) {
			// Check if is a client connection
			if (src_port < 1024 && dst_port >= 1024) {
				// It is not a client connection. Discard it
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
		strcpy(info->country, "");
		strcpy(info->netname, "");
    }
    else {
		// Connection already exists. Get its information
        info = (struct OV_info *) node->info;
		// Request write access
		requestWriteNode_shared_sorted_list(node);
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
	info_bandwidth = (struct OV_info_bandwidth *) malloc(sizeof(struct OV_info_bandwidth));
	if (info_bandwidth == NULL) {
		fprintf(stderr,"OV_addPacket: Could not allocate memory!!\n");
		exit(1);				
	}
	info_bandwidth->time = info->time;
	info_bandwidth->n_bytes = n_bytes;
	insert_tail_double_list(info->last_connections, (void *)info_bandwidth);

	// Calculate bandwidth
	OV_updateBandwidth(info, now);

	// Refresh the list of connections
	if (node == NULL) {
		// Insert the new connection in the list
		insert_shared_sorted_list(w_globvars.OV_l, info);
	}
	else {
		// No more write access needed
		leaveWriteNode_shared_sorted_list(node);

		// Move existing node to its right position
		updateNode_shared_sorted_list(w_globvars.OV_l, node);

		// Leaving current node
		leaveNode_shared_sorted_list(w_globvars.OV_l, node);
	}
}

void OV_updateBandwidth(struct OV_info *info, time_t now) {
	unsigned long total_bytes = 0;
	struct OV_info_bandwidth *info_bandwidth;	
	time_t t;
	int stop;

	// First, we remove all connections older than MAX_INTERVAL_BANDWIDTH seconds
	stop = 0;
	while (!stop && !isEmpty_double_list(info->last_connections)) {
		info_bandwidth = (struct OV_info_bandwidth *) front_double_list(info->last_connections);
		stop = now - info_bandwidth->time < MAX_INTERVAL_BANDWIDTH_OUTGOING;
		if (!stop) {
			// We have to remove this last connection
			remove_front_double_list(info->last_connections, 1);
		}
	}

	// Get time of older connection
	t = now;
	if (!isEmpty_double_list(info->last_connections)) {
		info_bandwidth = (struct OV_info_bandwidth *)front_double_list(info->last_connections);
		t = info_bandwidth->time;
	}

	if (now - t >= MIN_INTERVAL_BANDWIDTH_OUTGOING) {
		// Calculate total bytes 	
		for_each_double_list(info->last_connections, OV_accumulateBytes, (void *)&total_bytes);

		info->bandwidth = (float)total_bytes / (1024.0 * (now - t + 1));
	}
	else {
		info->bandwidth = 0.0;
	}
}

void OV_accumulateBytes(void *val, void *total) {
	*(unsigned long *)total += ((struct OV_info_bandwidth *)val)->n_bytes;
}

void OV_freeLastConnections(void *val, void *param) {
	struct OV_info *info;

	info = (struct OV_info *)val;

	// Clear Bandwidth info
	clear_all_double_list(info->last_connections, 1, NULL, NULL);
	// Free memory
	free(info->last_connections);
}

int OV_Equals(void *val1, void *val2) {
	struct OV_info *info1, *info2;

	info1 = (struct OV_info *)val1;
	info2 = (struct OV_info *)val2;

	if (info1->ip_protocol != info2->ip_protocol)
		return(1);

	if (info1->ip_src.s_addr != info2->ip_src.s_addr)
		return 1;

	if (info1->ip_dst.s_addr != info2->ip_dst.s_addr)
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

int OV_Compare(void *val1, void *val2) {
	struct OV_info *info1, *info2;
	//unsigned long grade1, grade2;
	float grade1, grade2;

	info1 = (struct OV_info *)val1;
	info2 = (struct OV_info *)val2;

	grade1 = info1->bandwidth;
	grade2 = info2->bandwidth;

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

void OV_Purge() {
	struct node_shared_sorted_list *node, *current_node;
	struct OV_info *info;
	time_t now;
	unsigned timeout;
	float old_bandwidth;

	// List is valid?
	if (!OV_isValidList())
	{
		return;
	}

	now = time(NULL);


	// Iterate the list and remove old connections
	node = firstNode_shared_sorted_list(w_globvars.OV_l);
	while (node != NULL) {
		info = (struct OV_info *)node->info;

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
			node = nextNode_shared_sorted_list(w_globvars.OV_l, node, 0);
			// Removing current node
			OV_freeLastConnections(current_node->info, NULL);
			removeNode_shared_sorted_list(w_globvars.OV_l, current_node, 1);
		}
		else {			
			// Update bandwidth
			old_bandwidth = info->bandwidth;
			OV_updateBandwidth(info, now);

			// Leave write access
			leaveWriteNode_shared_sorted_list(node);

			// Bandwidth changed?
			if (fabs(old_bandwidth - info->bandwidth) >= BANDWIDTH_PRECISION) {
				// have to resort (move) current node because we sort by bandwidth
				current_node = node;

				// Next node
				node = nextNode_shared_sorted_list(w_globvars.OV_l, node, 0);

				// Move current node
				updateNode_shared_sorted_list(w_globvars.OV_l, current_node);

				// Leave node
				leaveNode_shared_sorted_list(w_globvars.OV_l, current_node);
			}
			else {
				// Next node
				node = nextNode_shared_sorted_list(w_globvars.OV_l, node, 1);
			}
		}
	}
}

