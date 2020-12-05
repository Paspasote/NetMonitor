#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <curses.h>
#include <semaphore.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <debug.h>
#include <SortedList.h>
#include <Configuration.h>
#include <interface.h>
#include <DefaultView.h>

// Constants
#define	TCP_TIMEOUT	900
#define ANY_TIMEOUT 300
#define RECENT_TIMEOUT	3
#define INTERVAL_BANDWITH 2

// Global vars
sorted_list DV_l = NULL;
extern sem_t mutex_bp;
extern int result_count_lines;


// Function prototypes
void DV_ShowElement(void *data, void *param);
float calculateBandwidth(time_t now, struct DV_info *info);
void accumulateBytes(void *val, void *total);
int DV_Equals(void *val1, void *val2);
int DV_Reverse(void *val1, void *val2);
int DV_Compare(void *val1, void *val2);

void DV_Init() {
	if (sem_wait(&mutex_bp)) 
	{
		perror("DV_Init: sem_wait with mutex_bp");
		exit(1);
	}
	init_sorted_list(&DV_l, DV_Compare);
	if (sem_post(&mutex_bp))
	{
		perror("DV_Init: sem_post with mutex_bp");
		exit(1);		
	}
}

void DV_Reset() {
	clear_all_sorted_list(DV_l);
}

void DV_ShowElement(void *data, void *param) {
	struct DV_info *info;
	struct tm *t;
	time_t now;
	char s_time[20];
	char line[150];
	char s_protocol[5];
	struct servent *servinfo;
	char s_ip_src[INET_ADDRSTRLEN], s_ip_dst[INET_ADDRSTRLEN];
	char s_vicmp[][50] = {"Echo Reply","","","Destination Unreachable","Source Quench","Redirect Message","","",
						  "Echo Request","Router Advertisement","Router Solicitation","Time Exceeded","Bad IP header",
						  "Timestamp Request","Timestamp Reply","Information Request","Information Reply","Address Mask Request",
						  "Adress Mask Reply"};
	char s_icmp[50];
	char total_bytes[20];
	struct DV_info_bandwidth *info_bandwidth;
	int stop;
	float bandwidth;
	attr_t attr, *p_attr;
	char *service_alias;

	now = time(NULL);

	info = (struct DV_info *)data;

	t = localtime(&info->time_inbound);
	sprintf(s_time, "%02d/%02d/%4d %02d:%02d:%02d", t->tm_mday, t->tm_mon, 1900+t->tm_year, t->tm_hour, t->tm_min, t->tm_sec);

	inet_ntop(AF_INET, &(info->ip_src), s_ip_src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(info->ip_dst), s_ip_dst, INET_ADDRSTRLEN);

	if ((float)info->total_bytes / 1024.0 > 99999.99) {
		sprintf(total_bytes, "[%8.2f MB]", (float)info->total_bytes / (1024.0*1024.0));
	}
	else {
		sprintf(total_bytes, "[%8.2f KB]", (float)info->total_bytes / 1024.0);
	}

	// Calculate bandwidth
	// Before, we remove all connections older than INTERVAL_BANDWITH seconds
	stop = 0;
	while (!stop && !isEmpty_double_list(info->last_connections)) {
		info_bandwidth = (struct DV_info_bandwidth *) front_double_list(info->last_connections);
		stop = now - info_bandwidth->time < INTERVAL_BANDWITH;
		if (!stop) {
			// We have to remove this last connection
			remove_front_double_list(info->last_connections);
		}
	}
	bandwidth = calculateBandwidth(now, info);

	// Protocol?
	switch (info->ip_protocol) {
		case IPPROTO_ICMP:
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
			sprintf(line, "%s   [%05lu] %s [%8.2f KB/s]  %17s  %-5s%s\n", s_time, info->hits, total_bytes, bandwidth, s_ip_src, s_protocol, s_icmp);
			break;
		case IPPROTO_TCP:
			strcpy(s_protocol, "tcp");
			service_alias = serviceAlias(info->ip_protocol, info->shared_info.tcp_info.dport);
			if (service_alias != NULL && strcmp(service_alias, "")) {
				sprintf(line, "%s   [%05lu] %s [%8.2f KB/s]  %17s  %s\n", s_time, info->hits, total_bytes, bandwidth, s_ip_src, service_alias);				
			}
			else {
				servinfo = getservbyport(htons(info->shared_info.tcp_info.dport), s_protocol);
				if (servinfo != NULL && servinfo->s_name != NULL && strcmp(servinfo->s_name, "")) {
					sprintf(line, "%s   [%05lu] %s [%8.2f KB/s]  %17s  %s\n", s_time, info->hits, total_bytes, bandwidth, s_ip_src, servinfo->s_name);
				}
				else {
					sprintf(line, "%s   [%05lu] %s [%8.2f KB/s]  %17s  %-5s%5u\n", s_time, info->hits, total_bytes, bandwidth, s_ip_src, s_protocol, info->shared_info.tcp_info.dport);				
				}
			}
			break;
		case IPPROTO_UDP:
			strcpy(s_protocol, "udp");
			service_alias = serviceAlias(info->ip_protocol, info->shared_info.udp_info.dport);
			if (service_alias != NULL && strcmp(service_alias, "")) {
				sprintf(line, "%s   [%05lu] %s [%8.2f KB/s]  %17s  %s\n", s_time, info->hits, total_bytes, bandwidth, s_ip_src, service_alias);				
			}
			else {
				servinfo = getservbyport(htons(info->shared_info.udp_info.dport), s_protocol);
				if (servinfo != NULL && servinfo->s_name != NULL && strcmp(servinfo->s_name, "")) {
					sprintf(line, "%s   [%05lu] %s [%8.2f KB/s]  %17s  %s\n", s_time, info->hits, total_bytes, bandwidth, s_ip_src, servinfo->s_name);
				}
				else {
					sprintf(line, "%s   [%05lu] %s [%8.2f KB/s]  %17s  %-5s%5u\n", s_time, info->hits, total_bytes, bandwidth, s_ip_src, s_protocol, info->shared_info.udp_info.dport);				
				}
			}
			break;	
	}

	if (info->priority == 1 && now - info->time_inbound > RECENT_TIMEOUT) {
		p_attr = NULL;
	}
	else {
		p_attr = &attr;
	}
	attr = COLOR_PAIR(info->priority);
	writeLineOnResult(line, p_attr);
	result_count_lines++;
}

void DV_ShowInfo() {
	if (DV_l == NULL) {
		return;
	}

	result_count_lines = 0;
	if (sem_wait(&mutex_bp)) 
	{
		perror("DV_ShowInfo: sem_wait with mutex_bp");
		exit(1);
	}
	for_each_sorted_list(DV_l, DV_ShowElement, NULL);
	if (sem_post(&mutex_bp))
	{
		perror("DV_ShowInfo: sem_post with mutex_bp");
		exit(1);		
	}
}

void DV_addPacket(const struct ether_header *ethernet,const struct ip *ip,const struct icmp *icmp_header,
	const struct tcphdr *tcp_header,const struct udphdr *udp_header,const struct igmp *igmp_header, unsigned n_bytes, unsigned priority) {

	struct DV_info *info, *old_info;
	struct node_sorted_list *node;
	struct DV_info_bandwidth *info_bandwidth;
	unsigned timeout;
	int syn;
	//int inbound;
	int stop;

	// Protocol wanted??
	if (ip->ip_p != IPPROTO_ICMP && ip->ip_p != IPPROTO_TCP && ip->ip_p != IPPROTO_UDP) {
		return;
	}

	// SYNC Flag ?
	syn = ip->ip_p == IPPROTO_TCP && (tcp_header->th_flags & TH_SYN) && !(tcp_header->th_flags & TH_ACK);

	// Check if buffer list has been created
	if (DV_l == NULL) {
		// Initialize buffer
		DV_Init();
	}

	// List is valid?
	if (DV_l == NULL) 
	{
		fprintf(stderr,"DV_addPacket: List is not valid!!\n");
		exit(1);
	}

	/*
	// Inbound or Outbound ?
	inbound = ip->ip_dst.s_addr == own_ip;
	*/

	info = malloc(sizeof(struct DV_info));
	if (info == NULL) {
		fprintf(stderr,"DV_addPacket: Could not allocate memory!!\n");
		exit(1);				
	}

	// Store current time
	info->time = time(NULL);

	// Store priority
	info->priority = priority;

	// Store IP Protocol
	info->ip_protocol = ip->ip_p;

	// Store Source and Destination IP address
	info->ip_src = ip->ip_src;
	info->ip_dst = ip->ip_dst;

	// Protocol?
	switch (ip->ip_p) {
		case IPPROTO_ICMP:
			// Store ICMP type and code
			info->shared_info.icmp_info.type = icmp_header->icmp_type;
			info->shared_info.icmp_info.code = icmp_header->icmp_code;
			timeout = 0;
			break;
		case IPPROTO_TCP:
			// Store source and destination port, and TCP flags
			info->shared_info.tcp_info.sport = ntohs(tcp_header->th_sport);
			info->shared_info.tcp_info.dport = ntohs(tcp_header->th_dport);
			info->shared_info.tcp_info.flags = tcp_header->th_flags;
			timeout = TCP_TIMEOUT;
			break;
		case IPPROTO_UDP:
			// Store source and destination port
			info->shared_info.udp_info.sport = ntohs(udp_header->uh_sport);
			info->shared_info.udp_info.dport = ntohs(udp_header->uh_dport);
			timeout = ANY_TIMEOUT;
			break;	
	}

	/*
	if (inbound) {
	*/
		// Store timestamp of last inbound
		info->time_inbound = info->time;

		// Connection (node list) exist?
		if (sem_wait(&mutex_bp)) 
		{
			perror("DV_addPacket: sem_wait with mutex_bp");
			exit(1);
		}
		node = find_sorted_list(DV_l, (void *)info, DV_Equals);
		if (sem_post(&mutex_bp))
		{
			perror("DV_addPacket: sem_post with mutex_bp");
			exit(1);		
		}
		

		if (node == NULL) {
			// The connection is new. We only accept new TCP connections if syn flag is on and ack is off
			if (ip->ip_p == IPPROTO_TCP && !syn) {
				// Discard TCP connection
				free(info);
				return;
			}

			info->last_connections = NULL;
			init_double_list(&info->last_connections);
			info->hits = 1;
			info->total_bytes = 0;
		}
		else {
			old_info = (struct DV_info *) node->info;
			info->hits = old_info->hits + 1;
			info->total_bytes = old_info->total_bytes;
			info->last_connections = old_info->last_connections;
			/*
			// Copy old last connections (to calculate bandwith)
			// But before, we remove all connections older than INTERVAL_BANDWITH seconds
			stop = syn || (timeout && info->time - old_info->time_inbound > timeout);
			while (!stop && !isEmpty_double_list(old_info->last_connections)) {
				old_info_bandwidth = (struct DV_info_bandwidth *) tail_double_list(old_info->last_connections);
				stop = info->time - old_info_bandwidth->time > INTERVAL_BANDWITH;
				if (!stop) {
					info_bandwidth = malloc(sizeof(struct DV_info_bandwidth));
					if (info_bandwidth == NULL) {
						fprintf(stderr,"DV_addPacket: Could not allocate memory!!\n");
						exit(1);				
					}
					info_bandwidth->time = old_info_bandwidth->time;
					info_bandwidth->n_bytes = old_info_bandwidth->n_bytes;
					insert_front_double_list(info->last_connections, (void *)info_bandwidth);
					remove_tail_double_list(old_info->last_connections);
				}
			}
			*/
			if (syn || (timeout && info->time - old_info->time_inbound > timeout)) {
				// New connection or timeout. Remove all last connections
				clear_all_double_list(old_info->last_connections);
			}
		}
	/*
	}
	*/
	/*
	else {
		// Outbound package
		// Protocol wanted??
		if (ip->ip_p != IPPROTO_TCP && ip->ip_p != IPPROTO_UDP) {
			free(info);
			return;
		}

		// relative incoming connection (node list) exist?
		if (sem_wait(&mutex_bp)) 
		{
			perror("DV_addPacket: sem_wait with mutex_bp");
			exit(1);
		}
		node = find_sorted_list(DV_l, (void *)info, DV_Reverse);
		if (sem_post(&mutex_bp))
		{
			perror("DV_addPacket: sem_post with mutex_bp");
			exit(1);		
		}

		if (node == NULL) {
			free(info);
			return;
		}
		old_info = (struct DV_info *) node->info;

		// Timeout?
		if (info->time - old_info->time_inbound > timeout) {
			free(info);
			return;
		}

		info->time_inbound = old_info->time_inbound;
		info->hits = old_info->hits;
		info->last_connections = old_info->last_connections;
		info->total_bytes = old_info->total_bytes;
		info->ip_src = old_info->ip_src;
		info->ip_dst = old_info->ip_dst;
		if (ip->ip_p == IPPROTO_TCP) {
			info->shared_info.tcp_info.sport = old_info->shared_info.tcp_info.sport;
			info->shared_info.tcp_info.dport = old_info->shared_info.tcp_info.dport;		
		}
		else {
			info->shared_info.udp_info.sport = old_info->shared_info.udp_info.sport;
			info->shared_info.udp_info.dport = old_info->shared_info.udp_info.dport;					
		}

	}
	*/

	// Add current size to totals
	info->total_bytes = info->total_bytes + n_bytes;

	// Add current connection to last connections (to calculate bandwith)
	// Before, we remove all connections older than INTERVAL_BANDWITH seconds
	stop = 0;
	while (!stop && !isEmpty_double_list(info->last_connections)) {
		info_bandwidth = (struct DV_info_bandwidth *) front_double_list(info->last_connections);
		stop = info->time - info_bandwidth->time <= INTERVAL_BANDWITH;
		if (!stop) {
			// We have to remove this last connection
			remove_front_double_list(info->last_connections);
		}
	}


	info_bandwidth = malloc(sizeof(struct DV_info_bandwidth));
	if (info_bandwidth == NULL) {
		fprintf(stderr,"DV_addPacket: Could not allocate memory!!\n");
		exit(1);				
	}
	info_bandwidth->time = info->time;
	info_bandwidth->n_bytes = n_bytes;
	insert_tail_double_list(info->last_connections, (void *)info_bandwidth);


	// Insert info in the list
	if (sem_wait(&mutex_bp)) 
	{
		perror("DV_addPacket: sem_wait with mutex_bp");
		exit(1);
	}
	if (node != NULL) {
		removeNode_sorted_list(DV_l, (void *)node);
	}
	insert_sorted_list(DV_l, (void *)info);

	/***************************  DEBUG ***************************
	{
		char m[100];
		sprintf(m, "List size: %u", size_sorted_list(DV_l));
		debugMessageXY(0, 0, m, NULL, 1);
	}
	****************************************************************/

	if (sem_post(&mutex_bp))
	{
		perror("DV_addPacket: sem_post with mutex_bp");
		exit(1);		
	}
}

float calculateBandwidth(time_t now, struct DV_info *info) {
	unsigned long total_bytes = 0;
	struct DV_info_bandwidth *info_bandwidth;	
	time_t t;

	// Get time of older connection
	t = now;
	if (!isEmpty_double_list(info->last_connections)) {
		info_bandwidth = (struct DV_info_bandwidth *)front_double_list(info->last_connections);
		t = info_bandwidth->time;
	}
	
	for_each_double_list(info->last_connections, accumulateBytes, (void *)&total_bytes);

	if (total_bytes) {
		return (float)total_bytes / (1024.0 * (now - t + 1));
	}
	else {
		return 0.0;
	}
}

void accumulateBytes(void *val, void *total) {
	*(unsigned long *)total += ((struct DV_info_bandwidth *)val)->n_bytes;
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
	struct DV_info *info1, *info2;

	info1 = (struct DV_info *)val1;
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

	diff_time1 = now - info1->time_inbound;
	diff_time2 = now - info2->time_inbound ;

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

void DV_Purge() {
	struct node_sorted_list *node, *prev_node;
	struct DV_info *info;
	time_t now;
	unsigned timeout;

	// List is valid?
	if (DV_l == NULL) 
	{
		return;
	}

	now = time(NULL);

	if (sem_wait(&mutex_bp)) 
	{
		perror("DV_Purge: sem_wait with mutex_bp");
		exit(1);
	}

	prev_node = NULL;
	node = DV_l->header;
	while (node != NULL) {
		info = (struct DV_info *)node->info;

		if (info->ip_protocol == IPPROTO_TCP) {
			timeout = TCP_TIMEOUT;
		}
		else {
			timeout = ANY_TIMEOUT;
		}	

		// Timeout?
		if (now - info->time_inbound > timeout) {
			// have to delete node
			clear_all_double_list(info->last_connections);
			free(info->last_connections);
			if (prev_node == NULL) {
				DV_l->header = node->next;
				free(node->info);
				free(node);
				node = DV_l->header;
			}
			else {
				// Node to remove is the first node
				prev_node->next = node->next;
				free(node->info);
				free(node);
				node = prev_node->next;
			}
			result_count_lines--;
			DV_l->n_elements--;
		}
		else {
			prev_node = node;
			node = node->next;
		}
	}


	if (sem_post(&mutex_bp))
	{
		perror("DV_Purge: sem_post with mutex_bp");
		exit(1);		
	}
}

