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
#include <IPGroupedView.h>

// Constants
#define	TCP_TIMEOUT		900
#define ANY_TIMEOUT 	300
#define RECENT_TIMEOUT	3
#define MAX_SERVICES	5

// Global vars
sorted_list IPG_l = NULL;
extern sem_t mutex_bp;
extern int result_count_lines;

// Function prototypes
void IPG_ShowElement(void *data, void *param);
void IPG_ShowElementService(void *data, void *cont_services);
void IPG_ShowServices();
void IPG_addService(struct IPG_info *info, const struct ip *ip, const struct icmp *icmp_header,
				    const struct tcphdr *tcp_header, const struct udphdr *udp_header, unsigned priority);
int IPG_Equals(void *val1, void *val2);
int IPG_Compare(void *val1, void *val2);
int IPG_EqualsService(void *val1, void *val2);
int IPG_CompareService(void *val1, void *val2);
void IPG_PurgeServices();

void IPG_Init() {
	if (sem_wait(&mutex_bp)) 
	{
		perror("IPG_Init: sem_wait with mutex_bp");
		exit(1);
	}
	init_sorted_list(&IPG_l, IPG_Compare);
	if (sem_post(&mutex_bp))
	{
		perror("IPG_Init: sem_post with mutex_bp");
		exit(1);		
	}
}

void IPG_Reset() {
	clear_all_sorted_list(IPG_l);
}

void IPG_ShowElement(void *data, void *param) {
	struct IPG_info *info;
	struct tm *t;
	time_t now;
	char s_time[20];
	char line[100];
	char s_ip_src[INET_ADDRSTRLEN], s_ip_dst[INET_ADDRSTRLEN];
	attr_t attr, *p_attr;

	now = time(NULL);

	info = (struct IPG_info *)data;

	t = localtime(&info->time_inbound);
	sprintf(s_time, "%02d/%02d/%4d %02d:%02d:%02d", t->tm_mday, t->tm_mon, 1900+t->tm_year, t->tm_hour, t->tm_min, t->tm_sec);

	inet_ntop(AF_INET, &(info->ip_src), s_ip_src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(info->ip_dst), s_ip_dst, INET_ADDRSTRLEN);

	sprintf(line, "%s  [%05lu] %17s :", s_time, info->hits, s_ip_src);

	if (info->priority == 1 && now - info->time_inbound < RECENT_TIMEOUT) {
		p_attr = NULL;
	}
	else {
		p_attr = &attr;
	}
	attr = COLOR_PAIR(info->priority);
	writeLineOnResult(line, p_attr);

	IPG_ShowServices(info->l_services);

	writeLineOnResult("\n", NULL);

	result_count_lines++;
}

void IPG_ShowInfo() {
	if (IPG_l == NULL) {
		return;
	}

	result_count_lines = 0;
	if (sem_wait(&mutex_bp)) 
	{
		perror("IPG_ShowInfo: sem_wait with mutex_bp");
		exit(1);
	}
	for_each_sorted_list(IPG_l, IPG_ShowElement, NULL);
	if (sem_post(&mutex_bp))
	{
		perror("IPG_ShowInfo: sem_post with mutex_bp");
		exit(1);		
	}
}

void IPG_ShowElementService(void *data, void *cont_services) {
	struct IPG_service_info *info;
	time_t now;
	char line[50];
	char s_protocol[5];
	struct servent *servinfo;
	char s_vicmp[][50] = {"Echo Reply","","","Destination Unreachable","Source Quench","Redirect Message","","",
						  "Echo Request","Router Advertisement","Router Solicitation","Time Exceeded","Bad IP header",
						  "Timestamp Request","Timestamp Reply","Information Request","Information Reply","Address Mask Request",
						  "Adress Mask Reply"};
	char s_icmp[50];
	attr_t attr, *p_attr;
	char *service_alias;


	if (*(unsigned *)cont_services == MAX_SERVICES) {
		return;
	}
	*(unsigned *)cont_services++;
	
	now = time(NULL);

	info = (struct IPG_service_info *)data;

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
				sprintf(s_icmp, "%u", info->shared_info.icmp_info.type);
			}
			sprintf(line, " [%lu]%s/%s\n", info->hits, s_protocol, s_icmp);
			break;
		case IPPROTO_TCP:
			strcpy(s_protocol, "tcp");
			service_alias = serviceShortAlias(info->ip_protocol, info->shared_info.tcp_info.dport);
			if (service_alias != NULL && strcmp(service_alias, "")) {
				sprintf(line, "  [%lu]%s", info->hits, service_alias);
			}
			else {
				servinfo = getservbyport(htons(info->shared_info.tcp_info.dport), s_protocol);
				if (servinfo != NULL && servinfo->s_name != NULL && strcmp(servinfo->s_name, "")) {
					sprintf(line, "  [%lu]%s", info->hits, servinfo->s_name);
				}
				else {
					sprintf(line, "  [%lu]%s/%u", info->hits, s_protocol, info->shared_info.tcp_info.dport);				
				}
			}
			break;
		case IPPROTO_UDP:
			strcpy(s_protocol, "udp");
			service_alias = serviceShortAlias(info->ip_protocol, info->shared_info.udp_info.dport);
			if (service_alias != NULL && strcmp(service_alias, "")) {
				sprintf(line, "  [%lu]%s", info->hits, service_alias);
			}
			else {
				servinfo = getservbyport(htons(info->shared_info.udp_info.dport), s_protocol);
				if (servinfo != NULL && servinfo->s_name != NULL && strcmp(servinfo->s_name, "")) {
					sprintf(line, "  [%lu]%s", info->hits, servinfo->s_name);
				}
				else {
					sprintf(line, "  [%lu]%s/%u", info->hits, s_protocol, info->shared_info.udp_info.dport);				
				}
			}
			break;	
	}

	if (info->priority == 1 && now - info->time_inbound < RECENT_TIMEOUT) {
		p_attr = NULL;
	}
	else {
		p_attr = &attr;
	}
	attr = COLOR_PAIR(info->priority);
	writeLineOnResult(line, p_attr);
}

void IPG_ShowServices(sorted_list l) {
	unsigned cont_services;

	if (l == NULL) {
		return;
	}

	cont_services = 0;
	for_each_sorted_list(l, IPG_ShowElementService, (void *)&cont_services);
}


void IPG_addPacket(const struct ether_header *ethernet,const struct ip *ip,const struct icmp *icmp_header,
				   const struct tcphdr *tcp_header,const struct udphdr *udp_header,const struct igmp *igmp_header, unsigned n_bytes, unsigned priority) {

	struct IPG_info *info, *old_info;
	struct node_sorted_list *node;
	unsigned timeout;
	int syn;

	// Protocol wanted??
	if (ip->ip_p != IPPROTO_ICMP && ip->ip_p != IPPROTO_TCP && ip->ip_p != IPPROTO_UDP) {
		return;
	}

	// SYNC Flag ?
	syn = ip->ip_p == IPPROTO_TCP && tcp_header->th_flags & TH_SYN && !(tcp_header->th_flags & TH_ACK);

	// Check if buffer list has been created
	if (IPG_l == NULL) {
		// Initialize buffer
		IPG_Init();
	}

	// List is valid?
	if (IPG_l == NULL) 
	{
		fprintf(stderr,"IPG_addPacket: List is not valid!!\n");
		exit(1);
	}

	info = malloc(sizeof(struct IPG_info));
	if (info == NULL) {
		fprintf(stderr,"IPG_addPacket: Could not allocate memory!!\n");
		exit(1);				
	}

	// Store current time
	info->time = time(NULL);

	// Store priority
	info->priority = priority;

	// Store Source and Destination IP address
	info->ip_src = ip->ip_src;
	info->ip_dst = ip->ip_dst;

	// Store timestamp of last inbound
	info->time_inbound = info->time;

	// Source IP (node list) exist?
	if (sem_wait(&mutex_bp)) 
	{
		perror("IPG_addPacket: sem_wait with mutex_bp");
		exit(1);
	}
	node = find_sorted_list(IPG_l, (void *)info, IPG_Equals);
	if (sem_post(&mutex_bp))
	{
		perror("IPG_addPacket: sem_post with mutex_bp");
		exit(1);		
	}
	

	if (node == NULL) {
		// The source IP is new. We only accept new TCP connections if syn flag is on and ack is off
		if (ip->ip_p == IPPROTO_TCP && !syn) {
			// Discard TCP connection
			free(info);
			return;
		}

		info->hits = 1;
		info->first_time = info->time;
		info->l_services = NULL;
		init_sorted_list(&info->l_services, IPG_CompareService);
//			info->n_bytes = 0;
//			info->total_bytes = 0;
	}
	else {
		old_info = (struct IPG_info *) node->info;

		info->first_time = old_info->first_time;
		info->hits = old_info->hits + 1;
		info->l_services = old_info->l_services;
		//info->n_bytes = old_info->n_bytes;
		//info->total_bytes = old_info->total_bytes;

		// Sync Flag or Timeout?
		if (timeout && info->time - old_info->time_inbound > timeout) {
			// Timeout or connection reset
			info->first_time = info->time;
			clear_all_sorted_list(info->l_services);
			//info->n_bytes = 0;
		}
	}

	// Add current size to totals
	//info->n_bytes = info->n_bytes + n_bytes;
	//info->total_bytes = info->total_bytes + n_bytes;

	// Add service to list of services
	IPG_addService(info, ip, icmp_header, tcp_header, udp_header, priority);

	// Insert info in the list of connections
	if (sem_wait(&mutex_bp)) 
	{
		perror("IPG_addPacket: sem_wait with mutex_bp");
		exit(1);
	}
	if (node != NULL) {
		removeNode_sorted_list(IPG_l, (void *)node);
	}
	insert_sorted_list(IPG_l, (void *)info);

	/***************************  DEBUG ***************************
	{
		char m[100];
		sprintf(m, "List size: %u", size_sorted_list(IPG_l));
		debugMessageXY(0, 0, m, NULL, 1);
	}
	/****************************************************************/

	if (sem_post(&mutex_bp))
	{
		perror("IPG_addPacket: sem_post with mutex_bp");
		exit(1);		
	}
}

void IPG_addService(struct IPG_info *info, const struct ip *ip, const struct icmp *icmp_header,
				    const struct tcphdr *tcp_header, const struct udphdr *udp_header, unsigned priority) {
	struct IPG_service_info *info_service, *old_info_service;
	struct node_sorted_list *node;
	unsigned timeout;
	int syn;

	// SYNC Flag ?
	syn = ip->ip_p == IPPROTO_TCP && tcp_header->th_flags & TH_SYN && !(tcp_header->th_flags & TH_ACK);


	info_service = malloc(sizeof(struct IPG_service_info));
	if (info_service == NULL) {
		fprintf(stderr,"IPG_addService: Could not allocate memory!!\n");
		exit(1);				
	}

	// Store current time
	info_service->time = info->time;

	// Store priority
	info_service->priority = priority;

	// Store IP Protocol
	info_service->ip_protocol = ip->ip_p;

	// Protocol?
	switch (ip->ip_p) {
		case IPPROTO_ICMP:
			// Store ICMP type and code
			info_service->shared_info.icmp_info.type = icmp_header->icmp_type;
			info_service->shared_info.icmp_info.code = icmp_header->icmp_code;
			timeout = 0;
			break;
		case IPPROTO_TCP:
			// Store source and destination port, and TCP flags
			info_service->shared_info.tcp_info.sport = ntohs(tcp_header->th_sport);
			info_service->shared_info.tcp_info.dport = ntohs(tcp_header->th_dport);
			info_service->shared_info.tcp_info.flags = tcp_header->th_flags;
			timeout = TCP_TIMEOUT;
			break;
		case IPPROTO_UDP:
			// Store source and destination port
			info_service->shared_info.udp_info.sport = ntohs(udp_header->uh_sport);
			info_service->shared_info.udp_info.dport = ntohs(udp_header->uh_dport);
			timeout = ANY_TIMEOUT;
			break;	
	}

	// Store timestamp of last inbound
	info_service->time_inbound = info_service->time;

	// Connection (node list) exist?
	node = find_sorted_list(info->l_services, (void *)info_service, IPG_EqualsService);	

	if (node == NULL) {
		// The connection is new. We only accept new TCP connections if syn flag is on and ack is off
		if (ip->ip_p == IPPROTO_TCP && !syn) {
			// Discard TCP connection
			free(info_service);
			return;
		}

		info_service->hits = 1;
		info_service->first_time = info_service->time;
		//info_service->n_bytes = 0;
		//info_service->total_bytes = 0;
	}
	else {
		old_info_service = (struct IPG_service_info *) node->info;

		info_service->first_time = old_info_service->first_time;
		info_service->hits = old_info_service->hits + 1;
		//info_service->n_bytes = old_info_service->n_bytes;
		//info_service->total_bytes = old_info_service->total_bytes;

		// Sync Flag or Timeout?
		if (syn || (timeout && info_service->time - old_info_service->time_inbound > timeout)) {
			// Timeout or connection reset
			info_service->first_time = info_service->time;
			//info_service->n_bytes = 0;
		}
	}

	// Add current size to totals
	//info_service->n_bytes = info_service->n_bytes + n_bytes;
	//info_service->total_bytes = info_service->total_bytes + n_bytes;

	// Insert info in the list
	if (node != NULL) {
		removeNode_sorted_list(info->l_services, (void *)node);
	}
	insert_sorted_list(info->l_services, (void *)info_service);

	/***************************  DEBUG ***************************
	{
		char m[100];
		sprintf(m, "Service list size: %u", size_sorted_list(info->l_services));
		debugMessageXY(1, 0, m, NULL, 1);
	}
	/****************************************************************/
}

int IPG_Equals(void *val1, void *val2) {
	struct IPG_info *info1, *info2;

	info1 = (struct IPG_info *)val1;
	info2 = (struct IPG_info *)val2;

	return !(info1->ip_src.s_addr == info2->ip_src.s_addr);
}

int IPG_Compare(void *val1, void *val2) {
	struct IPG_info *info1, *info2;
	unsigned long grade1, grade2;
	time_t now, diff_time1, diff_time2;

	now = time(NULL);

	info1 = (struct IPG_info *)val1;
	info2 = (struct IPG_info *)val2;

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

int IPG_EqualsService(void *val1, void *val2) {
	struct IPG_service_info *info1, *info2;

	info1 = (struct IPG_service_info *)val1;
	info2 = (struct IPG_service_info *)val2;

	if (info1->ip_protocol != info2->ip_protocol)
		return(1);

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


int IPG_CompareService(void *val1, void *val2) {
	struct IPG_service_info *info1, *info2;
	unsigned long grade1, grade2;
	time_t now, diff_time1, diff_time2;

	now = time(NULL);

	info1 = (struct IPG_service_info *)val1;
	info2 = (struct IPG_service_info *)val2;

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

void IPG_Purge() {
	struct node_sorted_list *node, *prev_node;
	struct IPG_info *info;
	time_t now;
	unsigned timeout;

	// List is valid?
	if (IPG_l == NULL) 
	{
		return;
	}

	now = time(NULL);

	if (sem_wait(&mutex_bp)) 
	{
		perror("IPG_Purge: sem_wait with mutex_bp");
		exit(1);
	}

	prev_node = NULL;
	node = IPG_l->header;
	while (node != NULL) {
		info = (struct IPG_info *)node->info;

		IPG_PurgeServices(info->l_services);

		if (isEmpty_sorted_list(info->l_services)) {
			// have to delete node
			if (prev_node == NULL) {
				IPG_l->header = node->next;
				free(node->info);
				free(node);
				node = IPG_l->header;
			}
			else {
				prev_node->next = node->next;
				free(node->info);
				free(node);
				node = prev_node->next;
			}
			result_count_lines--;
			IPG_l->n_elements--;
		}
		else {
			prev_node = node;
			node = node->next;
		}
	}


	if (sem_post(&mutex_bp))
	{
		perror("IPG_Purge: sem_post with mutex_bp");
		exit(1);		
	}
}

void IPG_PurgeServices(sorted_list l) {
	struct node_sorted_list *node, *prev_node;
	struct IPG_service_info *info;
	time_t now;
	unsigned timeout;

	// List is valid?
	if (l == NULL) 
	{
		return;
	}

	now = time(NULL);

	prev_node = NULL;
	node = l->header;
	while (node != NULL) {
		info = (struct IPG_service_info *)node->info;

		if (info->ip_protocol == IPPROTO_TCP) {
			timeout = TCP_TIMEOUT;
		}
		else {
			timeout = ANY_TIMEOUT;
		}	

		// Timeout?
		if (now - info->time_inbound > timeout) {
			// have to delete node
			if (prev_node == NULL) {
				l->header = node->next;
				free(node->info);
				free(node);
				node = l->header;
			}
			else {
				prev_node->next = node->next;
				free(node->info);
				free(node);
				node = prev_node->next;
			}
			l->n_elements--;
		}
		else {
			prev_node = node;
			node = node->next;
		}
	}
}