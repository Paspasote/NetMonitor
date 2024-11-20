#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <curses.h>
#include <semaphore.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <GlobalVars.h>
#include <misc.h>
#include <Configuration.h>
#include <SortedList.h>
#include <SharedSortedList.h>
#include <Configuration.h>
#include <iptables.h>
#include <interface.h>
#ifdef DEBUG
#include <debug.h>
#endif

#include <OutNATView.h>

// EXTERNAL Global vars
extern struct const_global_vars c_globvars;
extern struct write_global_vars w_globvars;

// Global vars

// Function prototypes
int ONATV_isValidList();
void ONATV_createList();
int ONATV_isValidConnList(shared_sorted_list list, pthread_mutex_t mutex);

void ONATV_updateList();
void ONATV_freeRequests(struct ONATV_info *info, shared_sorted_list conn_list, struct node_shared_sorted_list *conn_node, int leave_read);
void ONATV_ShowElement(void *data, void *param);

void ONATV_Reset();

int OV_Compare(void *val1, void *val2);


int ONATV_isValidList() {

	return w_globvars.ONATV_l != NULL;
}

void ONATV_createList() {
	init_sorted_list(&w_globvars.ONATV_l, OV_Compare);
}

int ONATV_isValidConnList(shared_sorted_list list, pthread_mutex_t mutex) 
{
	int ret;

	if (pthread_mutex_lock(&mutex)) 
	{
		perror("ONATV_isValidConnList: pthread_mutex_lock with mutex list");
		exit(1);
	}
	ret = list != NULL;
	if (pthread_mutex_unlock(&mutex))
	{
		perror("ONATV_isValidConnList: pthread_mutex_unlock with mutex list");
		exit(1);		
	}

	return ret;
}

void ONATV_updateList()
{
    shared_sorted_list *hash_table;
	pthread_mutex_t *mutex;
	int i;
	struct node_shared_sorted_list *node;
	struct ONATV_info *info;

	if (!isEmpty_sorted_list(w_globvars.ONATV_l))
	{
		ONATV_Reset();
	}

    // Iterate buckets of outgoing intranet hash table
	hash_table = w_globvars.conn_intranet_out;
	mutex = &w_globvars.mutex_conn_intranet_out;
    for (i=0; i<65536; i++)
    {
        // Is list valid?
        if (ONATV_isValidConnList(hash_table[i], *mutex))
        {
            // Iterate the bucket's list 
            node = firstNode_shared_sorted_list(hash_table[i]);
            while (node != NULL) 
			{
				// Allocate memory for this connection
				info = (struct ONATV_info *) malloc(sizeof(struct ONATV_info));
				if (info == NULL) 
				{
					fprintf(stderr,"ONATV_updateList: Could not allocate memory!!\n");
					exit(1);				
				}

                // Save the connection info
				info->conn_node = node;
				info->conn_list = hash_table[i];
				strcpy(info->country, "");
				strcpy(info->netname, "");
				strcpy(info->flags, "     ");
				info->stablished = 0;

				// Insert the new connection in the list
				insert_sorted_list(w_globvars.ONATV_l, info);

				// Next node
				// We don't leave node's access because node view is pointing to this node connection
				node = nextNode_shared_sorted_list(hash_table[i], node, 0);
            }
        }
    }

}


void ONATV_freeRequests(struct ONATV_info *info, shared_sorted_list conn_list, struct node_shared_sorted_list *conn_node, int leave_read)
{
	if (leave_read)
	{
		leaveReadNode_shared_sorted_list(conn_node);
	}
	info->conn_list = NULL;
	info->conn_node = NULL;
	leaveNode_shared_sorted_list(conn_list, conn_node);

#ifdef DEBUG
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "Interface: ShowElement finished");
		debugMessageModule(INTERFACE, m, NULL, 1);
	}
#endif

}

void ONATV_ShowElement(void *data, void *param) {
	struct ONATV_info *info;
	struct connection_info *conn;
	struct tm *t;
	time_t now;
	char s_time[20];
	char line[250];
	char s_protocol[5];
	struct servent *servinfo;
	char s_ip_src[INET_ADDRSTRLEN], s_ip_dst[INET_ADDRSTRLEN];
	char s_icmp[50];
	char total_bytes[20];
	char *service_alias;
	struct node_shared_sorted_list *conn_node;
	shared_sorted_list conn_list;


#ifdef DEBUG
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "Interface: ShowElement start...");
		debugMessageModule(INTERFACE, m, NULL, 1);
	}
#endif

	info = (struct ONATV_info *)data;
	conn_node = info->conn_node;
	conn_list = info->conn_list;

#ifdef DEBUG
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "Interface: ShowElement before request read access to connection node...");
		debugMessageModule(INTERFACE, m, NULL, 1);
	}
#endif

	// Read access to connection node
	if (!requestReadNode_shared_sorted_list(conn_node))
	{
#ifdef DEBUG
		// This should never happen
		fprintf(stderr, "ONATV_ShowElement: Connection pointed by node view was removed!!");
		exit(EXIT_FAILURE);
#endif
		ONATV_freeRequests(info, conn_list, conn_node, 0);
		return;
	}
	conn = (struct connection_info *)info->conn_node->info;

	if (!conn->starting) {
		ONATV_freeRequests(info, conn_list, conn_node, 1);
		return;
	}	

#ifdef DEBUG
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "Interface: ShowElement after request read access to connection node...");
		debugMessageModule(INTERFACE, m, NULL, 1);
	}
#endif


	now = time(NULL);

	t = localtime(&conn->time);
	sprintf(s_time, "%02d/%02d/%4d %02d:%02d:%02d", t->tm_mday, t->tm_mon, 1900+t->tm_year, t->tm_hour, t->tm_min, t->tm_sec);

	inet_ntop(AF_INET, &(conn->ip_src), s_ip_src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(conn->ip_dst), s_ip_dst, INET_ADDRSTRLEN);

	if ((float)conn->total_bytes / 1024.0 > 99999.99) {
		sprintf(total_bytes, "[%8.2f MB]", (float)conn->total_bytes / (1024.0*1024.0));
	}
	else {
		sprintf(total_bytes, "[%8.2f KB]", (float)conn->total_bytes / 1024.0);
	}

	// Protocol?
	switch (conn->ip_protocol) {
		case IPPROTO_ICMP:
			if (now - conn->time >= ANY_VISIBLE_TIMEOUT) {
				// Visibility timeout
				ONATV_freeRequests(info, conn_list, conn_node, 1);
				return;
			}

			// Check if we have to update whois info
			if (!strcmp(info->country, ""))
			{
				updateWhoisInfo(conn->ip_dst.s_addr, info->country, info->netname);
			}

			// Update Respond/Stablished flag
			if (!conn->starting)
			{
				info->flags[FLAG_RESPOND_POS] = FLAG_RESPOND;
			}
			else
			{
				if (conn->stablished)
				{
					info->flags[FLAG_STABLISHED_POS] = FLAG_STABLISHED;
				}
				else
				{
					info->flags[FLAG_NEW_POS] = FLAG_NEW;
				}
			}
			// Update NAT flag
			info->flags[FLAG_NAT_POS] = FLAG_NAT;

			// Generate line info
			strcpy(s_protocol, "ICMP");
			s_icmp_type(conn->shared_info.icmp_info.type, conn->shared_info.icmp_info.code, s_icmp);
			sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s  %15s %-5s  %2s  %-16s  %-5s%s\n", s_time, conn->hits, total_bytes, conn->bandwidth, s_ip_src, s_ip_dst, info->flags, info->country, info->netname, s_protocol, s_icmp);
			break;
		case IPPROTO_TCP:
			if (now - conn->time >= TCP_VISIBLE_TIMEOUT) {
				// Visibility timeout
				ONATV_freeRequests(info, conn_list, conn_node, 1);
				return;
			}

			// Check if we have to update whois info
			if (!strcmp(info->country, ""))
			{
				updateWhoisInfo(conn->ip_dst.s_addr, info->country, info->netname);
			}

			// Update Respond/Stablished flag
			if (!conn->starting)
			{
				info->flags[FLAG_RESPOND_POS] = FLAG_RESPOND;
			}
			else
			{
				if (conn->stablished)
				{
					info->flags[FLAG_STABLISHED_POS] = FLAG_STABLISHED;
				}
				else
				{
					info->flags[FLAG_NEW_POS] = FLAG_NEW;
				}
			}
			// Update NAT flag
			info->flags[FLAG_NAT_POS] = FLAG_NAT;

			// Generate line info
			strcpy(s_protocol, "tcp");
			service_alias = serviceAlias(conn->ip_protocol, conn->shared_info.tcp_info.dport);
			if (service_alias != NULL && strcmp(service_alias, "")) {
				sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s  %15s %-5s  %2s  %-16s  %s\n", s_time, conn->hits, total_bytes, conn->bandwidth, s_ip_src, s_ip_dst, info->flags, info->country, info->netname, service_alias);				
			}
			else {
				servinfo = getservbyport(htons(conn->shared_info.tcp_info.dport), s_protocol);
				if (servinfo != NULL && servinfo->s_name != NULL && strcmp(servinfo->s_name, "")) {
					sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s  %15s %-5s  %2s  %-16s  %s\n", s_time, conn->hits, total_bytes, conn->bandwidth, s_ip_src, s_ip_dst, info->flags, info->country, info->netname, servinfo->s_name);
				}
				else {
					sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s  %15s %-5s  %2s  %-16s  %-5s%5u\n", s_time, conn->hits, total_bytes, conn->bandwidth, s_ip_src, s_ip_dst, info->flags, info->country, info->netname, s_protocol, conn->shared_info.tcp_info.dport);				
				}
			}
			break;
		case IPPROTO_UDP:
			if (now - conn->time >= UDP_VISIBLE_TIMEOUT) {
				// Visibility timeout
				ONATV_freeRequests(info, conn_list, conn_node, 1);
				return;
			}

			// Check if we have to update whois info
			if (!strcmp(info->country, ""))
			{
				updateWhoisInfo(conn->ip_dst.s_addr, info->country, info->netname);
			}
			// Update Respond/Stablished flag
			if (!conn->starting)
			{
				info->flags[FLAG_RESPOND_POS] = FLAG_RESPOND;
			}
			else
			{
				if (conn->stablished)
				{
					info->flags[FLAG_STABLISHED_POS] = FLAG_STABLISHED;
				}
				else
				{
					info->flags[FLAG_NEW_POS] = FLAG_NEW;
				}
			}
			// Update NAT flag
			info->flags[FLAG_NAT_POS] = FLAG_NAT;

			// Generate line info
			strcpy(s_protocol, "udp");
			service_alias = serviceAlias(conn->ip_protocol, conn->shared_info.udp_info.dport);
			if (service_alias != NULL && strcmp(service_alias, "")) {
				sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s  %15s %-5s  %2s  %-16s  %s\n", s_time, conn->hits, total_bytes, conn->bandwidth, s_ip_src, s_ip_dst, info->flags, info->country, info->netname, service_alias);				
			}
			else {
				servinfo = getservbyport(htons(conn->shared_info.udp_info.dport), s_protocol);
				if (servinfo != NULL && servinfo->s_name != NULL && strcmp(servinfo->s_name, "")) {
					sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s  %15s %-5s  %2s  %-16s  %s\n", s_time, conn->hits, total_bytes, conn->bandwidth, s_ip_src, s_ip_dst, info->flags, info->country, info->netname, servinfo->s_name);
				}
				else {
					sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s  %15s %-5s  %2s  %-16s  %-5s%5u\n", s_time, conn->hits, total_bytes, conn->bandwidth, s_ip_src, s_ip_dst, info->flags, info->country, info->netname, s_protocol, conn->shared_info.udp_info.dport);				
				}
			}
			break;	
	}

	writeLineOnResult(line, COLOR_PAIR(conn->priority), now - conn->time <= RECENT_TIMEOUT);

	ONATV_freeRequests(info, conn_list, conn_node, 1);
	w_globvars.result_count_lines++;
}

void ONATV_ShowInfo() {  
	// Is list created?
	if (!ONATV_isValidList())
	{
		ONATV_createList();
	}

	// Is list valid?
	if (!ONATV_isValidList())
	{
		fprintf(stderr,"ONATV_ShowInfo: List is not valid!!\n");
		exit(1);
	}

	ONATV_updateList();

	// Iterate the list and show info on screen
	w_globvars.result_count_lines = 0;
	for_each_sorted_list(w_globvars.ONATV_l, ONATV_ShowElement, NULL);
}

void ONATV_Reset() {
	// List is valid?
	if (ONATV_isValidList())
	{
		clear_all_sorted_list(w_globvars.ONATV_l, 1, NULL, NULL);
	}

}

int OV_Compare(void *val1, void *val2) {
	struct ONATV_info *info1, *info2;
	struct connection_info *conn1, *conn2;
	float grade1, grade2;

	info1 = (struct ONATV_info *)val1;
	info2 = (struct ONATV_info *)val2;

	if (requestReadNode_shared_sorted_list(info1->conn_node) &&
	    requestReadNode_shared_sorted_list(info2->conn_node))
	{
		conn1 = info1->conn_node->info;
		conn2 = info2->conn_node->info;

		grade1 = conn1->bandwidth;
		grade2 = conn2->bandwidth;

		leaveReadNode_shared_sorted_list(info1->conn_node);
		leaveReadNode_shared_sorted_list(info2->conn_node);
	}
#ifdef DEBUG
	else
	{
		// This should never happen
		fprintf(stderr, "OV_Compare: Connections pointed by node view were removed!!");
		exit(EXIT_FAILURE);
	}
#endif


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
