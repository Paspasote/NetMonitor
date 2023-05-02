#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <curses.h>
#include <semaphore.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <misc.h>
#include <GlobalVars.h>
#include <SharedSortedList.h>
#include <Configuration.h>
#include <iptables.h>
#include <interface.h>
#ifdef DEBUG
#include <debug.h>
#endif
#include <IPGroupedView.h>

// EXTERNAL Global vars
extern struct const_global_vars c_globvars;
extern struct write_global_vars w_globvars;

// Global vars

// Function prototypes
int IPG_isValidList();
void IPG_createList();
int IPG_isValidConnList(shared_sorted_list list, sem_t mutex);
int IPG_isValidServiceList(struct IPG_info *info);
void IPG_createServiceList(struct IPG_info *info);

void IPG_updateList();
int IPG_visibleService(struct connection_info *conn, time_t now);
void IPG_ShowElement(void *data, void *param);
void IPG_freeRequests(struct IPG_service_info *info_service, shared_sorted_list conn_list, struct node_shared_sorted_list *conn_node, int leave_read);
void IPG_ShowElementService(void *data, void *param);
void IPG_ShowServices(struct IPG_info *info);

void IPG_Reset();
void IPG_freeConnection(void *val, void *param);

int IPG_EqualSrcAddress(void *val1, void *val2);
int IPG_Compare(void *val1, void *val2);
int IPG_CompareService(void *val1, void *val2);

int IPG_isValidList() {
	return w_globvars.IPG_l != NULL;
}

void IPG_createList() {
	init_sorted_list(&w_globvars.IPG_l, IPG_Compare);
}

int IPG_isValidConnList(shared_sorted_list list, sem_t mutex) {
	int ret;

	if (sem_wait(&mutex)) 
	{
		perror("IPG_isValidList: sem_wait with mutex list");
		exit(1);
	}
	ret = list != NULL;
	if (sem_post(&mutex))
	{
		perror("IPG_isValidList: sem_post with mutex list");
		exit(1);		
	}

	return ret;
}

int IPG_isValidServiceList(struct IPG_info *info) {
	return info->l_services != NULL;
}

void IPG_createServiceList(struct IPG_info *info) {
	init_sorted_list(&info->l_services, IPG_CompareService);
}

void IPG_updateList()
{
    shared_sorted_list *hash_table;
	sem_t *mutex;
	int i, services_count, must_point;
	struct node_shared_sorted_list *node;
	struct IPG_info *info, *new_info;
	struct IPG_service_info *service_info;
	struct connection_info *conn;
	struct node_sorted_list *IPG_node;
	time_t now;

	now = time(NULL);

	if (!isEmpty_sorted_list(w_globvars.IPG_l))
	{
		IPG_Reset();
	}

    // Iterate buckets of incoming internet hash table
	hash_table = w_globvars.conn_internet_in;
	mutex = &w_globvars.mutex_conn_internet_in;
    for (i=0; i<65536; i++)
    {
        // Is list valid?
        if (IPG_isValidConnList(hash_table[i], *mutex))
        {
            // Iterate the bucket's list 
			services_count = 0;
            node = firstNode_shared_sorted_list(hash_table[i]);
            while (node != NULL && services_count < MAX_SERVICES) 
			{
				must_point = 0;
				// Allocate memory for this connection
				new_info = (struct IPG_info *) malloc(sizeof(struct IPG_info));
				if (new_info == NULL) 
				{
					fprintf(stderr,"IPG_updateList: Could not allocate memory!!\n");
					exit(1);				
				}

				if (requestReadNode_shared_sorted_list(node))
				{
					// Get connection info
					conn = (struct connection_info *)node->info;

					// Is this service connection visible?
					if (IPG_visibleService(conn, now))
					{
						// One service more
						services_count++;
						must_point = 1;

						// Store Source address
						new_info->ip_src = conn->ip_src;

						// Source IP (node list) exist?
						IPG_node = find_sorted_list(w_globvars.IPG_l, new_info, IPG_EqualSrcAddress);

						if (IPG_node == NULL)
						{
							// The source IP is new.
									
							// Initialize stats of new connection
							info = new_info;
							info->priority = 0;
							info->time = 0;
							info->hits = 0;
							info->total_bytes = 0;
							info->bandwidth = 0.0;
							strcpy(info->country, "");
							strcpy(info->netname, "");
							info->l_services = NULL;
							IPG_createServiceList(info);
						}
						else
						{
							// Source IP already exists. Get its information
							info = (struct IPG_info *) IPG_node->info;
							// Free new info
							free(new_info);
						}

						// Update stats
						info->priority = max(info->priority, conn->priority);
						info->time = max(info->time, conn->time);
						info->hits = info->hits + conn->hits;
						info->total_bytes = info->total_bytes + conn->total_bytes;
						info->bandwidth = info->bandwidth + conn->bandwidth;

						// Allocate memory for this service connection
						service_info = (struct IPG_service_info *) malloc(sizeof(struct IPG_service_info));
						if (service_info == NULL) 
						{
							fprintf(stderr,"IPG_updateList: Could not allocate memory!!\n");
							exit(1);				
						}

						// Save the service connection info
						service_info->conn_node = node;
						service_info->conn_list = hash_table[i];
						strcpy(service_info->flags, "?    ");
						service_info->iptable_rule = 0;
						service_info->stablished = 0;

						// Insert the new connection service in the services list
						insert_sorted_list(info->l_services, service_info);

						if (IPG_node == NULL)
						{
							// Insert the new (source IP) connection in the list
							insert_sorted_list(w_globvars.IPG_l, info);
						}

					}
					else
					{
						// This service is not visible
						free(new_info);
					}

					leaveReadNode_shared_sorted_list(node);
				}
				else
				{
					// The connection was removed
					free(new_info);
				}

				// Next node
				// We don't leave node's access if created node view (It is pointing to this node connection)
				node = nextNode_shared_sorted_list(hash_table[i], node, !must_point);
            }
        }
    }

}

int IPG_visibleService(struct connection_info *conn, time_t now) {
	if (!conn->starting) {
		return 0;
	}

	switch (conn->ip_protocol) {
		case IPPROTO_ICMP:
			return now - conn->time < ANY_VISIBLE_TIMEOUT;
		case IPPROTO_TCP:
			return now - conn->time < TCP_VISIBLE_TIMEOUT;
		case IPPROTO_UDP:
			return now - conn->time < UDP_VISIBLE_TIMEOUT;
	}
	return 0;
}

void IPG_ShowElement(void *data, void *param) {
	struct IPG_info *info;
	struct tm *t;
	time_t now;
	char s_time[20];
	char line[250];
	char s_ip_src[INET_ADDRSTRLEN];
	char total_bytes[20];


	info = (struct IPG_info *)data;

	now = time(NULL);

	t = localtime(&info->time);
	sprintf(s_time, "%02d/%02d/%4d %02d:%02d:%02d", t->tm_mday, t->tm_mon, 1900+t->tm_year, t->tm_hour, t->tm_min, t->tm_sec);

	inet_ntop(AF_INET, &(info->ip_src), s_ip_src, INET_ADDRSTRLEN);

	if ((float)info->total_bytes / 1024.0 > 99999.99) {
		sprintf(total_bytes, "[%8.2f MB]", (float)info->total_bytes / (1024.0*1024.0));
	}
	else {
		sprintf(total_bytes, "[%8.2f KB]", (float)info->total_bytes / 1024.0);
	}

	// Check if we have to update whois info
	if (!strcmp(info->country, ""))
	{
		updateWhoisInfo(info->ip_src.s_addr, info->country, info->netname);
	}

	sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s  %2s  %-16s :", s_time, info->hits, total_bytes, info->bandwidth, s_ip_src, info->country, info->netname);

	writeLineOnResult(line, COLOR_PAIR(info->priority), now - info->time < RECENT_TIMEOUT);

	IPG_ShowServices(info);

	writeLineOnResult("\n", 0, 0);

	w_globvars.result_count_lines++;
}

void IPG_ShowInfo() {
	// Is list created?
	if (!IPG_isValidList())
	{
		IPG_createList();
	}

	// Is list valid?
	if (!IPG_isValidList())
	{
		fprintf(stderr,"IPG_ShowInfo: List is not valid!!\n");
		exit(1);
	}

	IPG_updateList();

	// Iterate the list and show info on screen
	w_globvars.result_count_lines = 0;
	for_each_sorted_list(w_globvars.IPG_l, IPG_ShowElement, NULL);
}

void IPG_freeRequests(struct IPG_service_info *info_service, shared_sorted_list conn_list, struct node_shared_sorted_list *conn_node, int leave_read)
{
	if (leave_read)
	{
		leaveReadNode_shared_sorted_list(conn_node);
	}
	info_service->conn_list = NULL;
	info_service->conn_node = NULL;
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

void IPG_ShowElementService(void *data, void *param) {
	struct IPG_info *info;
	struct IPG_service_info *info_service;
	struct connection_info *conn;
	time_t now;
	char line[250];
	char s_protocol[5];
	struct servent *servinfo;
	char s_icmp[50];
	char *service_alias;
	struct node_shared_sorted_list *conn_node;
	shared_sorted_list conn_list;

	info = (struct IPG_info *)param;
	info_service = (struct IPG_service_info *)data;
	conn_node = info_service->conn_node;
	conn_list = info_service->conn_list;

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
		fprintf(stderr, "IPG_ShowElementService: Connection pointed by node view was removed!!");
		exit(EXIT_FAILURE);
#endif
		IPG_freeRequests(info_service, conn_list, conn_node, 0);
		return;
	}
	conn = (struct connection_info *)info_service->conn_node->info;

	now = time(NULL);

	// Protocol?
	switch (conn->ip_protocol) {
		case IPPROTO_ICMP:
			// Check if we have to update iptables flag
			if (now - info_service->iptable_rule > RULE_TIMEOUT)
			{
				// Mark iptable rule as old
				info_service->flags[FLAG_IPTABLES_POS] = '?';
			}
			if (info_service->stablished != conn->stablished)
			{
				info_service->stablished = conn->stablished;
				// Mark iptable rule as old
				info_service->flags[FLAG_IPTABLES_POS] = '?';
			}
			if (info_service->flags[FLAG_IPTABLES_POS] == '?')
			{
				info_service->iptable_rule = now;
				switch (actionIncoming(c_globvars.internet_dev, conn->ip_protocol, info->ip_src.s_addr, 0, 
									   conn->ip_dst.s_addr, 0, conn->shared_info.icmp_info.type, conn->shared_info.icmp_info.code, !conn->stablished, "INPUT"))
				{
					case -1:
						info_service->flags[FLAG_IPTABLES_POS] = ' ';
						break;
					case 1:
						info_service->flags[FLAG_IPTABLES_POS] = FLAG_ACCEPT;
						break;
					case 2:
						info_service->flags[FLAG_IPTABLES_POS] = FLAG_DROP;
						break;
					case 3:
						info_service->flags[FLAG_IPTABLES_POS] = FLAG_REJECT;
						break;
					case 4:
						info_service->flags[FLAG_IPTABLES_POS] = FLAG_BAN;
						break;
				}
			}
			// Update Respond/Stablished flag
			if (!conn->starting)
			{
				info_service->flags[FLAG_RESPOND_POS] = FLAG_RESPOND;
			}
			else
			{
				if (conn->stablished)
				{
					info_service->flags[FLAG_STABLISHED_POS] = FLAG_STABLISHED;
				}
				else
				{
					info_service->flags[FLAG_NEW_POS] = FLAG_NEW;
				}
			}
			// Update NAT flag
			if (conn->nat_node != NULL)
			{
				info_service->flags[FLAG_NAT_POS] = FLAG_NAT;
			}
			else
			{
				info_service->flags[FLAG_NAT_POS] = ' ';
			}

			// Generate line info
			strcpy(s_protocol, "icmp");
			s_icmp_type(conn->shared_info.icmp_info.type, conn->shared_info.icmp_info.code, s_icmp);
			sprintf(line, "  %s [%lu]%s/%s", info_service->flags, conn->hits, s_protocol, s_icmp);
			break;
		case IPPROTO_TCP:
			// Check if we have to update iptables flag
			if (now - info_service->iptable_rule > RULE_TIMEOUT)
			{
				// Mark iptable rule as old
				info_service->flags[FLAG_IPTABLES_POS] = '?';
			}
			if (info_service->stablished != conn->stablished)
			{
				info_service->stablished = conn->stablished;
				// Mark iptable rule as old
				info_service->flags[FLAG_IPTABLES_POS] = '?';
			}
			if (info_service->flags[FLAG_IPTABLES_POS] == '?')
			{
				info_service->iptable_rule = now;
				switch (actionIncoming(c_globvars.internet_dev, conn->ip_protocol, info->ip_src.s_addr, conn->shared_info.tcp_info.sport, 
									   conn->ip_dst.s_addr, conn->shared_info.tcp_info.dport, conn->shared_info.tcp_info.flags, 0, !conn->stablished, "INPUT"))
				{
					case -1:
						info_service->flags[FLAG_IPTABLES_POS] = ' ';
						break;
					case 1:
						info_service->flags[FLAG_IPTABLES_POS] = FLAG_ACCEPT;
						break;
					case 2:
						info_service->flags[FLAG_IPTABLES_POS] = FLAG_DROP;
						break;
					case 3:
						info_service->flags[FLAG_IPTABLES_POS] = FLAG_REJECT;
						break;
					case 4:
						info_service->flags[FLAG_IPTABLES_POS] = FLAG_BAN;
						break;
				}
			}
			// Update Respond/Stablished flag
			if (!conn->starting)
			{
				info_service->flags[FLAG_RESPOND_POS] = FLAG_RESPOND;
			}
			else
			{
				if (conn->stablished)
				{
					info_service->flags[FLAG_STABLISHED_POS] = FLAG_STABLISHED;
				}
				else
				{
					info_service->flags[FLAG_NEW_POS] = FLAG_NEW;
				}
			}
			// Update NAT flag
			if (conn->nat_node != NULL)
			{
				info_service->flags[FLAG_NAT_POS] = FLAG_NAT;
			}
			else
			{
				info_service->flags[FLAG_NAT_POS] = ' ';
			}

			// Generate line info
			strcpy(s_protocol, "tcp");
			service_alias = serviceShortAlias(conn->ip_protocol, conn->shared_info.tcp_info.dport);
			if (service_alias != NULL && strcmp(service_alias, "")) {
				sprintf(line, "  %s [%lu]%s", info_service->flags, conn->hits, service_alias);
			}
			else {
				servinfo = getservbyport(htons(conn->shared_info.tcp_info.dport), s_protocol);
				if (servinfo != NULL && servinfo->s_name != NULL && strcmp(servinfo->s_name, "")) {
					sprintf(line, "  %s [%lu]%s", info_service->flags, conn->hits, servinfo->s_name);
				}
				else {
					sprintf(line, "  %s [%lu]%s/%u", info_service->flags, conn->hits, s_protocol, conn->shared_info.tcp_info.dport);
				}
			}
			break;
		case IPPROTO_UDP:
			// Check if we have to update iptables flag
			if (now - info_service->iptable_rule > RULE_TIMEOUT)
			{
				// Mark iptable rule as old
				info_service->flags[FLAG_IPTABLES_POS] = '?';
			}
			if (info_service->stablished != conn->stablished)
			{
				info_service->stablished = conn->stablished;
				// Mark iptable rule as old
				info_service->flags[FLAG_IPTABLES_POS] = '?';
			}
			if (info_service->flags[FLAG_IPTABLES_POS] == '?')
			{
				info_service->iptable_rule = now;
				switch (actionIncoming(c_globvars.internet_dev, conn->ip_protocol, info->ip_src.s_addr, conn->shared_info.udp_info.sport, 
									   conn->ip_dst.s_addr, conn->shared_info.udp_info.dport, 0, 0, !conn->stablished, "INPUT"))
				{
					case -1:
						info_service->flags[FLAG_IPTABLES_POS] = ' ';
						break;
					case 1:
						info_service->flags[FLAG_IPTABLES_POS] = FLAG_ACCEPT;
						break;
					case 2:
						info_service->flags[FLAG_IPTABLES_POS] = FLAG_DROP;
						break;
					case 3:
						info_service->flags[FLAG_IPTABLES_POS] = FLAG_REJECT;
						break;
					case 4:
						info_service->flags[FLAG_IPTABLES_POS] = FLAG_BAN;
						break;
				}
			}
			// Update Respond/Stablished flag
			if (!conn->starting)
			{
				info_service->flags[FLAG_RESPOND_POS] = FLAG_RESPOND;
			}
			else
			{
				if (conn->stablished)
				{
					info_service->flags[FLAG_STABLISHED_POS] = FLAG_STABLISHED;
				}
				else
				{
					info_service->flags[FLAG_NEW_POS] = FLAG_NEW;
				}
			}
			// Update NAT flag
			if (conn->nat_node != NULL)
			{
				info_service->flags[FLAG_NAT_POS] = FLAG_NAT;
			}
			else
			{
				info_service->flags[FLAG_NAT_POS] = ' ';
			}

			// Generate line info
			strcpy(s_protocol, "udp");
			service_alias = serviceShortAlias(conn->ip_protocol, conn->shared_info.udp_info.dport);
			if (service_alias != NULL && strcmp(service_alias, "")) {
				sprintf(line, "  %s [%lu]%s", info_service->flags, conn->hits, service_alias);
			}
			else {
				servinfo = getservbyport(htons(conn->shared_info.udp_info.dport), s_protocol);
				if (servinfo != NULL && servinfo->s_name != NULL && strcmp(servinfo->s_name, "")) {
					sprintf(line, "  %s [%lu]%s", info_service->flags, conn->hits, servinfo->s_name);
				}
				else {
					sprintf(line, "  %s [%lu]%s/%u", info_service->flags, conn->hits, s_protocol, conn->shared_info.udp_info.dport);
				}
			}
			break;	
	}

	writeLineOnResult(line, COLOR_PAIR(info->priority), now - info->time < RECENT_TIMEOUT);

	IPG_freeRequests(info_service, conn_list, conn_node, 1);
}

void IPG_ShowServices(struct IPG_info *info) {

	if (!IPG_isValidServiceList(info))
	{
		return;
	}

	for_each_sorted_list(info->l_services, IPG_ShowElementService, info);
}

void IPG_Reset() {
	if (IPG_isValidList())
	{
		clear_all_sorted_list(w_globvars.IPG_l, 1, IPG_freeConnection, NULL);
	}
}


void IPG_freeConnection(void *val, void *param) {
	struct IPG_info *info;

	info = (struct IPG_info *)val;

	if (IPG_isValidServiceList(info)) {
		// Clear all services
		clear_all_sorted_list(info->l_services, 1, NULL, NULL);
		free(info->l_services);
	}
}

int IPG_EqualSrcAddress(void *val1, void *val2) {
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


int IPG_CompareService(void *val1, void *val2) {
	struct IPG_service_info *info1, *info2;
	struct connection_info *conn1, *conn2;
	unsigned long grade1, grade2;
	time_t now, diff_time1, diff_time2;

	now = time(NULL);

	info1 = (struct IPG_service_info *)val1;
	info2 = (struct IPG_service_info *)val2;

	if (requestReadNode_shared_sorted_list(info1->conn_node) &&
	    requestReadNode_shared_sorted_list(info2->conn_node))
	{
		conn1 = info1->conn_node->info;
		conn2 = info2->conn_node->info;

		diff_time1 = now - conn1->time;
		diff_time2 = now - conn2->time;

		grade1 = conn1->hits;
		grade2 = conn2->hits;

		leaveReadNode_shared_sorted_list(info1->conn_node);
		leaveReadNode_shared_sorted_list(info2->conn_node);
	}
#ifdef DEBUG
	else
	{
		// This should never happen
		fprintf(stderr, "IPG_CompareService: Connections pointed by node view were removed!!");
		exit(EXIT_FAILURE);
	}
#endif

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
