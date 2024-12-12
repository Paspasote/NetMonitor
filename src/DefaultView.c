#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <curses.h>
#include <semaphore.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>


#include <SharedSortedList.h>
#include <SortedList.h>
#include <GlobalVars.h>
#include <misc.h>
#include <Configuration.h>
#include <Connection.h>
#include <WhoIs.h>
#include <interface.h>
#if IPTABLES_ACTIVE == 1
#include <iptables.h>
#endif
#if NFTABLES_ACTIVE == 1
#include <nftables.h>
#endif

#ifdef DEBUG
#include <debug.h>
#endif

#include <DefaultView.h>

// EXTERNAL Global vars
extern struct const_global_vars c_globvars;
extern struct write_global_vars w_globvars;

// Global vars

// Function prototypes
int DV_isValidList();
void DV_createList();
int DV_isValidConnList(shared_sorted_list list, pthread_mutex_t mutex);

void DV_updateList();
void DV_freeRequests(struct DV_info *info, shared_sorted_list conn_list, struct node_shared_sorted_list *conn_node, int leave_read);
void DV_ShowElement(void *data, void *param);

void DV_Reset();
int DV_Compare(void *val1, void *val2);

int DV_isValidList() {
	return w_globvars.DV_l != NULL;
}

void DV_createList() {
	init_sorted_list(&w_globvars.DV_l, DV_Compare);
}

int DV_isValidConnList(shared_sorted_list list, pthread_mutex_t mutex) 
{
	int ret;

	if (pthread_mutex_lock(&mutex)) 
	{
		perror("DV_isValidConnList: pthread_mutex_lock with mutex list");
		exit(1);
	}
	ret = list != NULL;
	if (pthread_mutex_unlock(&mutex))
	{
		perror("DV_isValidConnList: pthread_mutex_unlock with mutex list");
		exit(1);		
	}

	return ret;
}

void DV_updateList()
{
    shared_sorted_list *hash_table;
	pthread_mutex_t *mutex;
	int i;
	struct node_shared_sorted_list *node;
	struct connection_info *node_info;
	struct DV_info *info;

	if (!isEmpty_sorted_list(w_globvars.DV_l))
	{
		DV_Reset();
	}

    // Iterate buckets of incoming internet hash tableq
	hash_table = w_globvars.conn_internet_in;
	mutex = &w_globvars.mutex_conn_internet_in;
    for (i=0; i<65536; i++)
    {
        // Is list valid?
        if (DV_isValidConnList(hash_table[i], *mutex))
        {
            // Iterate the bucket's list 
            node = firstNode_shared_sorted_list(hash_table[i]);
            while (node != NULL) 
			{
				// Read access to connection node is needed
				if (requestReadNode_shared_sorted_list(node))
				{
					// Get node info
					node_info = (struct connection_info *) node->info;

					// Is this an incoming starting (client) connection?
					if (node_info->starting) {
						// Yes. Allocate memory for this connection
						info = (struct DV_info *) malloc(sizeof(struct DV_info));
						if (info == NULL) 
						{
							fprintf(stderr,"DV_updateList: Could not allocate memory!!\n");
							exit(1);				
						}

						// Save the connection info
						info->conn_node = node;
						info->conn_list = hash_table[i];
						strcpy(info->country, "");
						strcpy(info->netname, "");
						strcpy(info->flags, "?    ");
						info->xtable_rule = 0;
						info->stablished = 0;



						// Insert the new connection in the list
						insert_sorted_list(w_globvars.DV_l, info);

						// We don't leave node's access because node view is pointing to this node connection
					}
					else {
						// it's not an incoming starting (client) connection. We are not interested on it.
						// We leave node's access because any node is pointing to this node connection
						leaveNode_shared_sorted_list(hash_table[i], node);
					}

					// Leave read access
					leaveReadNode_shared_sorted_list(node);

					// Next node
					node = nextNode_shared_sorted_list(hash_table[i], node, 0);
				}
				else
				{
					// Connection has been removed.
					// Next node
					node = nextNode_shared_sorted_list(hash_table[i], node, 1);
				}
            }
        }
    }
}

void DV_freeRequests(struct DV_info *info, shared_sorted_list conn_list, struct node_shared_sorted_list *conn_node, int leave_read)
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

void DV_ShowElement(void *data, void *param) 
{
	struct DV_info *info;
	struct connection_info *conn;
	struct tm *t;
	time_t now;
	char s_time[20];
	char line[250];
	char s_protocol[5];
	struct servent *servinfo;
	char s_ip_src[INET_ADDRSTRLEN], s_ip_dst[INET_ADDRSTRLEN], s_ip_NAT[INET_ADDRSTRLEN], *p_ip_dst;
	char s_icmp[50];
	char total_bytes[20];
	char *service_alias;
	char s_port[9];
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

	info = (struct DV_info *)data;
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
		DV_freeRequests(info, conn_list, conn_node, 0);
		return;
	}
	conn = (struct connection_info *)info->conn_node->info;

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
	p_ip_dst = s_ip_dst;
	if (conn->NAT) {
		inet_ntop(AF_INET, &(conn->ip_NAT_dst), s_ip_NAT, INET_ADDRSTRLEN);
		p_ip_dst = s_ip_NAT;
	}

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
				DV_freeRequests(info, conn_list, conn_node, 1);
#ifdef DEBUG
				/***************************  DEBUG ****************************/
				{
					char m[150];

					sprintf(m, "Interface: ShowElement finished (Visibility timeout)");
					debugMessageModule(INTERFACE, m, NULL, 1);
				}
#endif
				return;
			}

			// Check if we have to update whois conn
			if (!strcmp(info->country, ""))
			{
#ifdef DEBUG
				/***************************  DEBUG ****************************/
				{
					char m[150];

					sprintf(m, "Interface: ShowElement ICMP - Before update Whois...");
					debugMessageModule(INTERFACE, m, NULL, 1);
				}
#endif
				updateWhoisInfo(conn->ip_src.s_addr, info->country, info->netname);
#ifdef DEBUG
				/***************************  DEBUG ****************************/
				{
					char m[150];

					sprintf(m, "Interface: ShowElement ICMP - After update Whois");
					debugMessageModule(INTERFACE, m, NULL, 1);
				}
#endif
			}

#if IPTABLES_ACTIVE == 1 || NFTABLES_ACTIVE == 1
			// Check if we have to update xtables flag
			if (now - info->xtable_rule > RULE_TIMEOUT)
			{
				// Mark xtable rule as old
				info->flags[FLAG_XTABLES_POS] = '?';
			}
			if (info->stablished != conn->stablished)
			{
				info->stablished = conn->stablished;
				// Mark xtable rule as old
				info->flags[FLAG_XTABLES_POS] = '?';
			}
			if (info->flags[FLAG_XTABLES_POS] == '?')
			{
				info->xtable_rule = now;
#ifdef DEBUG
				/***************************  DEBUG ****************************/
				{
					char m[150];

					sprintf(m, "Interface: ShowElement ICMP - Before get xtables action...");
					debugMessageModule(INTERFACE, m, NULL, 1);
				}
#endif
#if IPTABLES_ACTIVE == 1
				switch (actionIncoming(c_globvars.internet_dev, conn->ip_protocol, conn->ip_src.s_addr, 0, 
									   conn->ip_dst.s_addr, 0, conn->shared_info.icmp_info.type, conn->shared_info.icmp_info.code, !conn->stablished, "INPUT"))
#else
				switch (actionIncoming(c_globvars.internet_dev, conn->ip_protocol, conn->ip_src.s_addr, 0, 
									   conn->ip_dst.s_addr, 0, conn->shared_info.icmp_info.type, conn->shared_info.icmp_info.code, !conn->stablished))
#endif
				{
					case -1:
						info->flags[FLAG_XTABLES_POS] = ' ';
						break;
					case 1:
						info->flags[FLAG_XTABLES_POS] = FLAG_ACCEPT;
						break;
					case 2:
						info->flags[FLAG_XTABLES_POS] = FLAG_DROP;
						break;
					case 3:
						info->flags[FLAG_XTABLES_POS] = FLAG_REJECT;
						break;
					case 4:
						info->flags[FLAG_XTABLES_POS] = FLAG_BAN;
						break;
				}
			}
#ifdef DEBUG
			/***************************  DEBUG ****************************/
			{
				char m[150];

				sprintf(m, "Interface: ShowElement ICMP - After get xtables action...");
				debugMessageModule(INTERFACE, m, NULL, 1);
			}
#endif
#endif
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
			if (conn->NAT)
			{
				info->flags[FLAG_NAT_POS] = FLAG_NAT;
			}
			else
			{
				info->flags[FLAG_NAT_POS] = ' ';
			}

			// Generate line info
			strcpy(s_protocol, "icmp");
			s_icmp_type(conn->shared_info.icmp_info.type, conn->shared_info.icmp_info.code, s_icmp);
			sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s       %-5s  %2s  %-16s  %-15s %-5s%s\n", s_time, conn->hits, total_bytes, conn->bandwidth, s_ip_src, info->flags, info->country, info->netname, p_ip_dst, s_protocol, s_icmp);
			break;
		case IPPROTO_TCP:
			if (now - conn->time >= TCP_VISIBLE_TIMEOUT) {
				// Visibility timeout
				DV_freeRequests(info, conn_list, conn_node, 1);
#ifdef DEBUG
				/***************************  DEBUG ****************************/
				{
					char m[150];

					sprintf(m, "Interface: ShowElement finished (Visibility timeout)");
					debugMessageModule(INTERFACE, m, NULL, 1);
				}
#endif
				return;
			}

			// Check if we have to update whois info
			if (!strcmp(info->country, ""))
			{
#ifdef DEBUG
				/***************************  DEBUG ****************************/
				{
					char m[150];

					sprintf(m, "Interface: ShowElement TCP - Before update Whois...");
					debugMessageModule(INTERFACE, m, NULL, 1);
				}
#endif
				updateWhoisInfo(conn->ip_src.s_addr, info->country, info->netname);
#ifdef DEBUG
				/***************************  DEBUG ****************************/
				{
					char m[150];

					sprintf(m, "Interface: ShowElement TCP - After update Whois");
					debugMessageModule(INTERFACE, m, NULL, 1);
				}
#endif
			}
#if IPTABLES_ACTIVE == 1 || NFTABLES_ACTIVE == 1
			// Check if we have to update xtables flag
			if (now - info->xtable_rule > RULE_TIMEOUT)
			{
				// Mark xtable rule as old
				info->flags[FLAG_XTABLES_POS] = '?';
			}
			if (info->stablished != conn->stablished)
			{
				info->stablished = conn->stablished;
				// Mark xtable rule as old
				info->flags[FLAG_XTABLES_POS] = '?';
			}
			if (info->flags[FLAG_XTABLES_POS] == '?')
			{
				info->xtable_rule = now;
#ifdef DEBUG
				/***************************  DEBUG ****************************/
				{
					char m[150];

					sprintf(m, "Interface: ShowElement TCP - Before get xtables action...");
					debugMessageModule(INTERFACE, m, NULL, 1);
				}
#endif
#if IPTABLES_ACTIVE == 1
				switch (actionIncoming(c_globvars.internet_dev, conn->ip_protocol, conn->ip_src.s_addr, conn->shared_info.tcp_info.sport, 
									   conn->ip_dst.s_addr, conn->shared_info.tcp_info.dport, conn->shared_info.tcp_info.flags, 0,
									   !conn->stablished, "INPUT"))
#else
				switch (actionIncoming(c_globvars.internet_dev, conn->ip_protocol, conn->ip_src.s_addr, conn->shared_info.tcp_info.sport, 
									   conn->ip_dst.s_addr, conn->shared_info.tcp_info.dport, conn->shared_info.tcp_info.flags, 0,
									   !conn->stablished))
#endif
				{
					case -1:
						info->flags[FLAG_XTABLES_POS] = ' ';
						break;
					case 1:
						info->flags[FLAG_XTABLES_POS] = FLAG_ACCEPT;
						break;
					case 2:
						info->flags[FLAG_XTABLES_POS] = FLAG_DROP;
						break;
					case 3:
						info->flags[FLAG_XTABLES_POS] = FLAG_REJECT;
						break;
					case 4:
						info->flags[FLAG_XTABLES_POS] = FLAG_BAN;
						break;
				}
			}
#ifdef DEBUG
			/***************************  DEBUG ****************************/
			{
				char m[150];

				sprintf(m, "Interface: ShowElement TCP - After get xtables action...");
				debugMessageModule(INTERFACE, m, NULL, 1);
			}
#endif
#endif
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
			if (conn->NAT)
			{
				info->flags[FLAG_NAT_POS] = FLAG_NAT;
			}
			else
			{
				info->flags[FLAG_NAT_POS] = ' ';
			}

			// Generate line info
			strcpy(s_protocol, "tcp");
			sprintf(s_port, "%0u", conn->shared_info.tcp_info.sport);
/*			if (conn->response) {
				strcat(s_port, "(R)");
			}*/
			service_alias = serviceAlias(conn->ip_protocol, conn->shared_info.tcp_info.dport);
			if (service_alias != NULL && strcmp(service_alias, "")) {
				sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s:%-5s %-5s  %2s  %-16s  %-15s %s\n", s_time, conn->hits, total_bytes, conn->bandwidth, s_ip_src, s_port, info->flags, info->country, info->netname, p_ip_dst, service_alias);				
			}
			else {
				servinfo = getservbyport(htons(conn->shared_info.tcp_info.dport), s_protocol);
				if (servinfo != NULL && strcmp(servinfo->s_name, "")) {
					sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s:%-5s %-5s  %2s  %-16s  %-15s %s\n", s_time, conn->hits, total_bytes, conn->bandwidth, s_ip_src, s_port, info->flags, info->country, info->netname, p_ip_dst, servinfo->s_name);
				}
				else {
					sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s:%-5s %-5s  %2s  %-16s  %-15s %-5s%5u\n", s_time, conn->hits, total_bytes, conn->bandwidth, s_ip_src, s_port, info->flags, info->country, info->netname, s_ip_dst, s_protocol, conn->shared_info.tcp_info.dport);				
				}
			}
			break;
		case IPPROTO_UDP:
			if (now - conn->time >= UDP_VISIBLE_TIMEOUT) {
				// Visibility timeout
				DV_freeRequests(info, conn_list, conn_node, 1);
#ifdef DEBUG
				/***************************  DEBUG ****************************/
				{
					char m[150];

					sprintf(m, "Interface: ShowElement finished (Visibility timeout)");
					debugMessageModule(INTERFACE, m, NULL, 1);
				}
#endif
				return;
			}

			// Check if we have to update whois info
			if (!strcmp(info->country, ""))
			{
#ifdef DEBUG
				/***************************  DEBUG ****************************/
				{
					char m[150];

					sprintf(m, "Interface: ShowElement UDP - Before update Whois...");
					debugMessageModule(INTERFACE, m, NULL, 1);
				}
#endif
				updateWhoisInfo(conn->ip_src.s_addr, info->country, info->netname);
#ifdef DEBUG
				/***************************  DEBUG ****************************/
				{
					char m[150];

					sprintf(m, "Interface: ShowElement UDP - After update Whois");
					debugMessageModule(INTERFACE, m, NULL, 1);
				}
#endif
			}
#if IPTABLES_ACTIVE == 1 || NFTABLES_ACTIVE == 1
			// Check if we have to update xtables flag
			if (now - info->xtable_rule > RULE_TIMEOUT)
			{
				// Mark xtable rule as old
				info->flags[FLAG_XTABLES_POS] = '?';
			}
			if (info->stablished != conn->stablished)
			{
				info->stablished = conn->stablished;
				// Mark xtable rule as old
				info->flags[FLAG_XTABLES_POS] = '?';
			}
			if (info->flags[FLAG_XTABLES_POS] == '?')
			{
				info->xtable_rule = now;
#ifdef DEBUG
				/***************************  DEBUG ****************************/
				{
					char m[150];

					sprintf(m, "Interface: ShowElement UDP - Before get xtables action...");
					debugMessageModule(INTERFACE, m, NULL, 1);
				}
#endif
#if IPTABLES_ACTIVE == 1
				switch (actionIncoming(c_globvars.internet_dev, conn->ip_protocol, conn->ip_src.s_addr, conn->shared_info.udp_info.sport, 
									   conn->ip_dst.s_addr, conn->shared_info.udp_info.dport, 0, 0, !conn->stablished, "INPUT"))
#else
				switch (actionIncoming(c_globvars.internet_dev, conn->ip_protocol, conn->ip_src.s_addr, conn->shared_info.udp_info.sport, 
									   conn->ip_dst.s_addr, conn->shared_info.udp_info.dport, 0, 0, !conn->stablished))
#endif
				{
					case -1:
						info->flags[FLAG_XTABLES_POS] = ' ';
						break;
					case 1:
						info->flags[FLAG_XTABLES_POS] = FLAG_ACCEPT;
						break;
					case 2:
						info->flags[FLAG_XTABLES_POS] = FLAG_DROP;
						break;
					case 3:
						info->flags[FLAG_XTABLES_POS] = FLAG_REJECT;
						break;
					case 4:
						info->flags[FLAG_XTABLES_POS] = FLAG_BAN;
						break;
				}
			}
#ifdef DEBUG
			/***************************  DEBUG ****************************/
			{
				char m[150];

				sprintf(m, "Interface: ShowElement UDP - After get xtables action...");
				debugMessageModule(INTERFACE, m, NULL, 1);
			}
#endif
#endif
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
			if (conn->NAT)
			{
				info->flags[FLAG_NAT_POS] = FLAG_NAT;
			}
			else
			{
				info->flags[FLAG_NAT_POS] = ' ';
			}

			// Generate line info
			strcpy(s_protocol, "udp");
			sprintf(s_port, "%0u", conn->shared_info.udp_info.sport);
/*			if (conn->response) {
				strcat(s_port, "(R)");
			} */
			service_alias = serviceAlias(conn->ip_protocol, conn->shared_info.udp_info.dport);
			if (service_alias != NULL && strcmp(service_alias, "")) {
				//sprintf(line, "%s   [%05lu] %s [%8.2f KB/s]  %22s  %s\n", s_time, conn->hits, total_bytes, conn->bandwidth, src_ip_port, service_alias);				
				sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s:%-5s %-5s  %2s  %-16s  %-15s %s\n", s_time, conn->hits, total_bytes, conn->bandwidth, s_ip_src, s_port, info->flags, info->country, info->netname, p_ip_dst, service_alias);				
			}
			else {
				servinfo = getservbyport(htons(conn->shared_info.udp_info.dport), s_protocol);
				if (servinfo != NULL && strcmp(servinfo->s_name, "")) {
					sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s:%-5s %-5s  %2s  %-16s  %-15s %s\n", s_time, conn->hits, total_bytes, conn->bandwidth, s_ip_src, s_port, info->flags, info->country, info->netname, p_ip_dst, servinfo->s_name);
				}
				else {
					sprintf(line, "%s  [%05lu] %s [%8.2f KB/s]  %15s:%-5s %-5s  %2s  %-16s  %-15s %-5s%5u\n", s_time, conn->hits, total_bytes, conn->bandwidth, s_ip_src, s_port, info->flags, info->country, info->netname, p_ip_dst, s_protocol, conn->shared_info.udp_info.dport);				
				}
			}
			break;	
	}

	writeLineOnResult(line, COLOR_PAIR(conn->priority), now - conn->time <= RECENT_TIMEOUT);

	DV_freeRequests(info, conn_list, conn_node, 1);
	w_globvars.result_count_lines++;

#ifdef DEBUG
	/***************************  DEBUG ****************************/
	{
		char m[150];

		sprintf(m, "Interface: ShowElement finished");
		debugMessageModule(INTERFACE, m, NULL, 1);
	}
#endif
}

void DV_ShowInfo() {
	// Is list created?
	if (!DV_isValidList())
	{
		DV_createList();
	}

	// Is list valid?
	if (!DV_isValidList())
	{
		fprintf(stderr,"DV_ShowInfo: List is not valid!!\n");
		exit(1);
	}

	DV_updateList();

	// Iterate the list and show info on screen
	w_globvars.result_count_lines = 0;
	for_each_sorted_list(w_globvars.DV_l, DV_ShowElement, NULL);
}

void DV_Reset() {
	if (w_globvars.DV_l != NULL)
	{
		clear_all_sorted_list(w_globvars.DV_l, 1, NULL, NULL);
	}
}

int DV_Compare(void *val1, void *val2) {
	struct DV_info *info1, *info2;
	struct connection_info *conn1, *conn2;
	unsigned long grade1, grade2;
	time_t now, diff_time1, diff_time2;

	now = time(NULL);

	info1 = (struct DV_info *)val1;
	info2 = (struct DV_info *)val2;

	if (!requestReadNode_shared_sorted_list(info2->conn_node))
	{
		// The node we want to compare is removed. 
		return 1;
	}

	conn1 = info1->conn_node->info;
	conn2 = info2->conn_node->info;

	diff_time1 = now - conn1->time;
	diff_time2 = now - conn2->time;

	grade1 = conn1->hits;
	grade2 = conn2->hits;

	leaveReadNode_shared_sorted_list(info2->conn_node);

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

