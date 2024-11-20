#include <stdio.h>
#include <stdlib.h>
#include <semaphore.h>
#include <arpa/inet.h>

#include <DoubleList.h>
#include <GlobalVars.h>
#include <debug.h>

#include <PacketList.h>

// EXTERNAL Global vars
extern struct const_global_vars c_globvars;
extern struct write_global_vars w_globvars;

// Global vars

// Function prototypes
void PL_show_packet(struct info_packet *packet);

void PL_addPacket(int internet, const struct ether_header *ethernet,const struct ip *ip,const struct icmp *icmp_header,
	const struct tcphdr *tcp_header,const struct udphdr *udp_header,const struct igmp *igmp_header, unsigned n_bytes) {
	
	double_list *list;
	pthread_mutex_t *mutex;
	struct info_packet *info;
	int i;

	if (internet) 
	{
		list = &w_globvars.internet_packets_buffer;
		mutex = &w_globvars.mutex_internet_packets;
	}
	else
	{
		list = &w_globvars.intranet_packets_buffer;
		mutex = &w_globvars.mutex_intranet_packets;
	}

	// Check if buffer packages list has been created
	if (pthread_mutex_lock(mutex)) 
	{
		perror("PL_addPacket: pthread_mutex_lock with mutex packages buffer");
		exit(1);
	}
	if (*list == NULL)
	{
		init_double_list(list);
	}
	if (pthread_mutex_unlock(mutex))
	{
		perror("PL_addPacket: pthread_mutex_unlock with mutex packages buffer");
		exit(1);		
	}

	// Maximum size??
	if (pthread_mutex_lock(mutex)) 
	{
		perror("PL_addPacket: pthread_mutex_lock with mutex packages buffer");
		exit(1);
	}
	if (size_double_list(*list) == MAX_PACKAGES)
	{
		if (pthread_mutex_unlock(mutex)) 
		{
			perror("PL_addPacket: pthread_mutex_unlock with mutex packages buffer");
			exit(1);
		}
		//fprintf(stderr, "PL_addPacket: Buffer overflow!!!!!\n");
		//exit(1);
		return;
	}
	if (pthread_mutex_unlock(mutex))
	{
		perror("PL_addPacket: pthread_mutex_unlock with mutex packages buffer");
		exit(1);		
	}
	
	// Allocate memory for package info
	info = (struct info_packet *)malloc(sizeof(struct info_packet));
	if (info == NULL)
	{
		fprintf(stderr,"PL_addPacket: Could not allocate memory!!\n");
		exit(1);				
	}

	// Store current time
	info->time = time(NULL);

	// Store packet size in bytes
	info->n_bytes = n_bytes;

	// Store ethernet addresses
	for (i=0; i<ETH_ALEN; i++)
	{
		info->ether_dhost[i] = ethernet->ether_dhost[i];
		info->ether_shost[i] = ethernet->ether_shost[i];
	}

	// Store IP Protocol
	info->ip_protocol = ip->ip_p;

	// Store Source and Destination IP address
	info->ip_src = ip->ip_src;
	info->ip_dst = ip->ip_dst;

	// Protocol?
	switch (ip->ip_p) {
		case IPPROTO_ICMP:
			// Store ICMP type and code
			info->shared_header.icmp_header.type = icmp_header->icmp_type;
			info->shared_header.icmp_header.code = icmp_header->icmp_code;
			break;
		case IPPROTO_TCP:
			// Store source and destination port, TCP Seq, TCP ACK and TCP flags
			info->shared_header.tcp_header.sport = ntohs(tcp_header->th_sport);
			info->shared_header.tcp_header.dport = ntohs(tcp_header->th_dport);
			info->shared_header.tcp_header.seq = ntohl(tcp_header->th_seq);
			info->shared_header.tcp_header.ack = ntohl(tcp_header->th_ack);
			info->shared_header.tcp_header.flags = tcp_header->th_flags;
			break;
		case IPPROTO_UDP:
			// Store source and destination port
			info->shared_header.udp_header.sport = ntohs(udp_header->uh_sport);
			info->shared_header.udp_header.dport = ntohs(udp_header->uh_dport);
			break;
		case IPPROTO_IGMP:
			// Store IGMP type and code and IGMP group address
			info->shared_header.igmp_header.type = igmp_header->igmp_type;
			info->shared_header.igmp_header.code = igmp_header->igmp_code;
			info->shared_header.igmp_header.group = igmp_header->igmp_group;
			break;
	}

	// Store the current packet in packet buffer
	if (pthread_mutex_lock(mutex))
	{
		perror("PL_addPacket: pthread_mutex_lock with mutex packages buffer");
		exit(1);
	}
	insert_tail_double_list(*list, info);
	if (pthread_mutex_unlock(mutex))
	{
		perror("PL_addPacket: pthread_mutex_unlock with mutex packages buffer");
		exit(1);		
	}


}

struct info_packet *PL_getPacket(int internet)
{
	double_list *list;
	pthread_mutex_t *mutex;
	struct info_packet *ret = NULL;

	if (w_globvars.internet_packets_buffer == NULL) {
		return NULL;
	}

	if (internet) 
	{
		list = &w_globvars.internet_packets_buffer;
		mutex = &w_globvars.mutex_internet_packets;
	}
	else
	{
		list = &w_globvars.intranet_packets_buffer;
		mutex = &w_globvars.mutex_intranet_packets;
	}

	// Any packet stored?
	if (pthread_mutex_lock(mutex)) 
	{
		perror("PL_getPacket: pthread_mutex_lock with mutex packages buffer");
		exit(1);
	}
	if (*list != NULL && !isEmpty_double_list(*list))
	{
		ret = front_double_list(*list);
		remove_front_double_list(*list, 0);
	}
	if (pthread_mutex_unlock(mutex))
	{
		perror("PL_getPacket: pthread_mutex_unlock with mutex packages buffer");
		exit(1);		
	}
	return ret;
}

void PL_show_packet(struct info_packet *packet)
{
	struct tm *t;
	char s_ip_src[INET_ADDRSTRLEN], s_ip_dst[INET_ADDRSTRLEN]; /* source an ddest address (dot format) */

	inet_ntop(AF_INET, &(packet->ip_src), s_ip_src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(packet->ip_dst), s_ip_dst, INET_ADDRSTRLEN);

	// Get packet time and prints it on screent
	t = localtime(&(packet->time));
	printf("%02d/%02d/%4d %02d:%02d:%02d\t", t->tm_mday, t->tm_mon, 1900+t->tm_year, t->tm_hour, t->tm_min, t->tm_sec);


	// Protocol?
	switch (packet->ip_protocol) {
		case IPPROTO_ICMP:
			printf("Protocol: ICMP\tSource: %-15s\tDestination: %-15s\t", s_ip_src, s_ip_dst);
			printf("Type: %-5u\t\tCode: %-5u\n", packet->shared_header.icmp_header.type, packet->shared_header.icmp_header.code);
			break;
		case IPPROTO_TCP:
			printf("Protocol: TCP\tSource: %-15s\tDestination: %-15s\t", s_ip_src, s_ip_dst);
			printf("Source port: %-5u\tDestination port: %-5u\n", 
				packet->shared_header.tcp_header.sport, packet->shared_header.tcp_header.dport);
			break;
		case IPPROTO_UDP:
			printf("Protocol: UDP\tSource: %-15s\tDestination: %-15s\t", s_ip_src, s_ip_dst);
			printf("Source port: %-5u\tDestination port: %-5u\n", 
				packet->shared_header.udp_header.sport, packet->shared_header.udp_header.dport);
			break;
		case IPPROTO_IGMP:
			printf("Protocol: IGMP\tSource: %-15s\tDestination: %-15s\t", s_ip_src, s_ip_dst);
			printf("Type: %-5u\t\tCode: %-5u\n", packet->shared_header.igmp_header.type, packet->shared_header.igmp_header.code);
			break;
		default:
			printf("Protocol: %u\tSource: %-15s\tDestination: %-15s\n", packet->ip_protocol, s_ip_src, s_ip_dst);
	}
}

void PL_show_info(int internet) {
	double_list *list;
	pthread_mutex_t *mutex;
	
	if (w_globvars.internet_packets_buffer == NULL) {
		return;
	}

	if (internet) 
	{
		list = &w_globvars.internet_packets_buffer;
		mutex = &w_globvars.mutex_internet_packets;
	}
	else
	{
		list = &w_globvars.intranet_packets_buffer;
		mutex = &w_globvars.mutex_intranet_packets;
	}

	// Show all pending packets (packets in buffer)
	if (pthread_mutex_lock(mutex))
	{
		perror("PL_show_info: pthread_mutex_lock with mutex packages buffer");
		exit(1);
	}
	while (!isEmpty_double_list(*list)) {
		// Show one packet and remove it
		if (pthread_mutex_unlock(mutex))
		{
			perror("PL_show_info: pthread_mutex_unlock with mmutex packages buffer");
			exit(1);		
		}
		PL_show_packet(front_double_list(*list));
		if (pthread_mutex_lock(mutex))
		{
			perror("PL_show_info: pthread_mutex_lock with mutex packages buffer");
			exit(1);
		}
		remove_front_double_list(*list, 1);
	}

	if (pthread_mutex_unlock(mutex))
	{
		perror("PL_show_info: pthread_mutex_unlock with mutex packages buffer");
		exit(1);		
	}

}

