#include <stdio.h>
#include <stdlib.h>
#include <semaphore.h>
#include <arpa/inet.h>
#include <PacketList.h>

// Global vars
list buffer_packets = NULL;
extern sem_t mutex_bp;

// Function prototypes
void init(list *l);
void clear_all(list l);
int isEmpty(list l);
void insert_front(list l, struct info_packet data);
void insert_tail(list l, struct info_packet data);
void remove_front(list l);
void remove_tail(list l);
struct info_packet * front(list l);
struct info_packet * tail(list l);
unsigned size(list l);

void addPacket(const struct ether_header *ethernet,const struct ip *ip,const struct icmp *icmp_header,
	const struct tcphdr *tcp_header,const struct udphdr *udp_header,const struct igmp *igmp_header) {

	struct info_packet info; /* Store all info packet */
	int i;

	// Check if buffer list has been created
	if (buffer_packets == NULL) {
		if (sem_wait(&mutex_bp)) 
		{
			perror("addPacket (PacketList): sem_wait with mutex_bp");
			exit(1);
		}
		init(&buffer_packets);
		if (sem_post(&mutex_bp))
		{
			perror("addPacket (PacketList): sem_post with mutex_bp");
			exit(1);		
		}
	}

	// List is valid?
	if (buffer_packets == NULL) 
	{
		fprintf(stderr,"addPacket (PacketList): List is not valid!!\n");
		exit(1);
	}

	// Store current time
	info.time = time(NULL);

	// Store ethernet addresses
	for (i=0; i<ETH_ALEN; i++)
	{
		info.ether_dhost[i] = ethernet->ether_dhost[i];
		info.ether_shost[i] = ethernet->ether_shost[i];
	}

	// Store IP Protocol
	info.ip_protocol = ip->ip_p;

	// Store Source and Destination IP address
	info.ip_src = ip->ip_src;
	info.ip_dst = ip->ip_dst;

	// Protocol?
	switch (ip->ip_p) {
		case IPPROTO_ICMP:
			// Store ICMP type and code
			info.shared_header.icmp_header.type = icmp_header->icmp_type;
			info.shared_header.icmp_header.code = icmp_header->icmp_code;
			break;
		case IPPROTO_TCP:
			// Store source and destination port, TCP Seq, TCP ACK and TCP flags
			info.shared_header.tcp_header.sport = ntohs(tcp_header->th_sport);
			info.shared_header.tcp_header.dport = ntohs(tcp_header->th_dport);
			info.shared_header.tcp_header.seq = ntohl(tcp_header->th_seq);
			info.shared_header.tcp_header.ack = ntohl(tcp_header->th_ack);
			info.shared_header.tcp_header.flags = tcp_header->th_flags;
			break;
		case IPPROTO_UDP:
			// Store source and destination port
			info.shared_header.udp_header.sport = ntohs(udp_header->uh_sport);
			info.shared_header.udp_header.dport = ntohs(udp_header->uh_dport);
			break;
		case IPPROTO_IGMP:
			// Store IGMP type and code and IGMP group address
			info.shared_header.igmp_header.type = igmp_header->igmp_type;
			info.shared_header.igmp_header.code = igmp_header->igmp_code;
			info.shared_header.igmp_header.group = igmp_header->igmp_group;
			break;
	}

	// Store the current packet in packet buffer
	if (sem_wait(&mutex_bp)) 
	{
		perror("addPacket (PacketList): sem_wait with mutex_bp");
		exit(1);
	}
	insert_tail(buffer_packets, info);
	if (sem_post(&mutex_bp))
	{
		perror("addPacket (PacketList): sem_post with mutex_bp");
		exit(1);		
	}


}

void show_packet(struct info_packet *packet)
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

void show_info() {
	if (buffer_packets == NULL) {
		return;
	}

	// Show one packet and remove it
	if (sem_wait(&mutex_bp)) 
	{
		perror("show_info (PacketList): sem_wait with mutex_bp");
		exit(1);
	}

	if (!isEmpty(buffer_packets)) {
		show_packet(front(buffer_packets));
		remove_front(buffer_packets);
	}

	if (sem_post(&mutex_bp))
	{
		perror("show_info (PacketList): sem_post with mutex_bp");
		exit(1);		
	}
}

void init(list *l)
{
	if (*l != NULL) 
	{
		fprintf(stderr,"init: List must be NULL!!\n");
		exit(1);
	}
	*l = malloc(sizeof(struct info_list));
	if (*l == NULL)
	{
		fprintf(stderr,"init: Could not allocate memory!!\n");
		exit(1);		
	}
	(*l)->header = NULL;
	(*l)->tail = NULL;
	(*l)->n_elements = 0;
}

void clear_all(list l)
{
	struct node *p;

	if (l == NULL) 
	{
		fprintf(stderr,"clear_all: List is not valid!!\n");
		exit(1);
	}

	while (l->header != NULL)
	{
		p = l->header;
		l->header=p->next;
		free(p);
	}
	l->tail = NULL;
	l->n_elements = 0;
}

int isEmpty(list l)
{
	if (l == NULL) 
	{
		fprintf(stderr,"isEmpty: List is not valid!!\n");
		exit(1);
	}

	return l->n_elements == 0;
}

void insert_front(list l, struct info_packet data)
{
	struct node *p = NULL;

	if (l == NULL) 
	{
		fprintf(stderr,"insert_front: List is not valid!!\n");
		exit(1);
	}

	p = malloc(sizeof(struct node));
	if (p == NULL)
	{
		fprintf(stderr,"insert_front: Could not allocate memory!!\n");
		exit(1);		
	}
	p->info = data;
	p->next = l->header;
	p->prev = NULL;

	if (l->header == NULL)
	{
		l->tail = p;
	}
	else
	{
		l->header->prev = p;
	}

	l->header = p;
	l->n_elements++;
}

void insert_tail(list l, struct info_packet data)
{
	struct node *p = NULL;

	if (l == NULL) 
	{
		fprintf(stderr,"insert_tail: List is not valid!!\n");
		exit(1);
	}

	p = malloc(sizeof(struct node));
	if (p == NULL)
	{
		fprintf(stderr,"insert_tail: Could not allocate memory!!\n");
		exit(1);		
	}
	p->info = data;
	p->prev = l->tail;
	p->next = NULL;

	if (l->tail == NULL)
	{
		l->header = p;		
	}
	else
	{
		l->tail->next = p;		
	}

	l->tail = p;
	l->n_elements++;
}

void remove_front(list l)
{
	struct node *p;

	if (l == NULL) 
	{
		fprintf(stderr,"remove_front: List is not valid!!\n");
		exit(1);
	}

	if (l->n_elements == 0) 
	{
		fprintf(stderr,"remove_front: List is empty!!\n");
		exit(1);
	}

	p = l->header;
	l->header = p->next;
	if (l->header == NULL)
	{
		l->tail = NULL;
	}
	else 
	{
		l->header->prev = NULL;		
	}
	free(p);
	l->n_elements--;
}

void remove_tail(list l) 
{
	struct node *p;

	if (l == NULL) 
	{
		fprintf(stderr,"remove_tail: List is not valid!!\n");
		exit(1);
	}

	if (l->n_elements == 0) 
	{
		fprintf(stderr,"remove_tail: List is empty!!\n");
		exit(1);
	}

	p = l->tail;
	l->tail = p->prev;
	if (l->tail == NULL)
	{
		l->header = NULL;
	}
	else
	{
		l->tail->next = NULL;
	}
	free(p);
	l->n_elements--;

}

struct info_packet * front(list l)
{
	if (l == NULL) 
	{
		fprintf(stderr,"front: List is not valid!!\n");
		exit(1);
	}

	if (l->n_elements == 0) 
	{
		fprintf(stderr,"front: List is empty!!\n");
		exit(1);
	}

	return &(l->header->info);
}

struct info_packet * tail(list l)
{
	if (l == NULL) 
	{
		fprintf(stderr,"tail: List is not valid!!\n");
		exit(1);
	}

	if (l->n_elements == 0) 
	{
		fprintf(stderr,"tail: List is empty!!\n");
		exit(1);
	}

	return &(l->tail->info);

}

unsigned size(list l)
{
	if (l == NULL) 
	{
		fprintf(stderr,"size: List is not valid!!\n");
		exit(1);
	}

	return l->n_elements;
}
