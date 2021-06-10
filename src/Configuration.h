#ifndef __CONFIGURATION_H
#define __CONFIGURATION_H

#include <arpa/inet.h>
#include <Dictionary.h>

// Constants
#define	TCP_TIMEOUT		900
#define UDP_TIMEOUT		300
#define ANY_TIMEOUT 	60
#define TCP_VISIBLE_TIMEOUT		60
#define UDP_VISIBLE_TIMEOUT		60
#define ANY_VISIBLE_TIMEOUT		15
#define RECENT_TIMEOUT	3
#define MIN_INTERVAL_BANDWIDTH 5
#define MAX_INTERVAL_BANDWIDTH 10
#define MIN_INTERVAL_BANDWIDTH_OUTGOING 5
#define MAX_INTERVAL_BANDWIDTH_OUTGOING 10
#define THRESHOLD_ESTABLISHED_CONNECTIONS	30

// Function prototypes
void Configuration();
int incoming_packetAllowed(unsigned protocol, unsigned port);
int outgoing_packetAllowed(struct in_addr address, unsigned protocol, unsigned port, int no_tcp_udp);
char *serviceAlias(unsigned protocol, unsigned port);
char *serviceShortAlias(unsigned protocol, unsigned port);

/************************************** DEBUG *********************/
void printConfDict(dictionary d);
/******************************************************************/

// Types
struct ports_range {
	unsigned lower;
	unsigned upper;
};
struct address_mask {
	struct in_addr address;
	unsigned mask;
};

struct info_alias {
	unsigned lower;
	unsigned upper;
	char *alias;
	char *short_alias;
};

#endif
