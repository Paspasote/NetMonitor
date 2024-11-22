#ifndef __CONFIGURATION_H
#define __CONFIGURATION_H

#include <arpa/inet.h>
#include <Dictionary.h>

// Constants
#define CHAIN_IPTABLES_BLACKLIST "BlackList"

#define SCREEN_REFRESH_DELAY	3000
#define USER_INTERFACE_DELAY	500

//#define	TCP_TIMEOUT							900
//#define UDP_TIMEOUT							300
#define	TCP_TIMEOUT						90
#define UDP_TIMEOUT						90
#define ANY_TIMEOUT 						60
#define TCP_VISIBLE_TIMEOUT					120
#define UDP_VISIBLE_TIMEOUT					120
#define ANY_VISIBLE_TIMEOUT					60
#define RECENT_TIMEOUT						3
#define MIN_INTERVAL_BANDWIDTH 				5
//#define MAX_INTERVAL_BANDWIDTH 				10
#define MAX_INTERVAL_BANDWIDTH 				30
#define MIN_INTERVAL_BANDWIDTH_OUTGOING 	5
//#define MAX_INTERVAL_BANDWIDTH_OUTGOING 	10
#define MAX_INTERVAL_BANDWIDTH_OUTGOING 	30
#define THRESHOLD_ESTABLISHED_CONNECTIONS	30

#define FLAG_IPTABLES_POS	0
#define FLAG_NEW_POS		2
#define FLAG_RESPOND_POS	2
#define FLAG_STABLISHED_POS	2
#define FLAG_NAT_POS		4

#define FLAG_BAN			'B'
#define FLAG_ACCEPT			'A'
#define FLAG_DROP			'D'
#define FLAG_REJECT			'R'
#define FLAG_NEW			'N'
#define FLAG_RESPOND		'R'
#define FLAG_STABLISHED		'S'
#define FLAG_NAT			'I'

// Function prototypes
void Configuration();
int incoming_packetAllowed(unsigned protocol, unsigned port);
int outgoing_packetAllowed(struct in_addr address, unsigned protocol, unsigned port, int no_tcp_udp);
char *serviceAlias(unsigned protocol, unsigned port);
char *serviceShortAlias(unsigned protocol, unsigned port);

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
