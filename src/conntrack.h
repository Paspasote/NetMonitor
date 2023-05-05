#ifndef __CONNTRACK_H
#define __CONNTRACK_H

#include <arpa/inet.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

#define CONNTRACK_SEEN_REPLY    1
#define CONNTRACK_STABLISHED    2
#define CONNTRACK_ASURED        4
#define CONNTRACK_CLIENT        8
#define CONNTRACK_NAT           16

// Function prototypes
int get(uint8_t ip_protocol, in_addr_t ip_src, uint16_t port_src, in_addr_t ip_dst, uint16_t port_dst, uint32_t *ip_NAT, uint16_t *port_NAT);
// Query conntrack kernel table for a specific connection
// NEEDS:
//       Protocol ID
//       Source IP address
//       Source port number
//       Destination IP address
//       Destination port number
//       Pointer to NAT IP destination
//       Pointer to NAT port number destination
// MODIFIES:
//       Pointer to NAT IP destination with the value for this connection
//       Pointer to NAT port number destination with the value for this connection
// RETURN:
//       if there is a connection in conntrack table then an integer with some bits activated (see constansts above)
//       -1 if there is not. 

#endif
