#ifndef __NETMONITOR_H
#define __NETMONITOR_H

#include <time.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/igmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct param_thread
{
    char *internet_dev;      // network device (internet size) to sniffe
    char *intranet_dev;      // network device (intranet size) to sniffe
};

#endif
