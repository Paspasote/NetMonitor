#ifndef __GLOBALVARS_H
#define __GLOBALVARS_H

#include <netinet/in.h>

struct const_global_vars
{
    char *internet_dev;      // network device (internet size) to sniffe
    char *intranet_dev;      // network device (intranet size) to sniffe
    bpf_u_int32 own_ip_internet;    // IP address of internet device
    bpf_u_int32 own_mask_internet;  // Mask address of internet device
    bpf_u_int32 own_ip_intranet;    // IP address of intranet device
    bpf_u_int32 own_mask_intranet;  // Mask address of intranet device

};

#endif
