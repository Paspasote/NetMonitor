#ifndef __GLOBALVARS_H
#define __GLOBALVARS_H

#include <pcap.h>
#include <semaphore.h>

#include <SharedSortedList.h>
#include <DefaultView.h>
#include <PacketList.h>

struct const_global_vars
{
    char *internet_dev;      // network device (internet size) to sniffe
    char *intranet_dev;      // network device (intranet size) to sniffe
    bpf_u_int32 own_ip_internet;    // IP address of internet device
    bpf_u_int32 own_mask_internet;  // Mask address of internet device
    bpf_u_int32 own_ip_intranet;    // IP address of intranet device
    bpf_u_int32 own_mask_intranet;  // Mask address of intranet device

};

struct write_global_vars
{
    // Mutex semaphores for incoming/outcoming package lists
    sem_t mutex_packages_list, mutex_outbound_list;
    // Mutex semaphores for screen
    sem_t mutex_screen, mutex_debug_panel;
    // Mutes semaphore for WhoIs module
    sem_t mutex_bd_whois;
    sem_t mutex_cont_requests;
    sem_t mutex_cont_whois_threads;

    // Current view mode and lines for view the info
    int visual_mode;
    int result_count_lines;

    // Package lists for Default View
    shared_sorted_list DV_l;
    shared_sorted_list DV_l_outbound;

    // Package lists for IPG View
    shared_sorted_list IPG_l;
    shared_sorted_list IPG_l_outbound;

    // Package list for NAT View
    shared_sorted_list OV_l;

    // Package list for Debug mode
    list buffer_packets;

    // The initial time of the current view
    time_t view_started;

    // Number of requests have been done to WhoIs server this day
    unsigned cont_requests;
};


#endif
