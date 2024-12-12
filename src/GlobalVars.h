#ifndef __GLOBALVARS_H
#define __GLOBALVARS_H

#include <pcap.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <Configuration.h>
#include <SharedSortedList.h>
#include <SortedList.h>
#include <DefaultView.h>
#include <PacketList.h>

struct const_global_vars
{
    char *internet_dev;      // network device (internet side) to sniffe
    char *intranet_dev;      // network device (intranet side) to sniffe
    in_addr_t own_ip_internet;    // IP address of internet device
    in_addr_t own_mask_internet;  // Mask address of internet device
    in_addr_t network_intranet;    // Address of intranet network
    in_addr_t own_mask_intranet;  // Mask address of intranet network
    time_t monitor_started;     // The time monitor was started


#ifdef DEBUG
    unsigned cont_is_allow;
    unsigned cont__is_warning;
    unsigned cont_is_alert;
    unsigned cont_is_deny;
    unsigned cont_os_allow;
    unsigned cont_os_warning;
    unsigned cont_os_alert;
    unsigned cont_os_deny;
    unsigned cont_ih_deny;
    unsigned cont_oh_allow;
    unsigned cont_oh_warning;
    unsigned cont_oh_alert;
    unsigned cont_oh_deny;
    unsigned cont_services_alias;
#endif
};

struct write_global_vars
{
    // Mutex for incoming/outcoming package lists
    pthread_mutex_t mutex_internet_packets, mutex_intranet_packets;
    // Mutex for hash tables
    pthread_mutex_t mutex_conn_internet_in, mutex_conn_internet_out, mutex_conn_intranet_in, mutex_conn_intranet_out;
    // Mutex for list view
    pthread_mutex_t mutex_view_list;
    // Mutex for screen
    pthread_mutex_t mutex_screen, mutex_debug_panel;
    // Mutes for WhoIs module
    pthread_mutex_t mutex_bd_whois;
    pthread_mutex_t mutex_cont_requests;
    pthread_mutex_t mutex_cont_whois_threads;

    // Current view mode and lines for view the info
    int visual_mode;
    int result_count_lines;

    // Buffers for internet and intranet packets
    double_list internet_packets_buffer;
    double_list intranet_packets_buffer;

    // Hash tables for connections
    shared_sorted_list * conn_internet_in;
    shared_sorted_list * conn_internet_out;
    shared_sorted_list * conn_intranet_in;
    shared_sorted_list * conn_intranet_out;

#if NFTABLES_ACTIVE == 1
    // List and dictionary for store current NFtables rules
    sorted_list input_chains;
    dictionary chains;
    dictionary sets;
#endif

    // Default view List
    sorted_list DV_l;

    // IPG view List
    sorted_list IPG_l;

    // Package list for Outbound NAT View
    sorted_list ONATV_l;

    // The initial time of the current view
    time_t view_started;

    // Number of requests have been done to WhoIs server this day
    unsigned cont_requests;
#ifdef DEBUG
    unsigned long internet_packets_processed, intranet_packets_processed;
    unsigned long internet_packets_purged, intranet_packets_purged;
    unsigned long allocated_config;
    unsigned long allocated_whois;
    unsigned long allocated_packets_inbound;
    unsigned long allocated_packets_outbound;
    unsigned long allocated_others;
    pthread_mutex_t mutex_debug_stats;
#endif
};


#endif
