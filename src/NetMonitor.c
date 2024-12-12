#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pcap.h>
#include <time.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/types.h>
#include <ifaddrs.h>


#include <GlobalVars.h>
#include <Configuration.h>
#include <WhoIs.h>
#include <sniffer.h>
#include <Connection.h>
#include <PurgeConnection.h>
#include <interface.h>
#include <WhoIs.h>
#if NFTABLES_ACTIVE == 1
#include <nftables.h>
#endif
#if IPTABLES_ACTIVE == 1
#include <iptables.h>
#endif

#include <NetMonitor.h>

// EXTERNAL Global vars
extern struct const_global_vars c_globvars;
extern struct write_global_vars w_globvars;
extern pthread_mutex_t mutex_internet_packets, mutex_intranet_packets;
extern double_list internet_packets_buffer;
extern double_list intranet_packets_buffer;

// Global vars

int main(int argc, char *argv[])
{
	pthread_t thread_sniffer_internet, thread_sniffer_intranet, thread_conn_tracker_internet;
	pthread_t thread_conn_tracker_intranet, thread_conn_purge, thread_interface;
	struct ifaddrs *ifaddr, *ifa;
	int i;
	int is_internet[2];
	int internet_exist = 0, intranet_exist = 0;

	// Check number of parameters 
	if (argc != 2 && argc != 3) 
	{
		fprintf(stderr, "%s: Invalid arguments.\n", argv[0]);
		fprintf(stderr, "Help: %s <internet device> [intranet device]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	// Save the net device
	c_globvars.internet_dev = argv[1];
	c_globvars.intranet_dev = argv[2];

	// Get IP/netmask addresses of netowrk devices
	if (getifaddrs(&ifaddr) == -1) 
	{
		perror("getifaddrs");
		exit(EXIT_FAILURE);
	}
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) 
	{
		if (ifa->ifa_addr == NULL)
			continue;  

		if (ifa->ifa_addr->sa_family==AF_INET && ifa->ifa_name != NULL)
		{
			// Check if it is internet device
			if (!strcmp(ifa->ifa_name, argv[1]))
			{
				c_globvars.own_ip_internet = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
				c_globvars.own_mask_internet = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr;
				internet_exist = 1;
			}
			// Check if it is intranet device
			if (argv[2] != NULL && !strcmp(ifa->ifa_name, argv[2]))
			{
				c_globvars.network_intranet = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr & ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr;
				c_globvars.own_mask_intranet = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr;
				intranet_exist = 1;
			}
		}
	}
	freeifaddrs(ifaddr);
	if (!internet_exist)
	{
		fprintf(stderr, "%s: Can't get information from internet device %s.\n", argv[0], argv[1]);
		exit(EXIT_FAILURE);
	}
	if (argv[2] != NULL && !intranet_exist)
	{
		fprintf(stderr, "%s: Can't get information from intranet device %s.\n", argv[0], argv[2]);
		exit(EXIT_FAILURE);
	}

/*
	{
		// This debug code shows the network devices information
		char s_ip_internet[INET_ADDRSTRLEN], s_netmask_internet[INET_ADDRSTRLEN];
		char s_ip_intranet[INET_ADDRSTRLEN], s_netmask_intranet[INET_ADDRSTRLEN];
		
		inet_ntop(AF_INET, &c_globvars.own_ip_internet, s_ip_internet, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &c_globvars.own_mask_internet, s_netmask_internet, INET_ADDRSTRLEN);
		printf("Internet device %s: %s/%s\n", c_globvars.internet_dev, s_ip_internet, s_netmask_internet);
		if (argv[2] != NULL)
		{
			inet_ntop(AF_INET, &c_globvars.network_intranet, s_ip_intranet, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &c_globvars.own_mask_intranet, s_netmask_intranet, INET_ADDRSTRLEN);
			printf("Intranet device %s: %s/%s\n", c_globvars.intranet_dev, s_ip_intranet, s_netmask_intranet);
		}

		exit(EXIT_SUCCESS);
	}
*/

	// Get start time
	c_globvars.monitor_started = time(NULL);
	
	// Initialize global vars
   	w_globvars.internet_packets_buffer = NULL;
    w_globvars.intranet_packets_buffer = NULL;
	w_globvars.conn_internet_in = NULL;
    w_globvars.conn_internet_out = NULL;
    w_globvars.conn_intranet_in = NULL;
    w_globvars.conn_intranet_out = NULL;
#if NFTABLES_ACTIVE == 1
	w_globvars.input_chains = NULL;
	w_globvars.chains = NULL;
#endif
	w_globvars.DV_l = NULL;
	w_globvars.IPG_l = NULL;
	w_globvars.ONATV_l = NULL;
	w_globvars.internet_packets_buffer = NULL;
	w_globvars.cont_requests = 0;
	w_globvars.visual_mode = 0;

	// Alloc memory for internet device connections hash table (65536 buckets) 
	w_globvars.conn_internet_in = (shared_sorted_list *)calloc(65536, sizeof(shared_sorted_list));
	if (w_globvars.conn_internet_in == NULL)
	{
		fprintf(stderr, "Can't allocate memory for incoming internet connections hash table");
		exit(EXIT_FAILURE);
	}
	w_globvars.conn_internet_out = (shared_sorted_list *)calloc(65536, sizeof(shared_sorted_list));
	if (w_globvars.conn_internet_out == NULL)
	{
		fprintf(stderr, "Can't allocate memory for outgoing internet connections hash table");
		exit(EXIT_FAILURE);
	}
	for (i=0; i<65536; i++)
	{
		w_globvars.conn_internet_in[i] = NULL;
		w_globvars.conn_internet_out[i] = NULL;
	}

	// Alloc memory for intranet device connections (if there is one)
	if (argv[2] != NULL)
	{
		w_globvars.conn_intranet_in = (shared_sorted_list *)calloc(65536, sizeof(shared_sorted_list));
		if (w_globvars.conn_intranet_in == NULL)
		{
			fprintf(stderr, "Can't allocate memory for incoming intranet connections hash table");
			exit(EXIT_FAILURE);
		}
		w_globvars.conn_intranet_out = (shared_sorted_list *)calloc(65536, sizeof(shared_sorted_list));
		if (w_globvars.conn_intranet_out == NULL)
		{
			fprintf(stderr, "Can't allocate memory for outgoing intranet connections hash table");
			exit(EXIT_FAILURE);
		}
		for (i=0; i<65536; i++)
		{
			w_globvars.conn_intranet_in[i] = NULL;
			w_globvars.conn_intranet_out[i] = NULL;
		}
	}

	// Initialize mutex for internet device
	if (pthread_mutex_init(&w_globvars.mutex_internet_packets, NULL))
	{		
		fprintf(stderr, "%s: Couldn't create mutex_internet_packets mutex!!!!", argv[0]);
		return 1;
	}	
	if (pthread_mutex_init(&w_globvars.mutex_conn_internet_in, NULL))
	{		
		fprintf(stderr, "%s: Couldn't create mutex_conn_internet_in mutex!!!!", argv[0]);
		return 1;
	}
	if (pthread_mutex_init(&w_globvars.mutex_conn_internet_out, NULL))
	{		
		fprintf(stderr, "%s: Couldn't create mutex_conn_internet_out mutex!!!!", argv[0]);
		return 1;
	}

	// Initialize mutex for intranet device  (if there is one)
	if (argv[2] != NULL) {
		if (pthread_mutex_init(&w_globvars.mutex_intranet_packets, NULL))
		{		
			fprintf(stderr, "%s: Couldn't create mutex_intranet_packets mutex!!!!", argv[0]);
			return 1;
		}
		if (pthread_mutex_init(&w_globvars.mutex_conn_intranet_in, NULL))
		{		
			fprintf(stderr, "%s: Couldn't create mutex_conn_intranet_in mutex!!!!", argv[0]);
			return 1;
		}
		if (pthread_mutex_init(&w_globvars.mutex_conn_intranet_out, NULL))
		{		
			fprintf(stderr, "%s: Couldn't create mutex_conn_intranet_out mutex!!!!", argv[0]);
			return 1;
		}
	}


	// Initialize other mutexes
	if (pthread_mutex_init(&w_globvars.mutex_view_list, NULL))
	{		
		fprintf(stderr, "%s: Couldn't create mutex_view_list mutex!!!!", argv[0]);
		return 1;
	}
   	if (pthread_mutex_init(&w_globvars.mutex_screen, NULL))
    {       
        fprintf(stderr, "%s: Couldn't create mutex_screen mutex!!!!", argv[0]);
        return 1;
    }
   	if (pthread_mutex_init(&w_globvars.mutex_debug_panel, NULL))
    {       
        fprintf(stderr, "%s: Couldn't create mutex_debug_panel mutex!!!!", argv[0]);
        return 1;
    }
   	if (pthread_mutex_init(&w_globvars.mutex_bd_whois, NULL))
    {       
        fprintf(stderr, "%s: Couldn't create mutex_bd_whois mutex!!!!", argv[0]);
        return 1;
    }
   	if (pthread_mutex_init(&w_globvars.mutex_cont_requests, NULL))
    {       
        fprintf(stderr, "%s: Couldn't create mutex_cont_requests mutex!!!!", argv[0]);
        return 1;
    }
   	if (pthread_mutex_init(&w_globvars.mutex_cont_whois_threads, NULL))
    {       
        fprintf(stderr, "%s: Couldn't create mutex_cont_whois_threads mutex!!!!", argv[0]);
        return 1;
    }
#ifdef DEBUG
   	if (pthread_mutex_init(&w_globvars.mutex_debug_stats, NULL))
    {       
        fprintf(stderr, "%s: Couldn't create mutex_debug_stats mutex!!!!", argv[0]);
        return 1;
    }
	w_globvars.internet_packets_processed = 0;
	w_globvars.intranet_packets_processed = 0;
	w_globvars.internet_packets_purged = 0;
	w_globvars.intranet_packets_purged = 0;
	w_globvars.allocated_config = 0;
	w_globvars.allocated_packets_inbound = 0;
	w_globvars.allocated_packets_outbound = 0;
	w_globvars.allocated_whois = 0;
	w_globvars.allocated_others = 0;
#endif

	// Read Whois BD
	readDatabaseWhois();

 	// Read config files
	Configuration();

#if IPTABLES_ACTIVE == 1 || NFTABLES_ACTIVE == 1
	// Initialize xtables (iptables or nftables)
	initXtables();
#endif

	// Init curses
    if (w_globvars.visual_mode != -1) {
        init_curses();
    }

	// Get starting time
	w_globvars.view_started = time(NULL);

	// Create internet sniffer thread
	is_internet[0] = 1;
	if (pthread_create(&thread_sniffer_internet, NULL, sniffer, is_internet))
	{
		fprintf(stderr, "%s: Couldn't create internet sniffer thread!!!!", argv[0]);
		return 1;
	}

	// Create intranet sniffer thread
	if (argv[2] != NULL)
	{
		is_internet[1]= 0;
		if (pthread_create(&thread_sniffer_intranet, NULL, sniffer, is_internet+1))
		{
			fprintf(stderr, "%s: Couldn't create intranet sniffer thread!!!!", argv[0]);
			return 1;
		}
	}

	// Create internet connection tracker thread
	if (pthread_create(&thread_conn_tracker_internet, NULL, connection_tracker, is_internet))
	{
		fprintf(stderr, "%s: Couldn't create internet connection tracker thread!!!!", argv[0]);
		return 1;
	}

	// Create intranet sniffer thread
	if (argv[2] != NULL)
	{
		if (pthread_create(&thread_conn_tracker_intranet, NULL, connection_tracker, is_internet+1))
		{
			fprintf(stderr, "%s: Couldn't create intranet connection tracker thread!!!!", argv[0]);
			return 1;
		}
	}

	// Create purge connections thread
	if (pthread_create(&thread_conn_purge, NULL, purge_connections, NULL))
	{
		fprintf(stderr, "%s: Couldn't create purge connections thread!!!!", argv[0]);
		return 1;
	}

	// Create interface thread
	if (pthread_create(&thread_interface, NULL, interface, NULL))
	{
		fprintf(stderr, "%s: Couldn't create interface thread!!!!", argv[0]);
		return 1;
	}

	// Wait until interface thread finish
	pthread_detach(thread_sniffer_internet);
	pthread_detach(thread_conn_tracker_internet);
	if (argv[2] != NULL) {
		pthread_detach(thread_sniffer_intranet);
		pthread_detach(thread_conn_tracker_intranet);
	}
	pthread_detach(thread_conn_purge);
	pthread_join(thread_interface, NULL);
	pthread_cancel(thread_sniffer_internet);
	pthread_cancel(thread_conn_tracker_internet);
	if (argv[2] != NULL) {
		pthread_cancel(thread_sniffer_intranet);
		pthread_cancel(thread_conn_tracker_intranet);
	}
	pthread_cancel(thread_conn_purge);


	// Destroy mutexes
	pthread_mutex_destroy(&w_globvars.mutex_internet_packets);
	pthread_mutex_destroy(&w_globvars.mutex_conn_internet_in);
	pthread_mutex_destroy(&w_globvars.mutex_conn_internet_out);
	if (argv[2] != NULL) {
		pthread_mutex_destroy(&w_globvars.mutex_intranet_packets);
		pthread_mutex_destroy(&w_globvars.mutex_conn_intranet_in);
		pthread_mutex_destroy(&w_globvars.mutex_conn_intranet_out);
	}
	pthread_mutex_destroy(&w_globvars.mutex_view_list);
	pthread_mutex_destroy(&w_globvars.mutex_screen);
	pthread_mutex_destroy(&w_globvars.mutex_debug_panel);
	pthread_mutex_destroy(&w_globvars.mutex_bd_whois);
	pthread_mutex_destroy(&w_globvars.mutex_cont_requests);
	pthread_mutex_destroy(&w_globvars.mutex_cont_whois_threads);
#ifdef DEBUG
	pthread_mutex_destroy(&w_globvars.mutex_debug_stats);
#endif

	// Free allocated memory
	for (i=0; i<65536; i++)
	{
		if (w_globvars.conn_internet_in[i] != NULL)
		{
			clear_all_shared_sorted_list(w_globvars.conn_internet_in[i], 1, NULL, NULL);
			free(w_globvars.conn_internet_in[i]);
		}
		if (w_globvars.conn_internet_out[i] != NULL)
		{
			clear_all_shared_sorted_list(w_globvars.conn_internet_out[i], 1, NULL, NULL);
			free(w_globvars.conn_internet_out[i]);
		}
	}
	free(w_globvars.conn_internet_in);
	free(w_globvars.conn_internet_out);
	if (argv[2] != NULL)
	{
		for (i=0; i<65536; i++)
		{
			if (w_globvars.conn_intranet_in[i] != NULL)
			{
				clear_all_shared_sorted_list(w_globvars.conn_intranet_in[i], 1, NULL, NULL);
				free(w_globvars.conn_intranet_in[i]);
			}
			if (w_globvars.conn_intranet_out[i] != NULL)
			{
				clear_all_shared_sorted_list(w_globvars.conn_intranet_out[i], 1, NULL, NULL);
				free(w_globvars.conn_intranet_out[i]);
			}
		}
		free(w_globvars.conn_intranet_in);
		free(w_globvars.conn_intranet_out);
	}


	// Save whois database
	writeDatabaseWhois();

	// Exit program
	return 0;
}

