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
#include <iptables.h>

#include <NetMonitor.h>

// EXTERNAL Global vars
extern struct const_global_vars c_globvars;
extern struct write_global_vars w_globvars;
extern sem_t mutex_internet_packets, mutex_intranet_packets;
extern double_list internet_packets_buffer;
extern double_list intranet_packets_buffer;

// Global vars

int main(int argc, char *argv[])
{
	pthread_t thread_sniffer_internet, thread_sniffer_intranet, thread_conn_tracker, thread_conn_purge, thread_interface;
	struct ifaddrs *ifaddr, *ifa;
	int i, internet, intranet;
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
			if (!strcmp(ifa->ifa_name, argv[2]))
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

	// Initialize semaphores
	if (sem_init(&w_globvars.mutex_internet_packets, 0, 1))
	{		
		fprintf(stderr, "%s: Couldn't create mutex_internet_packets semaphore!!!!", argv[0]);
		return 1;
	}
	if (sem_init(&w_globvars.mutex_intranet_packets, 0, 1))
	{		
		fprintf(stderr, "%s: Couldn't create mutex_intranet_packets semaphore!!!!", argv[0]);
		return 1;
	}
	if (sem_init(&w_globvars.mutex_conn_internet_in, 0, 1))
	{		
		fprintf(stderr, "%s: Couldn't create mutex_conn_internet_in semaphore!!!!", argv[0]);
		return 1;
	}
	if (sem_init(&w_globvars.mutex_conn_internet_out, 0, 1))
	{		
		fprintf(stderr, "%s: Couldn't create mutex_conn_internet_out semaphore!!!!", argv[0]);
		return 1;
	}
	if (sem_init(&w_globvars.mutex_conn_intranet_in, 0, 1))
	{		
		fprintf(stderr, "%s: Couldn't create mutex_conn_intranet_in semaphore!!!!", argv[0]);
		return 1;
	}
	if (sem_init(&w_globvars.mutex_conn_intranet_out, 0, 1))
	{		
		fprintf(stderr, "%s: Couldn't create mutex_conn_intranet_out semaphore!!!!", argv[0]);
		return 1;
	}
	if (sem_init(&w_globvars.mutex_view_list, 0, 1))
	{		
		fprintf(stderr, "%s: Couldn't create mutex_view_list semaphore!!!!", argv[0]);
		return 1;
	}
   	if (sem_init(&w_globvars.mutex_screen, 0, 1))
    {       
        fprintf(stderr, "%s: Couldn't create mutex_screen semaphore!!!!", argv[0]);
        return 1;
    }
   	if (sem_init(&w_globvars.mutex_debug_panel, 0, 1))
    {       
        fprintf(stderr, "%s: Couldn't create mutex_debug_panel semaphore!!!!", argv[0]);
        return 1;
    }
   	if (sem_init(&w_globvars.mutex_bd_whois, 0, 1))
    {       
        fprintf(stderr, "%s: Couldn't create mutex_bd_whois semaphore!!!!", argv[0]);
        return 1;
    }
   	if (sem_init(&w_globvars.mutex_cont_requests, 0, 1))
    {       
        fprintf(stderr, "%s: Couldn't create mutex_cont_requests semaphore!!!!", argv[0]);
        return 1;
    }
   	if (sem_init(&w_globvars.mutex_cont_whois_threads, 0, 1))
    {       
        fprintf(stderr, "%s: Couldn't create mutex_cont_whois_threads semaphore!!!!", argv[0]);
        return 1;
    }
#ifdef DEBUG
   	if (sem_init(&w_globvars.mutex_am, 0, 1))
    {       
        fprintf(stderr, "%s: Couldn't create mutex_am semaphore!!!!", argv[0]);
        return 1;
    }
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

	// Initialize iptables
	initIPtables();

	// Init curses
    if (w_globvars.visual_mode != -1) {
        init_curses();
    }

	// Get starting time
	w_globvars.view_started = time(NULL);

	// Create interrnet sniffer thread
	internet = 1;
	if (pthread_create(&thread_sniffer_internet, NULL, sniffer, &internet))
	{
		fprintf(stderr, "%s: Couldn't create internet sniffer thread!!!!", argv[0]);
		return 1;
	}

	// Create intranet sniffer thread
	if (argv[2] != NULL)
	{
		intranet = 0;
		if (pthread_create(&thread_sniffer_intranet, NULL, sniffer, &intranet))
		{
			fprintf(stderr, "%s: Couldn't create intranet sniffer thread!!!!", argv[0]);
			return 1;
		}
	}

	// Create connection tracker thread
	if (pthread_create(&thread_conn_tracker, NULL, connection_tracker, NULL))
	{
		fprintf(stderr, "%s: Couldn't create connection tracker thread!!!!", argv[0]);
		return 1;
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
	pthread_detach(thread_sniffer_intranet);
	pthread_detach(thread_conn_tracker);
	pthread_detach(thread_conn_purge);
	pthread_join(thread_interface, NULL);
	pthread_cancel(thread_sniffer_internet);
	pthread_cancel(thread_sniffer_intranet);
	pthread_cancel(thread_conn_tracker);
	pthread_cancel(thread_conn_purge);

	// Destroy sempahores
	sem_destroy(&w_globvars.mutex_internet_packets);
	sem_destroy(&w_globvars.mutex_intranet_packets);
	sem_destroy(&w_globvars.mutex_conn_internet_in);
	sem_destroy(&w_globvars.mutex_conn_internet_out);
	sem_destroy(&w_globvars.mutex_conn_intranet_in);
	sem_destroy(&w_globvars.mutex_conn_intranet_out);
	sem_destroy(&w_globvars.mutex_view_list);
	sem_destroy(&w_globvars.mutex_screen);
	sem_destroy(&w_globvars.mutex_debug_panel);
	sem_destroy(&w_globvars.mutex_bd_whois);
	sem_destroy(&w_globvars.mutex_cont_requests);
	sem_destroy(&w_globvars.mutex_cont_whois_threads);
#ifdef DEBUG
	sem_destroy(&w_globvars.mutex_am);
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

