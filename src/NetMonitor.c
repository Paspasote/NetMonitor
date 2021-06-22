#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pcap.h>
#include <time.h>
#include <pthread.h>
#include <semaphore.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/igmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <GlobalVars.h>
#include <Configuration.h>
#include <WhoIs.h>
#include <sniffer.h>
#include <interface.h>
#include <WhoIs.h>
#include <iptables.h>

#include <NetMonitor.h>

// EXTERNAL Global vars
extern struct const_global_vars c_globvars;
extern struct write_global_vars w_globvars;

// Global vars

int main(int argc, char *argv[])
{
	pthread_t thread_sniffer, thread_interface;
	char errbuf[PCAP_ERRBUF_SIZE];

	// Check number of parameters
	if (argc != 2 && argc != 3) 
	{
		fprintf(stderr, "%s: Invalid arguments.\n", argv[0]);
		fprintf(stderr, "Help: %s <internet device> [intranet device]\n", argv[0]);
		return 1;
	}

	// Save the net device
	c_globvars.internet_dev = argv[1];
	c_globvars.intranet_dev = argv[2];

	// Get network device address
	if (pcap_lookupnet(argv[1], &c_globvars.own_ip_internet, &c_globvars.own_mask_internet, errbuf) == -1) {
		fprintf(stderr, "Can't get own IP address from internet device %s", argv[1]);
		exit(EXIT_FAILURE);
	}

	// Get network intranet address
	if (argv[2] != NULL)
	{
		if (pcap_lookupnet(argv[2], &c_globvars.own_ip_intranet, &c_globvars.own_mask_intranet, errbuf) == -1) {
			fprintf(stderr, "Can't get own IP address from intranet device %s", argv[2]);
			exit(EXIT_FAILURE);
		}
	}

	// Initialize global vars
	w_globvars.DV_l = NULL;
	w_globvars.DV_l_outbound = NULL;
	w_globvars.IPG_l = NULL;
	w_globvars.IPG_l_outbound = NULL;
	w_globvars.OV_l = NULL;
	w_globvars.buffer_packets = NULL;
	w_globvars.cont_requests = 0;
	w_globvars.visual_mode = 0;

	// Initialize semaphores
	if (sem_init(&w_globvars.mutex_packages_list, 0, 1))
	{		
		fprintf(stderr, "%s: Couldn't create mutex_packages_list semaphore!!!!", argv[0]);
		return 1;
	}
	if (sem_init(&w_globvars.mutex_outbound_list, 0, 1))
	{		
		fprintf(stderr, "%s: Couldn't create mutex_outbound_list semaphore!!!!", argv[0]);
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

	// Get starting time
	w_globvars.view_started = time(NULL);

	// Create sniffer thread
	if (pthread_create(&thread_sniffer, NULL, sniffer, NULL))
	{
		fprintf(stderr, "%s: Couldn't create sniffer thread!!!!", argv[0]);
		return 1;
	}

	// Create interface thread
	if (pthread_create(&thread_interface, NULL, interface, NULL))
	{
		fprintf(stderr, "%s: Couldn't create interface thread!!!!", argv[0]);
		return 1;
	}

	// Wait until interface thread finish
	pthread_join(thread_interface, NULL);

	// Destroy sempahores
	sem_destroy(&w_globvars.mutex_packages_list);
	sem_destroy(&w_globvars.mutex_outbound_list);
	sem_destroy(&w_globvars.mutex_screen);
	sem_destroy(&w_globvars.mutex_debug_panel);
	sem_destroy(&w_globvars.mutex_bd_whois);
	sem_destroy(&w_globvars.mutex_cont_requests);
	sem_destroy(&w_globvars.mutex_cont_whois_threads);
#ifdef DEBUG
	sem_destroy(&w_globvars.mutex_am);
#endif

	// Save whois database
	writeDatabaseWhois();

	// Exit program
	return 0;
}

