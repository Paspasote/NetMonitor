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

#include <Configuration.h>
#include <WhoIs.h>
#include <NetMonitor.h>
#include <sniffer.h>
#include <interface.h>
#include <WhoIs.h>
#include <iptables.h>

// Global vars
sem_t mutex_packages_list, mutex_outbound_list;
sem_t mutex_screen, mutex_debug_panel;
sem_t mutex_bd_whois;
sem_t mutex_cont_requests;
sem_t mutex_cont_whois_threads;
time_t start;

int main(int argc, char *argv[])
{
	pthread_t thread_sniffer, thread_interface;
	struct param_thread paramt;
	char errbuf[PCAP_ERRBUF_SIZE];

	// Check number of parameters
	if (argc != 2 && argc != 3) 
	{
		fprintf(stderr, "%s: Invalid arguments.\n", argv[0]);
		fprintf(stderr, "Help: %s <internet device> [intranet device]\n", argv[0]);
		return 1;
	}

	// Save the net device
	paramt.internet_dev = argv[1];
	paramt.intranet_dev = argv[2];

	// Get network device address
	if (pcap_lookupnet(argv[1], &paramt.own_ip_internet, &paramt.own_mask_internet, errbuf) == -1) {
		fprintf(stderr, "Can't get own IP address from internet device %s", argv[1]);
		exit(EXIT_FAILURE);
	}

	// Get network intranet address
	if (argv[2] != NULL)
	{
	if (pcap_lookupnet(argv[2], &paramt.own_ip_intranet, &paramt.own_mask_intranet errbuf) == -1) {
		fprintf(stderr, "Can't get own IP address from intranet device %s", argv[2]);
		exit(EXIT_FAILURE);
	}

	// Initialize semaphores
	if (sem_init(&mutex_packages_list, 0, 1))
	{		
		fprintf(stderr, "%s: Couldn't create mutex_packages_list semaphore!!!!", argv[0]);
		return 1;
	}
	if (sem_init(&mutex_outbound_list, 0, 1))
	{		
		fprintf(stderr, "%s: Couldn't create mutex_outbound_list semaphore!!!!", argv[0]);
		return 1;
	}
   if (sem_init(&mutex_screen, 0, 1))
    {       
        fprintf(stderr, "%s: Couldn't create mutex_screen semaphore!!!!", argv[0]);
        return 1;
    }
   if (sem_init(&mutex_debug_panel, 0, 1))
    {       
        fprintf(stderr, "%s: Couldn't create mutex_debug_panel semaphore!!!!", argv[0]);
        return 1;
    }
   if (sem_init(&mutex_bd_whois, 0, 1))
    {       
        fprintf(stderr, "%s: Couldn't create mutex_bd_whois semaphore!!!!", argv[0]);
        return 1;
    }
   if (sem_init(&mutex_cont_requests, 0, 1))
    {       
        fprintf(stderr, "%s: Couldn't create mutex_cont_requests semaphore!!!!", argv[0]);
        return 1;
    }
   if (sem_init(&mutex_cont_whois_threads, 0, 1))
    {       
        fprintf(stderr, "%s: Couldn't create mutex_cont_whois_threads semaphore!!!!", argv[0]);
        return 1;
    }

	// Read Whois BD
	readDatabaseWhois();

 	// Read config files
	Configuration();

	// Initialize iptables
	initIPtables();

	// Get starting time
	start = time(NULL);

	// Create sniffer thread
	if (pthread_create(&thread_sniffer, NULL, sniffer, (void *)&paramt))
	{
		fprintf(stderr, "%s: Couldn't create sniffer thread!!!!", argv[0]);
		return 1;
	}

	// Create interface thread
	if (pthread_create(&thread_interface, NULL, interface, (void *)&paramt))
	{
		fprintf(stderr, "%s: Couldn't create interface thread!!!!", argv[0]);
		return 1;
	}

	// Wait until threads finish
	//pthread_join(thread_sniffer, NULL);
	pthread_join(thread_interface, NULL);

	// Destroy sempahores
	sem_destroy(&mutex_packages_list);

	// Save whois database
	writeDatabaseWhois();

	// Exit program
	return 0;
}

