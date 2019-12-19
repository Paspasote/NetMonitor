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
#include <sniffer.h>
#include <interface.h>

// Global vars
sem_t mutex_bp;
sem_t mutex_screen;

int main(int argc, char *argv[])
{
	pthread_t thread_sniffer, thread_interface;

	// Check number of parameters
	if (argc != 2) 
	{
		fprintf(stderr, "%s: Invalid arguments.\n", argv[0]);
		fprintf(stderr, "Help: %s <net device>\n", argv[0]);
		return 1;
	}

	// Save the net device
	char *net_dev = argv[1];

	// Initialize semaphores
	if (sem_init(&mutex_bp, 0, 1))
	{		
		fprintf(stderr, "%s: Couldn't create mutext_bp semaphore!!!!", argv[0]);
		return 1;
	}
   if (sem_init(&mutex_screen, 0, 1))
    {       
        fprintf(stderr, "%s: Couldn't create mutext_screen semaphore!!!!", argv[0]);
        return 1;
    }

 	// Read config files
	Configuration();

	// Create sniffer thread
	if (pthread_create(&thread_sniffer, NULL, sniffer, (void *)net_dev))
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

	// Wait until threads finish
	//pthread_join(thread_sniffer, NULL);
	pthread_join(thread_interface, NULL);

	// Destroy sempahores
	sem_destroy(&mutex_bp);

	// Exit program
	return 0;
}

