#ifndef __WHOIS_H
#define __WHOIS_H

#include <SharedSortedList.h>

// Constants
#define MAX_LEN_COUNTRY 2
#define MAX_LEN_NETNAME 32
#define MAX_VISIBLE_NETNAME 16
#define MAX_WHOIS_THREADS 1
#define DELAY_BETWEEN_REQUESTS 3 // Allow MAX_WHOIS_THREADS whois requests every DELAY_BETWEEN_REQUESTS seconds
#define MAX_WHOIS_REQUESTS 1000

// Types
struct t_key
{
    uint32_t initial_address;
    uint32_t end_address;
};
struct t_value
{
    time_t  updated;
    char netname[MAX_LEN_NETNAME+1];
    char country[MAX_LEN_COUNTRY+1];
};
struct DV_info;

// Function prototypes
void *whoIs(void *ptr_paramt);
void readDatabaseWhois();
void writeDatabaseWhois();
struct t_value * findAdressWhois(uint32_t ip_address);
void updateWhoisInfo(uint32_t address, char *country, char *netname);
void showDatabase(int first_register, int max_registers);
int numberOfWhoisRegisters();

#endif