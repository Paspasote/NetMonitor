#ifndef __MISC_H
#define __MISC_H

#include <netinet/in.h>
#include <arpa/inet.h>

// Types
struct icmp_names {
    const char *name;
    uint8_t type;
    uint8_t code;
};

// Function prototypes
int min(int a, int b);
int max(int a, int b);
char *ltrim(char *str, const char *seps);
char *rtrim(char *str, const char *seps);
int checkIPAddress(char *s_ip, in_addr_t *address);
int checkPairIPMask(char *s_pair, in_addr_t *address, u_int8_t *mask_byte, in_addr_t *mask);
int checkRangeAddress(char *range, char *begin, char *end);
void addressMask2Range(in_addr_t address, u_int8_t mask_byte, char *s_initial_addr, char *s_final_addr);
void s_icmp_type(uint8_t type, uint8_t code, char *buffer);
int externalIP(in_addr_t address);
int banIP(char *address);
int unbanIP(char *address);
#endif

