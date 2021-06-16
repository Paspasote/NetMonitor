#ifndef __MISC_H
#define __MISC_H

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
void s_icmp_type(uint8_t type, uint8_t code, char *buffer);

#endif

