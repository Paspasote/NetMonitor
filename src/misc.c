#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>

#include <Configuration.h>
#include <misc.h>
#include <GlobalVars.h>

// EXTERNAL global vars
extern struct const_global_vars c_globvars;


int min(int a, int b) {
    if (a <= b) {
        return a;
    }
    else {
        return b;
    }
}

int max(int a, int b) {
    if (a >= b) {
        return a;
    }
    else {
        return b;
    }
}

char *ltrim(char *str, const char *seps)
{
    size_t totrim;
    if (seps == NULL) {
        seps = "\t\n\v\f\r ";
    }
    totrim = strspn(str, seps);
    if (totrim > 0) {
        size_t len = strlen(str);
        if (totrim == len) {
            str[0] = '\0';
        }
        else {
            memmove(str, str + totrim, len + 1 - totrim);
        }
    }
    return str;
}

char *rtrim(char *str, const char *seps)
{
    int i;
    if (seps == NULL) {
        seps = "\t\n\v\f\r ";
    }
    i = strlen(str) - 1;
    while (i >= 0 && strchr(seps, str[i]) != NULL) {
        str[i] = '\0';
        i--;
    }
    return str;
}

int checkIPAddress(char *s_ip, in_addr_t *address)
{
	char *delim = ".";
    char s_ip_aux[INET_ADDRSTRLEN];
    char *s_byte;
	unsigned i, byte, cont_byte;

   	// Check address format
    if (strlen(s_ip) > INET_ADDRSTRLEN-1)
    {
        return 0;
    }

	strcpy(s_ip_aux, s_ip);
	cont_byte = 0;
	s_byte = strtok(s_ip_aux, delim);
	while (s_byte != NULL && cont_byte < 4) {
		cont_byte++;
		for (i=0; i<strlen(s_byte); i++) {
			if (!isdigit(s_byte[i])) {
                return 0;
			}
		}
		if (sscanf(s_byte, "%u", &byte) != 1 || byte > 255) {
            return 0;
		}
		s_byte = strtok(NULL, delim);
	}
	if (s_byte != NULL || cont_byte != 4) {
        return 0;
	}
	if (s_ip[strlen(s_ip)-1] == '.') {
        return 0;
	}

    if (address != NULL)
    {
       	inet_pton(AF_INET, s_ip, address);
    }
    return 1;
}

int checkPairIPMask(char *s_pair, in_addr_t *address, u_int8_t *mask_byte, in_addr_t *mask)
{
   	char *delim = "/";
	char *s_address, *s_mask;
	unsigned i, byte;
	in_addr_t address_aux, mask_aux;
	 

	// Extract Address
	s_address = strtok(s_pair, delim);

	// Mask?
	s_mask = strtok(NULL, delim);
	if (s_mask != NULL) {
		// More tokens ?
		if (strtok(NULL, delim) != NULL) {
            return 0;
		}
	}

    // Get IP address
    if (!checkIPAddress(s_address, address))
    {
        return 0;
    }

	// Check mask    
	if (s_mask != NULL) {
		for (i=0; i<strlen(s_mask); i++) {
			if (!isdigit(s_mask[i])) {
                return 0;
			}
		}
		if (sscanf(s_mask, "%u", &byte) != 1 || byte > 32) {
            return 0;
		}
		if (byte != 32) {
			// Check network address. Host part of the address must be zero
			inet_pton(AF_INET, s_address, &address_aux);
			mask_aux = 0xFFFFFFFF;
			mask_aux = mask_aux << byte;
			if (address_aux & mask_aux) 
            {
                return 0;
			}
		}
        if (mask_byte != NULL)
        {
            *mask_byte = byte;
        }
        if (mask != NULL)
        {
            *mask = 0xFFFFFFFF;
            *mask = *mask << byte;
        }
	}
    else
    {
        if (mask_byte != NULL)
        {
            *mask_byte = 32;
        }
        if (mask != NULL)
        {
            *mask = 0xFFFFFFFF;
        }
    }

    return 1;
}

int checkRangeAddress(char *range, char *begin, char *end)
{
    char *p;
    char delim[3] = " \t";

    // Get initial address
    p = strtok(range, delim);
    if (p == NULL)
    {
        return 0;
    }
    // Got it! Save initial address
    strncpy(begin, p, INET_ADDRSTRLEN-1);
    if (strlen(p) >= INET_ADDRSTRLEN)
    {
        begin[INET_ADDRSTRLEN] = '\0';
    }

    // Get - char
    p = strtok(NULL, delim);
    if (p == NULL || strcmp(p, "-"))
    {
        return 0;
    }

    // Got it! Get final address
    p = strtok(NULL, delim);
    if (p == NULL)
    {
        return 0;
    }
    // Got it! Save final address
    strncpy(end, p, INET_ADDRSTRLEN-1);
    if (strlen(p) >= INET_ADDRSTRLEN)
    {
        end[INET_ADDRSTRLEN] = '\0';
    }

    return 1;
}

void addressMask2Range(in_addr_t address, u_int8_t mask_byte, char *s_initial_addr, char *s_final_addr)
{
    in_addr_t final_address, mask_aux;

    // Convert initial address
    inet_ntop(AF_INET, &address, s_initial_addr, INET_ADDRSTRLEN);

    // Calculate end address
	mask_aux = 0xFFFFFFFF;
    mask_aux = mask_aux >> mask_byte;
    final_address = address | mask_aux;

    // Convert end address
    inet_ntop(AF_INET, &final_address, s_final_addr, INET_ADDRSTRLEN);
}

void s_icmp_type(uint8_t type, uint8_t code, char *buffer)
{
    static const struct icmp_names icmp_codes[] = {
	    { "Any", 0xFF, 0},
	    { "Echo reply", 0, 0},
	    { "Destination unreachable", 3, 0},
	    { "Network unreachable", 3, 0},
	    { "Host unreachable", 3, 1},
	    { "Protocol unreachable", 3, 2},
	    { "Port unreachable", 3, 3},
	    { "Fragmentation needed", 3, 4},
	    { "Source route failed", 3, 5},
	    { "Network unknown", 3, 6},
	    { "Host unknown", 3, 7},
	    { "Network prohibited", 3, 9},
	    { "Host prohibited", 3, 10},
	    { "TOS network unreachable", 3, 11},
	    { "TOS host unreachable", 3, 12},
	    { "Communication prohibited", 3, 13},
	    { "Host precedence violation", 3, 14},
	    { "Precedence cutoff", 3, 15},
	    { "Source quench", 4, 0},
	    { "Redirect", 5, 0},
	    { "Network redirect", 5, 0},
	    { "Host redirect", 5, 1},
	    { "TOS network redirect", 5, 2},
	    { "TOS host redirect", 5, 3},
	    { "Echo request", 8, 0},
	    { "Router advertisement", 9, 0},
	    { "Router solicitation", 10, 0},
	    { "Time exceeded", 11, 0},
	    { "TTL zero during transit", 11, 0},
	    { "TTL zero during reassembly", 11, 1},
	    { "Parameter problem", 12, 0},
	    { "IP header bad", 12, 0},
	    { "Required option missing", 12, 1},
	    { "Timestamp request", 13, 0},
        { "Timestamp reply", 14, 0},
        { "Address mask request", 17, 0},
        { "Address mask reply", 18, 0}
    };
    unsigned i;

    for (i=0; i<37; i++)
    {
        if (icmp_codes[i].type == type && icmp_codes[i].code == code)
        {
            strcpy(buffer, icmp_codes[i].name);
            return;
        }
    }
    strcpy(buffer, "");
}

int externalIP(in_addr_t address)
{
    if (address == c_globvars.own_ip_internet)
    {
        return 0;
    }

    if ((address & c_globvars.own_mask_intranet) == c_globvars.network_intranet)
    {
        return 0;
    }

    return 1;
}

int banIP(char *address)
{
    int pid;
    int status;
    int fd;

    // Create a child to execute iptables
    pid = fork();
    if (pid == -1) 
    {
		perror("banIP: ");
		exit(EXIT_FAILURE);
    }

    if (!pid)
    {
        fd = open("/dev/null", O_WRONLY);
        if (fd != -1)
        {
            close(1);
            close(2);
            dup(fd);
            dup(fd);
        }
        execlp("iptables", "iptables", "-I", IPTABLES_CHAIN_BLACKLIST, "-p", "all", "--src", address, "-j", "DROP", NULL);
        exit(EXIT_FAILURE);
    }

    // Wait until command child finished
    while (wait(&status) != pid);

    return (WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int unbanIP(char *address)
{
    int pid;
    int status;
    int fd;

    // Create a child to execute iptables
    pid = fork();
    if (pid == -1) 
    {
		perror("banIP: ");
		exit(EXIT_FAILURE);
    }

    if (!pid)
    {
        fd = open("/dev/null", O_WRONLY);
        if (fd != -1)
        {
            close(1);
            close(2);
            dup(fd);
            dup(fd);
        }
        execlp("iptables", "iptables", "-D", IPTABLES_CHAIN_BLACKLIST, "-p", "all", "--src", address, "-j", "DROP", NULL);
        exit(EXIT_FAILURE);
    }

    // Wait until command child finished
    while (wait(&status) != pid);

    return (WIFEXITED(status) && WEXITSTATUS(status) == 0);
}