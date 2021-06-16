#include <stdio.h>
#include <string.h>

#include <misc.h>

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
