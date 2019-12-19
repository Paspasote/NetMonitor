#ifndef __CONFIGURATION_H
#define __CONFIGURATION_H

#include <Dictionary.h>

// Function prototypes
void Configuration();
int packetAllowed(unsigned protocol, unsigned port);
char *serviceAlias(unsigned protocol, unsigned port);
char *serviceShortAlias(unsigned protocol, unsigned port);

/************************************** DEBUG *********************/
void printConfDict(dictionary d);
/******************************************************************/

// Types
struct ports_range {
	unsigned lower;
	unsigned upper;
};

struct info_alias {
	unsigned lower;
	unsigned upper;
	char *alias;
	char *short_alias;
};

#endif
