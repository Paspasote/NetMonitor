#ifndef __NFTABLESPARSER_H
#define __NFTABLESPARSER_H

#include <Configuration.h>
#if NFTABLES_ACTIVE == 1

// Function prototypes
/*
Iterate and parse all nftables tables and chains
RETURN: 1 if all is ok
        0 if any error
*/
int iterate_tables_and_chains();

#endif

#endif

