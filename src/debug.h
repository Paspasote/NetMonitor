#ifndef __DEBUG_H
#define __DEBUG_H

#ifdef DEBUG

#include <ncurses.h>

// Constants

#define INTERNET_SNIFFER 0
#define INTRANET_SNIFFER 1
#define INTERNET_CONNECTIONS_TRACKER 2
#define INTERNET_CONNECTIONS_TRACKER_INFO 3
#define INTRANET_CONNECTIONS_TRACKER 4
#define INTRANET_CONNECTIONS_TRACKER_INFO 5
#define CONNECTIONS_PURGER 6
#define WHOIS 7
#define WHOIS_EXTRA 8
#define INTERFACE 9
#define INTERFACE_STATS 10
#define INTERFACE_STATS_EXTRA1 11
#define INTERFACE_STATS_EXTRA2 12
#define INTERFACE_STATS_EXTRA3 13

#define SNIFFER_THREAD_ROW 7
#define SNIFFER_INTERNET_THREAD_COL 0
#define SNIFFER_INTRANET_THREAD_COL 80
#define TRACKER_THREAD_ROW 8
#define INTERNET_TRACKER_THREAD_COL 0
#define INTRANET_TRACKER_THREAD_COL 80
#define PURGE_THREAD_ROW 10
#define PURGE_THREAD_COL 80
#define WHOIS_THREAD_ROW 6
#define WHOIS_THREAD_COL 0
#define WHOIS_THREAD_EXTRA_COL 80
#define INTERFACE_THREAD_ROW 10
#define INTERFACE_THREAD_COL 0
#define INTERFACE_THREAD_STATS_ROW 2
#define MODULE_MESSAGE_SIZE 75


// Debug level (0 - No debug   >0 debug on)
//#define DEBUG			1
// Please, define this symbol and its value in the compiler options
// Example: -DDEBUG=1

// Panel size

#define DEBUG_LINES		11
#define DEBUG_COLS		250

// Aspect ratio for debug panel
#define DEBUG_SIZE		0.25

void init_debug_panel();
void debugMessage(char *message, attr_t *attr, unsigned prioridad);
void debugMessageXY(int row, int col, char *message, attr_t *attr, unsigned prioridad);
void debugMessageModule(int module, char *message, attr_t *attr, unsigned prioridad);

#endif

#endif
